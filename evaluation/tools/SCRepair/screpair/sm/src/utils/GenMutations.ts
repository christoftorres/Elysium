/**
 * @author: Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
 * 
 */


import assert from 'assert';
import debug from '../utils/debug';
import fs from 'fs';
import mkdirp from 'mkdirp';
import path from 'path';
import parse from 'prettier-plugin-solidity/src/parser';
import readline from 'readline';
import { ASTNodeTypeString, CodeRange } from 'solidity-parser-antlr';
import { FileRootASTNode } from 'solidity-parser-antlr';
import treeify from 'treeify';
import { DeepReadonly, UnreachableCaseError } from 'ts-essentials';
import util from 'util';
import { Arguments } from 'yargs';
import { objToMutation } from '../lib/Mutations';
import MutationSequence from '../lib/MutationSequence';
import RandomMutationSequenceGenerator, { RandomMutationGenerator_Result, faultSpaceToFaultSpaceInfo } from '../lib/RandomMutationSequenceGenerator';
import { Seed, ASTNodeRemoveExtraAttributesDeep } from '../lib/utils';
import logger from './logger';
import { a2S } from './SRCUtils';
import interestedSpaceSpecifierParser from '../lib/InterestedSpaceSpecifierParser';
import FaultSpace from 'src/lib/FaultSpace';
import { generateFaultSpace } from '../lib/utils';
import g from './global';
import {isEqual as lodash_equal, without as lodash_without} from 'lodash';


const debugLogger_interaction = debug('inter');
const debugLogger_interaction_in = debugLogger_interaction.extend('in');
const debugLogger_interaction_out = debugLogger_interaction.extend('out');

const debugLogger_space = debug('space');
const debugLogger_faultSpace = debugLogger_space.extend('FaultSpace');

const debugLogger_ast = debug('ast');
const debugLogger_oriAST = debugLogger_ast.extend('oriAST');

export default function genMutations(
  x: Arguments,
  max_num_seq: 'iter-json',
  maxMutationDistance: number = Infinity,
  patched_src_dir: string | undefined,
  seed: Seed,
  skip_same_bin: boolean,
  interested_space_specifier: string | undefined,
  ASTNewNodeTypes: ASTNodeTypeString[] | undefined,
  must_include_mutation_types: ASTNodeTypeString[] | undefined,
  replaceableNodeType: ASTNodeTypeString[] | undefined,
  simplify: boolean,
  output_mutation: boolean,
  mutate_mutated_location: boolean
): void {
  logger.info(`Using seed "${seed}" as type ${typeof seed}`);

  if (patched_src_dir !== undefined) {
    mkdirp.sync(patched_src_dir);
    assert(fs.lstatSync(patched_src_dir).isDirectory(), `${patched_src_dir} is not a directory`);
  }

  const oriAST = parse(fs.readFileSync(x.path_to_contract_source as string, 'utf8'));

  debugLogger_oriAST(oriAST);

  const interestedSpace = interestedSpaceSpecifierParser(oriAST, interested_space_specifier);

  debugLogger_faultSpace(`InterestedSpace: ${util.inspect(interestedSpace, true, Infinity, true)}`);

  const faultSpace: readonly FaultSpace[] = generateFaultSpace(oriAST, interestedSpace);

  debugLogger_faultSpace(faultSpace);

  const mutationSeqGen = new RandomMutationSequenceGenerator(
    oriAST,
    1,
    maxMutationDistance,
    faultSpace,
    x.mutation_types as string[],
    ASTNewNodeTypes as ASTNodeTypeString[] | undefined,
    must_include_mutation_types,
    replaceableNodeType as ASTNodeTypeString[] | undefined,
    x['only-compilable'] as boolean,
    skip_same_bin,
    mutate_mutated_location,
    seed,
  );

  let numProcessed: number = 0;

  if (max_num_seq === 'iter-json') {
    // On Iter mode
    // Support mutate or crossover operations

    function respond(responseObj: DeepReadonly<IterJSONResponse>): void {
      debugLogger_interaction_out(`\n${treeify.asTree(responseObj as any, true, true)}`);
      console.log(JSON.stringify(responseObj));
    }

    const rl = readline.createInterface({
      input: process.stdin,
    });

    const debugLogger_interaction_in_parsed = debugLogger_interaction_in.extend('parsed');

    process.on('SIGUSR2', () => {
      logger.info('Rececived terminate signal');
      g.terminateNow = true;
    });

    rl.on('line', async line => {
      if (line === 'q') {
        logger.info('Received exit command, exiting.');
        rl.close();
        return;
      }

      g.terminateNow = false;
      await util.promisify(fs.exists)(`/tmp/terminate_${process.pid}`) && await util.promisify(fs.unlink)(`/tmp/terminate_${process.pid}`);

      const requestObj_ = JSON.parse(line);
      debugLogger_interaction_in_parsed(`\n${treeify.asTree(requestObj_, true, true)}`);
      assert(typeof requestObj_.type === 'string', `Unexpected request type: ${requestObj_.type}\n`);

      const requestObj = requestObj_ as IterJSONRequest;

      const newMutationSequences: MutationSequence[] = [];

      switch (requestObj.type) {
        case 'random': {
          const rstMutationSequences = await genMutations_genSeqs(
            requestObj.num_mutations,
            mutationSeqGen,
            undefined,
            undefined,
          );
          if (rstMutationSequences === undefined) {
            const response: IterJSONResponse_Failure = {
              Result: 'AllSpaceExhasuted',
            };

            respond(response);
            return;
          }

          newMutationSequences.push(...rstMutationSequences);

          break;
        }
        case 'mutate': {

          const baseMutationSeqObj: DeepReadonly<any[]> = requestObj.baseMutationSequence;

          assert(
            Array.isArray(baseMutationSeqObj),
            `mutation_sequence should be an array while provided: \n${util.inspect(
              baseMutationSeqObj,
              true,
              Infinity,
              true,
            )}`,
          );

          const overridenFaultSpaceSpecifier = requestObj.overridenFaultSpaceSpecifier !== null ? requestObj.overridenFaultSpaceSpecifier : undefined;

          const baseMutationSeq = new MutationSequence(...baseMutationSeqObj.map(objToMutation));
          const baseAST = baseMutationSeq.mutateAST(oriAST);

          ASTNodeRemoveExtraAttributesDeep(baseAST);

          if (mutationSeqGen.findASTByMutationSequence(baseMutationSeq) === undefined) {
            
            const possibleMutationTypes = x.mutation_types as string[];
            let original_faultSpace_Path = faultSpace.map((x) => faultSpaceToFaultSpaceInfo(x, possibleMutationTypes));

            baseMutationSeq.mutateAST(oriAST, (beforeAST, _, newMutation)=>{

              if(newMutation !== undefined) {
                original_faultSpace_Path = original_faultSpace_Path
                .map(x => {
                  const newNodePath = newMutation.updateASTPath.bind(newMutation, beforeAST)(x.faultSpace.nodePath);
                  if (newNodePath === null) {
                    return null;
                  } else if (lodash_equal(x!.faultSpace.nodePath, newMutation.targetNodePath)) {
                    const mutationType = newMutation.mutationType;
                    const newRemainingMutation = lodash_without(x!.remainingMutation, mutationType);
                    if (newRemainingMutation.length !== 0) {
                      return { faultSpace: { nodePath: newNodePath }, remainingMutation: newRemainingMutation };
                    } else {
                      return null;
                    }
                  } else {
                    return { faultSpace: { nodePath: newNodePath }, remainingMutation: x.remainingMutation };
                  }
                })
                .filter(x => x !== null) as any;
              }

                return true;
            });

            (mutationSeqGen as RandomMutationSequenceGenerator).addKnownAST(baseAST, baseMutationSeq, original_faultSpace_Path);
          }

          const rstMutationSequences = await genMutations_genSeqs(1, mutationSeqGen, baseAST, overridenFaultSpaceSpecifier);
          if (rstMutationSequences === undefined) {
            const response: IterJSONResponse_Failure = {
              Result: 'AllSpaceExhasuted',
            };

            respond(response);
            return;
          } else if (rstMutationSequences.length === 0) {
            const response: IterJSONResponse_Failure = {
              Result: 'SpaceExhasutedForAST',
            };

            respond(response);
            return;
          } else {
            newMutationSequences.push(...rstMutationSequences);
          }

          break;
        }
        default: {
          throw new Error(`Unknown iter-json request object type: ${(requestObj as any).type}`);
        }
      }

      const outPaths: string[] = new Array(newMutationSequences.length);

      assert(typeof patched_src_dir !== 'undefined');
      const len_newMutationSequences = newMutationSequences.length;
      for (let i = 0; i < len_newMutationSequences; i++) {
        const num: number = numProcessed + i;

        const outPath = path.format({
          dir: patched_src_dir,
          name: num.toString(),
          ext: '.sol',
        });

        const newAST = newMutationSequences[i].mutateAST(oriAST);
        const finalNewAST = simplify ? mutationSeqGen.simplifyAST(newAST) : newAST;
        const newSRC = a2S(finalNewAST);
        const newMutationSeq = newMutationSequences[i];
        fs.writeFileSync(outPath, newSRC);
        outPaths[i] = outPath;
        logger.info(`Patched source file #${num} written to ${outPath}`);
        if (output_mutation) {
          const outPath_mutation = path.format({
            dir: patched_src_dir,
            name: `${num}.sol.mutation`,
            ext: '.json',
          });

          fs.writeFileSync(outPath_mutation, JSON.stringify(newMutationSeq));
          logger.info(`Mutation sequence file #${num} for ${outPath} written to ${outPath_mutation}`);
        }
      }

      numProcessed += newMutationSequences.length;

      switch (requestObj.type) {
        case 'mutate': {
          assert(newMutationSequences.length === 1);

          const response: DeepReadonly<IterJSONResponse_Success_NewMutant> = {
            Result: 'Success',
            NewMutationSequences: newMutationSequences, // Surely contain only one element
            PatchedFilePaths: outPaths, // Surely contain only one element
            ModifiedLocations: newMutationSequences.map((x) => x.modifiedLocations(oriAST)),
          };

          respond(response);

          return;
        }

        case 'random': {
          const response: DeepReadonly<IterJSONResponse_Success_NewMutant> = {
            Result: 'Success',
            NewMutationSequences: newMutationSequences,
            PatchedFilePaths: outPaths,
            ModifiedLocations: newMutationSequences.map((x) => x.modifiedLocations(oriAST)),
          };

          respond(response);

          return;
        }

        default: {
          // If it's truly invalid request type, it should have failed already
          throw new UnreachableCaseError(requestObj);
        }
      }
    });
  } else {
    // Some implementation inconsistency
    throw new UnreachableCaseError(max_num_seq);
  }
}

async function genMutations_genSeqs(
  num: number,
  mutationSeqGen: RandomMutationSequenceGenerator,
  ast: FileRootASTNode | undefined,
  overridenFaultSpaceSpecifier: string | undefined = undefined
) {

  let overridenFaultSpace: DeepReadonly<FaultSpace[]> | undefined = undefined;
  if (overridenFaultSpaceSpecifier !== undefined) {
    const interestedSpace = interestedSpaceSpecifierParser(ast!, overridenFaultSpaceSpecifier);
    overridenFaultSpace = generateFaultSpace(ast!, interestedSpace);
  }

  const rstMutations = [];

  for (let i = 0; i < num; i++) {

    overridenFaultSpace;
    const mutationSeq = (await mutationSeqGen.next({ requestAST: ast })).value;

    if (typeof mutationSeq === 'undefined') {
      logger.info('Patch search space exhausted.');
      return undefined;
    } else if (mutationSeq === RandomMutationGenerator_Result.ExhaustedForRequestedAST) {
      logger.debug("Requested AST can't be modified further.");
      break;
    } else if (mutationSeq === RandomMutationGenerator_Result.TerminateRequested) {
      logger.debug('Terminated requested');
      break;
    } else {
      logger.debug(`Generated ${i + 1} patches for current task`);
    }

    rstMutations.push(mutationSeq);
  }

  return rstMutations;
}

interface IterJSONRequest_Base { }

interface IterJSONRequest_Random extends IterJSONRequest_Base {
  readonly type: 'random';
  readonly num_mutations: number;
}

interface IterJSONRequest_Mutate extends IterJSONRequest_Base {
  readonly type: 'mutate';
  readonly baseMutationSequence: MutationSequence;
  readonly overridenFaultSpaceSpecifier: string;
}

interface IterJSONRequest_Crossover_OnePoint extends IterJSONRequest_Base {
  readonly type: 'crossover-onepoint';
  readonly MutationSequence1: MutationSequence;
  readonly CrossPoint1: number;
  readonly MutationSequence2: MutationSequence;
  readonly CrossPoint2: number;
}


type IterJSONRequest = IterJSONRequest_Random | IterJSONRequest_Mutate | IterJSONRequest_Crossover_OnePoint;

interface IterJSONResponse_Base {
  readonly Result: string;
}

interface IterJSONResponse_Success extends IterJSONResponse_Base {
  readonly Result: 'Success';
}

// Note: Try having an uniform response format for success
interface IterJSONResponse_Success_NewMutant extends IterJSONResponse_Success {
  readonly NewMutationSequences: MutationSequence[];
  readonly PatchedFilePaths: string[];
  readonly ModifiedLocations: (CodeRange[] | 'unknown' | null)[];
}

// interface IterJSONResponse_Random_Success extends IterJSONResponse_Base {
//   Result: 'Success';
//   NewMutationSequences: DeepReadonly<MutationSequence[]>;
//   PatchedFilePaths: readonly string[];
// }

// interface IterJSONResponse_Mutate_Success extends IterJSONResponse_Base {
//   Result: 'Success';
//   NewMutationSequence: DeepReadonly<MutationSequence>;
//   PatchedFilePath: string;
// }

// // Note: For crossover, success can be no new code generated (i.e. `GeneratedNewCode == 0`).
// interface IterJSONResponse_Crossover_Success extends IterJSONResponse_Base {
//   Result: 'Success';
//   GeneratedNewCode: number;
//   NewMutationSequences: DeepReadonly<MutationSequence[]>;
//   PatchedFilePaths: readonly string[];
// }

interface IterJSONResponse_Failure extends IterJSONResponse_Base {
  readonly Result: 'SpaceExhasutedForAST' | 'AllSpaceExhasuted';
}

type IterJSONResponse = IterJSONResponse_Failure | IterJSONResponse_Success_NewMutant; // IterJSONResponse_Random_Success | IterJSONResponse_Mutate_Success | IterJSONResponse_Crossover_Success;
