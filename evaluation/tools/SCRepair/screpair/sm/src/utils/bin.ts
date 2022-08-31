#!/usr/bin/env node

/**
 * @author: Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
 * 
 */


import { ASTNodeTypeString } from 'solidity-parser-antlr';
import { Arguments, Argv /*, Options*/ } from 'yargs';
import Yargs from 'yargs/yargs';
import { allMutationTypes } from '../lib/Mutations';
import { Seed, astNodeTypeStrings } from '../lib/utils';
import genMutations from './GenMutations';

export default function main(): void {

  const genMutations_common_args = {
    'for-node-types': {
      demandOption: false,
      type: 'array',
    },
    'replaceable-node-types': {
      demandOption: false,
      type: 'array',
    },
    mutation_types: {
      alias: 'types',
      demandOption: false,
      default: allMutationTypes,
      type: 'array',
    },
    'must-include-mutation-types': {
      demandOption: false,
      type: 'array'
    },
    'only-compilable': {
      demandOption: false,
      default: true,
      type: 'boolean',
    },
    'simplify': {
      demandOption: false,
      default: false,
      type: 'boolean',
    },
    'patched-src-dir': {
      normalize: true,
      demandOption: true,
      type: 'string',
    },
    'output-mutation': {
      demandOption: false,
      default: false,
      type: 'boolean',
      group: 'debug:',
    },
    seed: {
      demandOption: false,
      default: 'lucky-seed',
    },
    'mutation-space': {
      demandOption: false,
      default: undefined,
    },
  } as const;

  const genMutations_common_args_check = (argv: Arguments) => {
    const c1 = (argv['output-mutation'] === false || argv['patched-src-dir'] !== undefined);

    const for_node_types = argv['for-node-types'];
    const c2 = for_node_types === undefined || (Array.isArray(for_node_types) && for_node_types.every((x)=>astNodeTypeStrings.includes(x)));

    return c1 && c2;
  };

  Yargs(process.argv.slice(2))
    .command(
      'iter-gen-mutations <path_to_contract_source>',
      "Itereatively generate mutants. It expects continuous user input that input specifies a solidity contract, this outputs a mutant of the provided versison of smart contract mutated using one mutation operator.\n\
      This command doesn't generate two identifcal smart contracts.",
      ((parameter_yargs: Argv) => {
        parameter_yargs
          .options({ ...genMutations_common_args })
          .check(genMutations_common_args_check);
      }) as any,
      (x: Arguments) =>
        genMutations(
          x,
          'iter-json',
          x['max-mutation-sequences-length'] as number,
          x['patched-src-dir'] as string,
          (typeof x.seed === 'undefined' ? Math.random().toString() : x.seed) as Seed,
          true,
          x['mutation-space'] as string | undefined,
          (x['for-node-types'] === undefined ? undefined : x['for-node-types'] as ASTNodeTypeString[]),
          x.mutation_types as any,
          (x['replaceable-node-types'] === undefined ? undefined : x['replaceable-node-types']) as ASTNodeTypeString[] | undefined,
          x['simplify'] as boolean,
          x['output-mutation'] as boolean,
          true,
        ),
    )
    .help()
    .recommendCommands()
    .strict()
    .completion('completion')
    .parse();
}

main();
