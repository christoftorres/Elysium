/**
 * @author: Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
 */

import assert from 'assert';
import child_process from 'child_process';
import fs from 'fs';
import { cloneDeep as lodash_cloneDeep, flatMapDeep as lodash_flatMapDeep } from 'lodash';
import { sync as mkdirpSync } from 'mkdirp';
import os from 'os';
import path from 'path';
import util, { promisify } from 'util';
import execa from 'execa';

const logger = new Proxy({}, {
  get() {
    return (...args: any[]) => console.error(...args);
  }
}) as any;

export default async function ExecTestCases_StateTest(
  testFillers: any,
  testethCMD: string,
  contractBins: Record<string, string> | undefined = undefined,
): Promise<boolean[]> {

  const rstArr: boolean[] = [];
  for (const testName in testFillers.Tests) {
    const rst = (await ExecTestCases_StateTest_Single(
      testFillers.Tests[testName].TestFiller,
      testName,
      testethCMD,
      contractBins,
      false,
      undefined
    )).Result;
    rstArr.push(rst);
  }

  return rstArr;
}

export type ExecTestCases_StateTest_Single_Result = {
  Result: boolean,
  PCs?: number[]
}

export async function ExecTestCases_StateTest_Single(
  _testFiller: any,
  testName: string = 'test',
  testethCMD: string,
  contractBins: Record<string, string> | undefined = undefined,
  retPC: boolean = false,
  testExecTimeout: number | undefined = undefined,
): Promise<ExecTestCases_StateTest_Single_Result> {
  let testFiller;

  if (contractBins !== undefined) {
    testFiller = lodash_cloneDeep(_testFiller);
    for (const addr_ in contractBins) {
      const addr = addr_.toLowerCase();
      assert(typeof testFiller.pre[addr] !== 'undefined', `addr: ${addr}${os.EOL}testFiller.pre keys: ${util.inspect(Object.keys(testFiller.pre), false, Infinity, true)}`);
      assert(typeof testFiller.pre[addr].code !== 'undefined');
      const transformedBin = !contractBins[addr_].startsWith('0x') ? `0x${contractBins[addr_]}` : contractBins[addr_];
      testFiller.pre[addr].code = transformedBin;
      if (typeof testFiller.expect[0].result[addr].code !== 'undefined') {
        testFiller.expect[0].result[addr].code = transformedBin;
      }
    }
  } else {
    testFiller = _testFiller;
  }

  const rstTestFilterObj: any = {
    [testName]: testFiller,
  };

  const tmpEthTestDir = await promisify(fs.mkdtemp)(`${os.tmpdir()}${path.sep}`);
  await promisify(fs.chmod)(
    tmpEthTestDir,
    fs.constants.S_IRWXU |
    fs.constants.S_IRWXG |
    fs.constants.S_IROTH |
    fs.constants.S_IXOTH,
  );

  const execEnv = lodash_cloneDeep(process.env);
  execEnv[`ETHEREUM_TEST_PATH`] = tmpEthTestDir;
  const testFilterDir = path.join(
    tmpEthTestDir,
    'src',
    'GeneralStateTestsFiller',
    'stExample',
  );
  mkdirpSync(testFilterDir);
  const testcaseDir = path.join(
    tmpEthTestDir,
    'GeneralStateTests',
    'stExample',
  );
  mkdirpSync(testcaseDir, {
    mode: fs.constants.S_IRWXU | fs.constants.S_IRWXG | fs.constants.S_IRWXO,
  }); // The mode opt isn't effective for new nodejs version
  await promisify(fs.chmod)(
    testcaseDir,
    fs.constants.S_IRWXU | fs.constants.S_IRWXG | fs.constants.S_IRWXO,
  );

  await promisify(fs.writeFile)(
    path.join(testFilterDir as string, `${testName}Filler.json`),
    JSON.stringify(rstTestFilterObj),
  );

  let arg_retPC = '';
  if (retPC) {
    const obj = {
      disableStorage: true,
      disableMemory: true,
      disableStack: true,
      fullStorage: false,
    }
    arg_retPC = `--jsontrace '${JSON.stringify(obj)}'`;
  }

  const execTestethCMD = `${testethCMD} -t GeneralStateTests/stExample -- --filltests --dismissGasCost ${arg_retPC}`;
  let PCs: undefined | number[] = undefined;

  logger.debug(`eth test filter dir: ${testFilterDir}`);
  logger.debug(`Executing testeth with CMD: ${execTestethCMD}`);

  let outputs: string;
  try {
    outputs = (await execa.command(execTestethCMD, {
      env: execEnv,
      encoding: 'utf8',
      maxBuffer: Infinity,
      cleanup: true,
      stdin: undefined,
      stripFinalNewline: true,
      timeout: testExecTimeout === undefined ? 0 : testExecTimeout
    })).stdout;

  } catch (err_) {
    // Note: when the test case is failed, it will have non-zero status. So, it might not be an error when it's not having 0 exit code.

    const err: child_process.SpawnSyncReturns<string> = err_;

    const exit_code = (err as any).exitCode;

    if(exit_code === undefined) {
      // Not a normal execa exception, throwing it again
      throw err_;
    }

    logger.debug(err.stderr);
    logger.debug(`testeth exit status is ${exit_code}.`);

    // exit code 200 and 201 are normal test case failing exit code
    if (![200, 201].includes(exit_code)) {
      throw new Error(`testeth has unexpected exit status ${exit_code} (${(err as any).exitCodeName})`);
    }

    return {
      Result: false
    };
  }
  logger.debug('testeth execution succeeded');

  if (retPC) {
    PCs = [];

    // Note: First line should be ignored
    const traces = lodash_flatMapDeep(outputs.split(os.EOL).slice(1), ((line) => {

      let obj = undefined;

      try {

        try {
          obj = JSON.parse(line);
        } catch (err) {
          // Sometimes one line contains multiple objects..
          return line.split('}').map((x) => x.length > 0 ? JSON.parse(`${x}}`) : []);
        }
      } catch (err) {
        console.error(err);
        logger.error(`Erronous input: ${line}`);
        throw err;
      }

      return obj;
    }));


    // Note: Currently only support detecting pcs in the first called function
    // Support for depth > 0 can be added by checking stack when op is call-related
    for (const instTrace of traces) {
      if (instTrace.depth === '0') {
        const pc = parseInt(instTrace.pc);
        assert(Number.isInteger(pc));
        PCs.push(pc);
      }
    }
  }

  return {
    Result: true,
    PCs: PCs
  };
}
