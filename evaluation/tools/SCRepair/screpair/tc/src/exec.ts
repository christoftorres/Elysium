/**
 * @author: Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
 */

import assert from 'assert';
import fs from 'fs';
import execTestCases_StateTest_lib from './exec2';
import { flatten as lodash_flatten } from 'lodash';
import { promisify } from 'util';
import pMap from 'p-map';

const logger = new Proxy({}, {
  get() {
    return (...args: any[]) => console.error(...args);
  }
}) as any;

class FailingTestError extends Error {
  public constructor(msg?: string) {
    super(msg);
  }
}

/**
 * 
 * @param arg 
 * @param fastFail when true, all test case executions will be terminated as soon as a test case is failing and return a single failing result
 * @param concurrency_limit 
 */
export default async function ExecTestCases_StateTest(arg: any, addr: string, bin: string | undefined, fastFail: boolean = false, concurrency_limit: number = Infinity, onlyLocaltions_: string | undefined = undefined, testethCMD: string) {

  const onlyLocaltions = (typeof onlyLocaltions_ === 'string') ? JSON.parse(onlyLocaltions_) : onlyLocaltions_;

  const path_to_test_case_files: string[] = arg.path_to_test_case_file;
  assert(path_to_test_case_files.every(x => fs.existsSync(x)));

  let rsts_: readonly (readonly boolean[] | TestCaseResult.NotRelevant)[];
  try {
    rsts_ = await pMap(path_to_test_case_files, (path_testCase: any) => process_one_test_case_file(path_testCase, testethCMD, addr, bin, onlyLocaltions, fastFail), {
      concurrency: concurrency_limit,
    });
  } catch (err) {
    if (err instanceof FailingTestError) {
      rsts_ = [[false]];
    } else {
      throw err;
    }
  }

  const rsts: readonly boolean[] = lodash_flatten(rsts_ as any);

  console.log(JSON.stringify(rsts));
}

enum TestCaseResult {
  NotRelevant = 'NotRelevant'
};

/**
 * 
 * @param path_testCase 
 * @param testethCMD 
 * @param addr 
 * @param bin 
 * @param throwOnFailing 
 */
async function process_one_test_case_file(path_testCase: string, testethCMD: string, addr: string, bin: string | undefined, onlyLocaltions: any[] | undefined = undefined, throwOnFailing: boolean = false): Promise<boolean[] | TestCaseResult.NotRelevant> {

  const outStateTest: any = JSON.parse(
    await promisify(fs.readFile)(path_testCase, {
      encoding: 'utf-8',
    }),
  );

  if (onlyLocaltions !== undefined) {

    let coveredLocations: any[] | undefined = undefined;
    switch (outStateTest.Version as string) {
      case '2': {
        coveredLocations = (outStateTest as unknown as any).CoveredStatementLocation;
        break;
      }
      case '3': {
        coveredLocations = outStateTest.CoverageInformation !== null ? outStateTest.CoverageInformation.CoveredStatementLocation : undefined;
        break;
      }
    }

    if (coveredLocations !== undefined) {
      if (coveredLocations.every((x) => !onlyLocaltions.some((y) => locationIntersect(x, y)))) {
        return TestCaseResult.NotRelevant;
      }
    } else {
      logger.warn(`location coverage based filtering requested but disabled because coverage information wasn't generated`);
    }
  }

  const rst = await execTestCases_StateTest_lib(
    outStateTest,
    testethCMD,
    bin !== undefined ? { [addr.toLowerCase()]: bin } : undefined,
  );

  if (throwOnFailing && !rst) {
    throw new FailingTestError();
  } else {
    return rst;
  }

}

export function locationIntersect(a: any, b: any): boolean {

  // Start of a is inside b
  return (LineColumnComparator(a.start, b.start) >= 0 && LineColumnComparator(a.start, b.end) <= 0) ||
      // Start of b is inside a
      (LineColumnComparator(b.start, a.start) >= 0 && LineColumnComparator(b.start, a.end) <= 0)
}

// For ascending sorting
export function LineColumnComparator(firstEl: any, secondEl: any) {
  return firstEl.line !== secondEl.line ? firstEl.line - secondEl.line : firstEl.column - secondEl.column;
}
