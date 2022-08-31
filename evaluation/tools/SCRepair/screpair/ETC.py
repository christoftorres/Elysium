"""
@author: Xiao Liang Yu
"""
import os
from pathlib import Path
from typing import Dict, Sequence, Optional, Tuple, Union, cast, List, AsyncContextManager, Any

import attr
from docker import DockerClient
from .IN import ProblemDetector, ProblemDetectorResult, VulnerabilityInfo, NonDetectedVulnerability, DetectedVulnerability
from .IN import CodeRange
import json

import subprocess
from shutil import which

import signal
import copy
from encodings import utf_8
from logbook import Logger
import sys
import codecs
import time
import stat
import asyncio
import multiprocessing

from .Utils import strToBool

logger = Logger(os.path.basename(__file__))


class TestCaseExecutionResult(VulnerabilityInfo):
    def isTargeted(self,
                   targetedVul: Optional[Sequence[str]] = None,
                   targetedLocation: Optional[Sequence[CodeRange]] = None
                   ) -> bool:
        return self.detected

class PassedTestCase(NonDetectedVulnerability, TestCaseExecutionResult):
    pass


class FailedTestCase(DetectedVulnerability, TestCaseExecutionResult):
    pass


class ETC(ProblemDetector):

    name:str='ETC'
    paths_tc: Tuple[str, ...]
    baseArgs_execTC: Tuple[str, ...]
    cmd_solcJSON: str  # In a form of shell command
    addr: str
    filterTCByCoverage: bool
    optimize_contract: bool
    ctxManagerExecTC: AsyncContextManager  # AsyncContextManager before executing test case, added dedicated for mutex lock. Must be reentrant

    def __init__(self, args: Optional[Dict[str, str]] = None):

        args = {} if args is None else args

        super().__init__(args)

        dirTestCases = Path(args['PathTestCases'])

        self.paths_tc = tuple(
            str((dirTestCases / p).absolute())
            for p in os.listdir(dirTestCases))

        self.Cmd_solcJSON = args['Cmd_solcJSON']
        self.addr = args['ContractAddr']

        testethCMD = args['Cmd_testeth']
        path_sc_tx_tool = str(
            Path(args['path_sc_tx_tool']).expanduser().resolve())

        base_args = (path_sc_tx_tool, )

        # Note: the concurrent limit is per instance of test case executor
        concurrent_limit = int(
            args.get('concurrent_limit', multiprocessing.cpu_count()))

        self.baseArgs_execTC = base_args + (
            F'--CMD={testethCMD}',
            F'--con={concurrent_limit}')

        self.optimize_contract = strToBool(
            args.pop('optimize-contract', str(True)))

        one_at_a_time = strToBool(args.pop('one-at-a-time', str(True)))
        self.ctxManagerExecTC = asyncio.Lock()

    async def detect(self,
                     path_source: Sequence[Path],
                     targetContractName: Optional[str],
                     targetLocations: Optional[Sequence[CodeRange]] = None,
                     targetedVul: Optional[Sequence[str]] = None,
                     fastFail: bool = False,
                     **_extra_args) -> ProblemDetectorResult:
        """
        When fastFail is True, this results a single bool indicating whether all test cases are passing.
        When fastFail is False, this results a dict of {path_test_case: bool}
        """

        if targetContractName is None:
            raise ValueError('targetContractName must be provided')

        # We might want to check whether the abi of contract has been changed
        args_buildContract = F'{self.Cmd_solcJSON}'

        os.environ['R'] = open(path_source[0], 'r').read()
        os.environ['C'] = targetContractName

        buildContractRun = await asyncio.create_subprocess_shell(
            args_buildContract,
            #   input=inputJSON,
            #   shell=True,
            #   check=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            # universal_newlines=True,
            encoding=utf_8.getregentry().name)

        stdout = ((await buildContractRun.communicate())[0]).decode(utf_8.getregentry().name)
        assert buildContractRun.returncode == 0, F'unexpected exit status {buildContractRun.returncode}'

        bytecode = stdout

        if len(bytecode) == 0:
            logger.error(F'Compilation output: \n{buildContractRun.stdout}')
            raise ValueError('Compiled bytecode is empty!')

        args_execTC = self.baseArgs_execTC + (
            F'--bin={bytecode}',
            F'--addr={self.addr}') + tuple(F'--path={p}' for p in self.paths_tc)

        if targetLocations is not None:
            args_execTC += (F'--LOCSTR={json.dumps(targetLocations)}', )

        async with self.ctxManagerExecTC:
            logger.debug(F'Start executing {len(self.paths_tc)} test cases')
            tcRsts_ = await self.execTCs(args_execTC)

        tcRsts: List[VulnerabilityInfo]
        if fastFail and tcRsts_ and not tcRsts_[0]:
            tcRsts = [FailedTestCase(name='EthereumTestCase_StateTest')]
        else:

            tcRsts = []
            for testFile, rst in zip(self.paths_tc, tcRsts_):

                vulInfoObj: Optional[VulnerabilityInfo] = None
                if rst is True:
                    vulInfoObj = PassedTestCase(name=str(testFile))
                elif rst is False:
                    vulInfoObj = FailedTestCase(name=str(testFile))
                elif rst == 'NotRelevant':
                    vulInfoObj = None

                if vulInfoObj is not None:
                    tcRsts.append(vulInfoObj)

        logger.debug(F'{len(tcRsts)} test cases finally executed')
        return tcRsts

    @staticmethod
    async def execTC(args_execTC: Tuple[str, ...]) -> bool:

        logger.trace(F'Executing test case with args: {args_execTC!r}')

        execTCRun = await asyncio.create_subprocess_exec(
            *args_execTC,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
        )

        data_stdout, _ = await execTCRun.communicate()

        logger.trace('Finished executing TCRun')

        assert execTCRun.returncode == 0

        stdout = data_stdout.decode(utf_8.getregentry().name)
        try:
            tcRst = json.loads(stdout)[0]
        except:
            logger.error(F'Received output expected in json: \n{stdout}')
            raise

        return tcRst

    @staticmethod
    async def execTCs(args_execTC: Tuple[str, ...]) -> List[Union[bool, str]]:

        logger.trace(F'Executing test case with args: {args_execTC!r}')

        try:
            execTCRun = await asyncio.create_subprocess_exec(
                *args_execTC,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
            )
            data_stdout, _ = await execTCRun.communicate()
        finally:
            if 'execTCRun' in vars() and execTCRun.returncode is None:
                execTCRun.kill()

        logger.trace('Finished executing TCRun')

        assert execTCRun.returncode == 0

        stdout = data_stdout.decode(utf_8.getregentry().name)
        try:
            tcRst = json.loads(stdout)
        except:
            logger.error(F'Received output expected in json: \n{stdout}')
            raise

        return tcRst
