"""
@author: Xiao Liang Yu
"""
from .IN import ProblemDetector, ProblemDetectorResult, DetectedVulnerability
from .IN import CodeRange, Location
from encodings import utf_8
from typing import Iterable, Union, Dict, Optional, Any, ClassVar, Sequence, DefaultDict, cast, List
from pathlib import Path
import docker
from logbook import Logger
import os
import json
import concurrent
import asyncio
from collections import defaultdict
from .Utils import FaultElement_NodeType, FaultElement_CodeRange
from itertools import chain

logger = Logger(os.path.basename(__file__))

class Slither(ProblemDetector):

    name: str ='slither'
    docker_image: str
    dockerCl: Any
    threadPool: ClassVar[
        concurrent.futures.
        ThreadPoolExecutor] = concurrent.futures.ThreadPoolExecutor()

    titleVulDict: ClassVar[Dict[str, str]] = {
        # 'Integer Underflow': 'integer_underflow', # TODO
        # 'Integer Overflow': 'integer_overflow', # TODO
        'reentrancy-eth': 'reentrancy',
        'reentrancy-no-eth': 'reentrancy',
        'unused-return': 'unchecked_call',
        'unchecked-lowlevel': 'unchecked_call',
        'unchecked-send': 'unchecked_call',
    }

    def __init__(self, args):
        super().__init__(args)
        self.docker_image = args['slither-docker-image']
        self.dockerCl = docker.from_env()

    # Only support one source code for now
    async def detect(self,
                     path_source: Sequence[Path],
                     targetContractName: Optional[str] = None,
                     targetLocations: Optional[Sequence[CodeRange]] = None,
                     targetedVul: Optional[Sequence[str]] = None,
                     fastFail: bool = True,
                     **extra_args) -> ProblemDetectorResult:
        """
        execute Slither for every single contract
        :param path_source:
        :param targetContractName: 
        :return:
        """

        logger.debug('Going to start Slither container')

        cmd = ['/bin/bash', '-c', 'slither /tmp/subject.sol --json -']

        def runContainer():
            container = self.dockerCl.containers.run(
                image=self.docker_image,
                command=cmd,
                detach=True,
                auto_remove=False,
                network_disabled=True,
                network_mode='none',
                tty=False,
                stdin_open=False,
                volumes={
                    path_source[0]: {
                        'bind': '/tmp/subject.sol',
                        'mode': 'ro'
                    }
                })

            # Purposely not checking the exit status
            container.wait()

            output = ''.join(
                line.decode(utf_8.getregentry().name)
                for line in container.logs(
                    stdout=True, stderr=False, stream=True, tail='all'))
            STDERROut = ''.join(
                line.decode(utf_8.getregentry().name)
                for line in container.logs(
                    stdout=False, stderr=True, stream=True, tail='all'))
            container.remove()

            return output, STDERROut

        output, STDERROut = await asyncio.get_event_loop().run_in_executor(
            self.threadPool, runContainer)

        assert len(
            STDERROut
        ) == 0, F'Slither STDERR output is non-empty!{os.linesep}STDERR:{os.linesep}{STDERROut}'
        logger.debug(F'Slither STDERR:{os.linesep}{STDERROut}')
        logger.trace(F'Slither output:{os.linesep}{output}')

        return self.__processOutput(output, targetedVul)

    def __processOutput(self,
                        output,
                        targetedVul: Optional[Sequence[str]] = None):

        try:
            rst = cast(Dict[str, Any], json.loads(output))
        except Exception:
            logger.critical(
                F'The following Slither output parsing failed...{os.linesep}{output}'
            )
            raise

        if not rst['success']:
            raise RuntimeError(
                F'Slither processed unsuccessfully. Error: {rst["error"]}')

        ret: List[DetectedVulnerability] = []
        for issue in rst['results']['detectors']:
            relevantElements_Node = tuple(e for e in issue['elements']
                                          if e['type'] == 'node')
            occurrence = tuple(
                sorted(
                    CodeRange(
                        start=Location(
                            line=min(e_sourceMap['lines']),
                            column=e_sourceMap['starting_column'] -
                            1  # -1 for 0-based column number
                        ),
                        end=Location(
                            line=max(e_sourceMap['lines']),
                            column=e_sourceMap['ending_column'] -
                            1  # -1 for 0-based column number
                        ))
                    for e_sourceMap in (e['source_mapping']
                                        for e in relevantElements_Node)))

            relevantElements_Function = sorted(
                (e for e in issue['elements'] if e['type'] == 'function'),
                key=lambda e: (e['type_specific_fields']['parent']['name'], e[
                    'name']))
            faultLocalizationInfo = tuple(
                chain((FaultElement_NodeType(
                    contractName=func['type_specific_fields']['parent']
                    ['name'],
                    functionName=func['name'],
                    nodeType='Block') for func in relevantElements_Function),
                      (FaultElement_CodeRange(codeRange=occur)
                       for occur in occurrence)))

            ret.append(
                DetectedVulnerability(
                    name=self.titleVulDict.get(issue['check'], issue['check']),
                    faultLocalizationInfo=faultLocalizationInfo))

        return ret
