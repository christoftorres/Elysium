"""
@author: Xiao Liang Yu
"""

from .IN import PatchSynthesizer
from .IN import MutationSequence
from .IN import PatchInfo
from tempfile import mkdtemp
from typing import Iterable, Deque
from pathlib import Path
import os
import subprocess
from subprocess import PIPE
from typing import Tuple, AsyncGenerator, Optional, List, Any, ClassVar, Sequence, Dict, cast, Iterator, Union
import json
from logbook import Logger
import sys
from encodings import utf_8
from shutil import which
from .Utils import strToBool
import attr
from abc import ABC
import asyncio
from contextlib import suppress
from .Utils import powerset
from collections import deque

logger = Logger(os.path.basename(__file__))


@attr.s(auto_attribs=True, frozen=True)
class RequestObject(ABC):
    type: str = attr.ib(init=False)


class SolidityM(PatchSynthesizer):

    name: ClassVar[str] = 'SolidityM'
    tempPatchDirs: Tuple[str, ...]
    path_sm: Path
    seed: Optional[str]
    mutation_types: List[str] = ['insert', 'replace', 'move']
    spaceInfo: Dict[Tuple[str, ...], Dict[str, Any]]
    must_include_mutation_types: Optional[List[str]] = None # TODO: Unused
    output_mutation: bool
    for_node_types: Optional[List[str]] = None
    replaceable_node_types: Optional[List[str]] = None
    profiling: bool = False

    def __init__(self, args: Dict[str, str]):
        super().__init__(args)

        args_ = {**args}

        self.path_sm = Path(
            args_.pop('path_sm')).expanduser().resolve()
        self.seed = args_.pop('seed', None)
        self.output_mutation = strToBool(
            args_.pop('output_mutation', str(False)))

        # Whether enable nodejs profiling
        if 'profiling' in args_:
            self.profiling = strToBool(args_.pop('profiling'))
            logger.info(F'sm profiling enabled.')

        mutation_types = args_.pop('mutation_types', None)
        if mutation_types is not None:
            self.mutation_types = mutation_types.strip().split(' ')

        self.spaceInfo = {space: {'tempPatchDir': mkdtemp()} for space in tuple(filter(lambda x: x, powerset(self.mutation_types)))}

        must_include_mutation_types: Optional[str] = args_.pop('must-include-mutation-types', None)
        if must_include_mutation_types is not None:
            self.must_include_mutation_types = must_include_mutation_types.strip().split(' ')

        for_node_types = args_.pop('for_node_types', None)
        if for_node_types is not None:
            self.for_node_types = for_node_types.strip().split(' ')

        replaceable_node_types = args_.pop('replaceable_node_types', None)
        if replaceable_node_types is not None:
            self.replaceable_node_types = replaceable_node_types.strip().split(
                ' ')

        if self.seed is not None:
            logger.info('Using seed {} for randomness'.format(self.seed))

        if args_:
            logger.warn(
                F'The following passed arguments are unused: {args_.keys()}')

    patchSourceLock = asyncio.Lock()
    async def patchSource(
            self,
            path_ori_source: Sequence[Path],
            num_patched: int = 1,
            fault_specifier: Any = None,
            **extra_args
    ) -> AsyncGenerator[Tuple[PatchInfo, ...], Optional[RequestObject]]:
        gen = self.__patchSource(path_ori_source, num_patched, fault_specifier,
                                 **extra_args)
        val = None
        while True:
            # Can only send sm one request each time
            async with self.patchSourceLock:
                try:
                    val = yield (await gen.asend(val))
                except StopAsyncIteration:
                    return

    # Only support doing for one file
    # Note: This method is completely sync for avoiding concurrent request to sm which can't be handled
    async def __patchSource(
            self,
            path_ori_source: Sequence[Path],
            num_patched: int = 1,
            fault_specifier: Any = None,
            **extra_args
    ) -> AsyncGenerator[Tuple[PatchInfo, ...], Optional[RequestObject]]:
        """
        NOTE: This whole function is in critical region
        """

        unconsumedPatches: Deque[Dict[str, Union[PatchInfo, str]]] = deque()

        # Building CMD
        args = [
            str(self.path_sm), 'iter-gen-mutations',
            '--only-compilable=true',
            str(path_ori_source[0])
        ]

        if self.seed is not None:
            args.append(F"--seed={self.seed}")

        if fault_specifier is not None:
            args.append(F'--mutation-space={fault_specifier}')

        if self.output_mutation:
            args.append('--output-mutation')

        if self.for_node_types is not None:
            args.append('--for-node-types')
            args.extend(self.for_node_types)

        if self.replaceable_node_types is not None:
            args.append('--replaceable-node-types')
            args.extend(self.replaceable_node_types)

        logger.trace(F'Constructed base args for sm: {args!r}')

        if os.path.exists('/tmp/terminate_all'):
            os.unlink('/tmp/terminate_all')

        try:

            for space in self.spaceInfo:

                thisArgs = [*args, F'--patched-src-dir={self.spaceInfo[space]["tempPatchDir"]}']

                # This should be the last one to add
                thisArgs.append('--mutation_types')
                thisArgs.extend(space)
                
                # This should be the last one to add
                thisArgs.append('--must-include-mutation-types')
                thisArgs.extend(space)

                logger.trace(F'Start sm for space {space} with args: {thisArgs!r}')
                self.spaceInfo[space]['proc'] = await asyncio.create_subprocess_exec(*thisArgs,
                                            #    bufsize=0,
                                            limit=2**128,
                                            stdin=PIPE,
                                            stdout=PIPE,
                                            stderr=sys.stderr,
                                            #    shell=False,
                                            #    universal_newlines=True,
                                            encoding=utf_8.getregentry().name)

                logger.debug(F'sm for space {space} started: pid={self.spaceInfo[space]["proc"].pid}')

            request = None

            while True:

                requestObj: RequestObject

                if request is None:
                    requestObj = RequestObject_Random(num_mutations=num_patched)
                else:
                    assert (isinstance(request, RequestObject))
                    requestObj = request

                requestDict = attr.asdict(requestObj,
                                        recurse=True,
                                        retain_collection_types=True)

                # For debugging
                logger.trace(F'sm input: {requestDict!r}')

                jsonStr = json.dumps(requestDict)

                OkPatches = [x for x in unconsumedPatches if x['json'] == jsonStr]
                if OkPatches:
                    # Consume first
                    unconsumedPatches.remove(OkPatches[0])
                    request = yield (OkPatches[0]['payload'], )
                    continue

                self.checkIfProcessesOkay()
                if not self.allRunningProcesses():
                    break
                
                stdinDrainTasks = []
                for _, proc in self.allRunningProcesses():
                    proc.stdin.write(bytes(jsonStr + os.linesep, utf_8.getregentry().name))
                    stdinDrainTasks.append(proc.stdin.drain())
                
                await asyncio.gather(*stdinDrainTasks)
                readTasks = [asyncio.Task(proc.stdout.readline()) for _, proc in self.allRunningProcesses()]

                _, pending = await asyncio.wait(readTasks, return_when=asyncio.FIRST_COMPLETED)
                
                for _, proc in self.allRunningProcesses():
                    open(F'/tmp/terminate_{proc.pid}', 'w').close()
                open('/tmp/terminate_all', 'w').close()
                logger.trace('Sent SIGUSR2')

                await asyncio.gather(*pending)
                rs = [x.result() for x in readTasks]
                
                os.unlink('/tmp/terminate_all')

                gotHax = False
                for space, r in zip(self.spaceInfo, rs):
                    out = r.decode(utf_8.getregentry().name)
                    if out == '':
                        raise RuntimeError(
                            F"Unexpected empty output from sm for space {space}")

                    try:
                        resultObj = json.loads(out)
                    except Exception:
                        logger.error(
                            F'sm for space {space} output is not JSON! output:{os.linesep}{out!r}'
                        )
                        raise

                    assert isinstance(
                        resultObj.get('Result'), str
                    ), F'Unexpected result object from sm for space {space} :\n{resultObj!r}'

                    logger.trace(F'sm for space {space} OUTPUT: {resultObj!r}')

                    if resultObj['Result'] == 'AllSpaceExhasuted':
                        gotHax = True
                        continue
                    elif resultObj['Result'] == 'SpaceExhasutedForAST':
                        newRst: Tuple[PatchInfo, ...] = ()
                    else:
                        newRst = tuple(
                            PatchInfo(MutationSequence=mutationSeq,
                                    PatchedFilePath=filePath,
                                    ModifiedLocations=modifiedLocations if modifiedLocations != 'unknown' else None)
                            for mutationSeq, filePath, modifiedLocations in zip(
                                resultObj['NewMutationSequences'],
                                resultObj['PatchedFilePaths'],
                                resultObj['ModifiedLocations'],
                            ))
                    
                    for r in newRst:
                        if r.ModifiedLocations is None:
                            logger.debug(F'{r.PatchedFilePath} has unknown modified locations!')
                    
                    unconsumedPatches.extend(({"payload": x, "json": jsonStr} for x in newRst))

                OkPatches = [x for x in unconsumedPatches if x['json'] == jsonStr]
                if not OkPatches:
                    if not gotHax:
                        request = yield ()
                    continue
                unconsumedPatches.remove(OkPatches[0])
                request = yield (OkPatches[0]['payload'], )
            return

        finally:
            self.killAllProcesses()

    def allProcesses(self) -> Tuple[Tuple[Tuple[str, ...], Any], ...]:
        return tuple((space, info['proc']) for space, info in self.spaceInfo.items() )

    def allTerminatedProcesses(self):
        return tuple(x for x in self.allProcesses() if x[1].returncode is not None )

    def allRunningProcesses(self):
        return tuple(x for x in self.allProcesses() if x[1].returncode is None )

    def checkIfProcessesOkay(self):
        for space, proc in self.allTerminatedProcesses():
            if proc.returncode != 0:
                raise RuntimeError(
                    F"sm for space {space}  terminated unexpectedly, return code: {proc.returncode}")

    def killAllProcesses(self):
        for _, proc in self.allRunningProcesses():
            with suppress(ProcessLookupError):
                    proc.kill()


@attr.s(auto_attribs=True, frozen=True)
class RequestObject_Random(RequestObject):
    type: str = attr.ib(default='random', init=False)
    num_mutations: int


@attr.s(auto_attribs=True, frozen=True)
class RequestObject_Mutate(RequestObject):
    type: str = attr.ib(default='mutate', init=False)
    baseMutationSequence: MutationSequence
    overridenFaultSpaceSpecifier: Optional[str] = None


@attr.s(auto_attribs=True, frozen=True)
class RequestObject_Crossover_OnePoint(RequestObject):
    type: str = attr.ib(default='crossover-onepoint', init=False)
    MutationSequence1: MutationSequence
    CrossPoint1: int
    MutationSequence2: MutationSequence
    CrossPoint2: int
