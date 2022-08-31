"""
@author: Xiao Liang Yu
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, AsyncGenerator, Tuple, Any, Sequence, Optional, Dict
import attr

Mutation = Tuple[str, ...]
MutationSequence = Tuple[Mutation, ...]


import attr
from typing import Optional

@attr.s(auto_attribs=True, cmp=True, frozen=True)
class Location(object):
    line: int
    column: Optional[int]

import attr


@attr.s(auto_attribs=True, cmp=True, frozen=True)
class CodeRange(object):
    start: Location = attr.ib(
        converter=(lambda x: Location(**x) if isinstance(x, dict) else x)) # type: ignore
    end: Location = attr.ib(
        converter=(lambda x: Location(**x) if isinstance(x, dict) else x)) # type: ignore

    def intersectWith(self, other) -> bool:
        return (self.start >= other.start
                and self.start <= other.end) or (other.start >= self.start
                                                 and other.start <= self.end)

@attr.s(auto_attribs=True, frozen=False)
class PatchInfo(object):
    MutationSequence: MutationSequence
    PatchedFilePath: Path
    ModifiedLocations: Optional[Tuple[CodeRange, ...]] = None

    @classmethod
    def fromPatchInfo(selfCls, patchInfo: 'PatchInfo') -> 'PatchInfo':
        return selfCls(MutationSequence=patchInfo.MutationSequence, PatchedFilePath=patchInfo.PatchedFilePath)

class PatchSynthesizer(ABC):
    """Abstract Base Class for generic patch synthesizer
    """

    """
    Whether the synthesizer is compatible with general RepairCore
    """
    pluggable: bool = True

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def __init__(self, args: Optional[Dict[str, str]] = None):
        pass

    @abstractmethod
    async def patchSource(
            self,
            path_ori_source: Sequence[Path],
            num_patched: int = 1,
            fault_specifier: Any = None,
            **extra_args
    ) -> AsyncGenerator[Tuple[PatchInfo, ...], Any]:
        """Abstract method: Attempt to patch buggy source code

        Returns:
            An Iterable of paths of patched source code files
        """

        # Must contain yield statement for mypy to work correctly
        yield ()

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, Dict, Union, Optional, Sequence, AsyncGenerator, Any
import attr
from .Utils import FaultElement, FaultElement_CodeRange


@attr.s(auto_attribs=True, frozen=True, kw_only=True)
class VulnerabilityInfo(object):
    """
    This class represent information about one vulnerabilitiy.
    Each instance should correspond to one independent piece of information about vulnerability.
    """
    name: str
    detected: bool
    additionalInfo: Any = None

    # TODO: add coverage information attribute

    def isTargeted(self,
                   targetedVul: Optional[Sequence[str]] = None,
                   targetedLocation: Optional[Sequence[CodeRange]] = None
                   ) -> bool:
        return self.name in targetedVul if targetedVul is not None else self.detected


@attr.s(auto_attribs=True, frozen=True, kw_only=True)
class NonDetectedVulnerability(VulnerabilityInfo):
    detected: bool = attr.ib(default=False, init=False)


@attr.s(auto_attribs=True, frozen=True, kw_only=True)
class DetectedVulnerability(VulnerabilityInfo):
    detected: bool = attr.ib(default=True, init=False, repr=False)
    faultLocalizationInfo: Optional[Sequence[FaultElement]] = None

    def isTargeted(self,
                   targetedVul: Optional[Sequence[str]] = None,
                   targetedLocation: Optional[Sequence[CodeRange]] = None
                   ) -> bool:
        return super().isTargeted(
            targetedVul,
            None) and (self.faultLocalizationInfo is None
                       or targetedLocation is None or any(
                           occ.codeRange.intersectWith(targetedLoc)
                           for occ in self.faultLocalizationInfo
                           if isinstance(occ, FaultElement_CodeRange)
                           for targetedLoc in targetedLocation))


@attr.s(auto_attribs=True, frozen=True, kw_only=True)
class DetectedVulnerability_FastFail(DetectedVulnerability):
    name: str = 'FastFail'

    def isTargeted(self,
                   targetedVul: Optional[Sequence[str]] = None,
                   targetedLocation: Optional[Sequence[CodeRange]] = None
                   ) -> bool:
        return True


ProblemDetectorResult = Sequence[VulnerabilityInfo]


class ProblemDetector(ABC):
    """Abstract Base Class for component that detects problems in source code
    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def __init__(self, args: Optional[Dict[str, str]] = None):
        pass

    @abstractmethod
    async def detect(self,
                     path_source: Sequence[Path],
                     targetContractName: Optional[str],
                     targetLocations: Optional[Sequence[CodeRange]],
                     targetedVul: Optional[Sequence[str]] = None,
                     fastFail: bool = False,
                     **_extra_args) -> ProblemDetectorResult:
        """Abstract method: Detect whether there's any problem in the provided source code

        Args:
            path_source (Iterable[Path]): An iterable of path to source codes

        Returns:
            Sequence of DetectedVulnerability object
        """
        pass

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Iterable, Type, Sequence, Optional, Union, DefaultDict, Dict, Awaitable
import attr
import asyncio
import math
from itertools import chain
from logbook import Logger
import os
from collections import ChainMap

logger = Logger(os.path.basename(__file__))


@attr.s(auto_attribs=True, frozen=True)
class PlausiblePatch(object):
    PathPatchedCode: Path


class ProblemDetectorResults(Dict[str, ProblemDetectorResult]):
    pass


@attr.s(auto_attribs=True)
class RepairTarget_Detector_Target(ABC):
    @abstractmethod
    def isTargetFulfilled(self, rst: ProblemDetectorResult,
                          targetedVuls: Optional[Sequence[str]], targetedLoc: Optional[Sequence[CodeRange]]) -> bool:
        pass

    @abstractmethod
    def cmpProblemDetectorResult(self, a: ProblemDetectorResult, b: ProblemDetectorResult, targetedVuls: Optional[Sequence[str]], targetedLoc: Optional[Sequence[CodeRange]]) -> int:
        pass


@attr.s(auto_attribs=True)
class RepairTarget_Detector_Target_Remaining(RepairTarget_Detector_Target):
    """ RepairTarget_Detector_Target_Remaining Specify the acceptable number of remaining targeted vulnerability.
    When number of targeted vulnerabilities less than or equal to the specified number is demed as acceptabpe. 
    """
    num_remaining: Union[int, float] = 0

    def isTargetFulfilled(self, rst: ProblemDetectorResult,
                          targetedVuls: Optional[Sequence[str]], targetedLoc: Optional[Sequence[CodeRange]]) -> bool:
        return self.num_remaining >= sum(
            1 for r in rst if r.isTargeted(targetedVuls, targetedLoc))
    
    def cmpProblemDetectorResult(self, a: ProblemDetectorResult, b: ProblemDetectorResult, targetedVuls: Optional[Sequence[str]], targetedLoc: Optional[Sequence[CodeRange]]) -> int:
        """
        Return positive number when a is better than b. Negative when b is better than a. 0 when they are equally good. With regard to this RepairTarget
        """
        raise NotImplementedError()


@attr.s(auto_attribs=True)
class RepairTarget_Detector_Target_Repaired(
        RepairTarget_Detector_Target_Remaining):
    num_original_targetedVuls: int = attr.ib(repr=False)

    num_repaired: Union[int, float] = math.inf

    num_remaining: int = attr.ib(
        repr=False,
        init=False,
        default=attr.Factory(lambda self: self.num_original_targetedVuls - self
                             .num_repaired
                             if not math.isinf(self.num_repaired) else 0,
                             takes_self=True))


class RepairTarget(DefaultDict[str, RepairTarget_Detector_Target]):
    def __init__(self, *args, **kwargs):
        super().__init__(RepairTarget_Detector_Target_Remaining, *args,
                         **kwargs)

    def isTargetFulfilled(self, rsts: ProblemDetectorResults,
                          targetedVuls: Optional[Sequence[str]], targetedLoc: Optional[Sequence[CodeRange]]) -> bool:
        return all(self[detector].isTargetFulfilled(vuls, targetedVuls, targetedLoc)
                   for detector, vuls in rsts.items())

    def criticalProblemDetector(self) -> Sequence[str]:
        """
        Return the name of `ProblemDetector`s that is related to the repair target
        """
        return tuple(self.keys())
    
    def cmpProblemDetectorResults(self, a: ProblemDetectorResults, b: ProblemDetectorResults) -> int:
        raise NotImplementedError()


class RepairCore(ABC):
    """Abstract Base Class for repair component
    """

    problemDectors: Dict[str, ProblemDetector]
    patchSynthesizers: Dict[str, PatchSynthesizer]

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def __init__(self,
                 clsProblemDectors: Iterable[Type[ProblemDetector]],
                 clsPatchSynthesizers: Iterable[Type[PatchSynthesizer]],
                 detectorArgs: Optional[Dict[str, str]] = None,
                 synthesizerArgs: Optional[Dict[str, str]] = None,
                 repaircoreArgs: Optional[Dict[str, str]] = None):
        self.problemDectors = self.instantiateProblemDectors(
            clsProblemDectors, detectorArgs)
        self.patchSynthesizers = self.instantiatePatchSynthesizer(
            clsPatchSynthesizers, synthesizerArgs)

    @abstractmethod
    async def repair(self,
                     path_source: Sequence[Path],
                     targetContractName: str,
                     targetedVul: Optional[List[str]] = None,
                     targetedLoc: Optional[Sequence[CodeRange]] = None,
                     num_plausible: int = 1,
                     repair_target: RepairTarget = RepairTarget(),
                     maxTrial: Optional[int] = None,
                     **extra_args) -> Sequence[PlausiblePatch]:
        """Abstract method: Attempt to repair the given source codes. Returns a dict {}

        Args:
            path_source (Iterable[Path]): An Iterable of path of potentially buggy code files
        """

        pass

    @staticmethod
    def instantiateProblemDectors(
            clsProblemDectors: Iterable[Type[ProblemDetector]],
            detectorArgs: Optional[dict] = None) -> Dict[str, ProblemDetector]:

        if detectorArgs is None: detectorArgs = {}

        return {
            pd.name: pd
            for pd in (clsPd(args=detectorArgs) for clsPd in clsProblemDectors)
        }

    @staticmethod
    def instantiatePatchSynthesizer(
            clsPatchSynthesizers: Iterable[Type[PatchSynthesizer]],
            synthesizerArgs: Optional[dict] = None
    ) -> Dict[str, PatchSynthesizer]:
        # TODO: handle when more than one synthesizer is of the same name

        if synthesizerArgs is None: synthesizerArgs = {}

        return {
            ps.name: ps
            for ps in (clsPs(args=synthesizerArgs)
                       for clsPs in clsPatchSynthesizers)
        }

    @staticmethod
    def targetVulDetected(rst: ProblemDetectorResults,
                          targetedVul: Optional[Sequence[str]] = None) -> bool:
        return any(
            vul.isTargeted(targetedVul)
            for vul in chain.from_iterable(rst.values()))

    async def detectPatch(
            self,
            patch: PatchInfo,
            targetContractName: str,
            targetLocations: Optional[Sequence[CodeRange]] = None,
            fastFail: bool = False,
            targetedVul: Optional[Sequence[str]] = None,
            not_skippable_detectors: Sequence[str] = ()
    ) -> ProblemDetectorResults:
        """
        Only need to specify `targetedVul` and optionally `not_skippable_detectors` when fastFail is True
        """

        class FastFailException(Exception):
            pass

        async def coroTargetVulDetect(
                detectCoro: Awaitable[ProblemDetectorResult], fastFail: bool):

            rst = await detectCoro
            rst_ = ProblemDetectorResults({'detector:': rst})
            if self.targetVulDetected(rst_,
                                      targetedVul) is not False and fastFail:
                raise FastFailException()

            return rst

        async def helper(detectorName, detector, fastFail: bool):
            return (detectorName, await coroTargetVulDetect(
                detector.detect((patch.PatchedFilePath, ), targetContractName,
                                targetLocations, targetedVul, fastFail), fastFail))

        skippable_problemDetectors = {
            k: self.problemDectors[k]
            for k in self.problemDectors if k not in not_skippable_detectors
        }
        non_skippable_problemDetectors = {
            k: self.problemDectors[k]
            for k in self.problemDectors if k in not_skippable_detectors
        }

        # Note: made fastFail False for non-skippable detector. This might not always be wanted
        non_skippable_feature = asyncio.gather(*(
            helper(detectorName, detector, False) for detectorName, detector in
            non_skippable_problemDetectors.items()))
        skippable_feature = asyncio.gather(*(
            helper(detectorName, detector, fastFail)
            for detectorName, detector in skippable_problemDetectors.items()))

        async def skippableAsyncFn_helper():
            try:
                return await skippable_feature
            except FastFailException:
                logger.debug(
                    'Some detector detected target vulnerability and fastFaill specified, cancelling continuation of evaluation of this patch.'
                )

                skippable_feature.cancel()

                return ('fastfail', (DetectedVulnerability_FastFail(), ))

        rsts = await asyncio.gather(skippableAsyncFn_helper(),
                                    non_skippable_feature)

        return ProblemDetectorResults(chain.from_iterable((rsts[0], rsts[1])))

from itertools import chain
from typing import Optional, Sequence, cast, Tuple
from .Utils import FaultLocalization

def faultLocalizationFromDetectionResults(
        detectRst: ProblemDetectorResults,
        targetedVul: Optional[Sequence[str]] = None,
        targetedLoc: Optional[Sequence[CodeRange]] = None
) -> FaultLocalization:

    return FaultLocalization(
        tuple(
            chain.from_iterable(
                vul.faultLocalizationInfo
                for vul in chain.from_iterable(detectRst.values())
                if isinstance(vul, DetectedVulnerability)
                and vul.isTargeted(targetedVul, targetedLoc)
                and vul.faultLocalizationInfo is not None)))
