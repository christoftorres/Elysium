"""
@author: Xiao Liang Yu
"""
from .IN import RepairCore, PatchSynthesizer, ProblemDetector, PatchInfo, ProblemDetectorResult, DetectedVulnerability, VulnerabilityInfo, PlausiblePatch, RepairTarget, ProblemDetectorResults, MutationSequence, CodeRange
from pathlib import Path
from typing import Iterable, Tuple, Optional, List, Union, Type, Dict, NoReturn, Any, AsyncGenerator, Set, Sequence, DefaultDict, Callable, cast, Awaitable
from .SolidityM import SolidityM, RequestObject_Mutate, RequestObject_Crossover_OnePoint, RequestObject
from logbook import Logger
import os
from collections import defaultdict
from deap import base, creator, tools
import numpy as np
from random import Random
import random
from functools import partial
from itertools import repeat, count, combinations, chain
import asyncio
from operator import attrgetter
import itertools
import math
from operator import truediv, mul
from .Utils import strToBool
from .IN import faultLocalizationFromDetectionResults, FaultLocalization, FaultElement_CodeRange
from copy import deepcopy
from .Slither import Slither
from .GR import GR
from .ETC import ETC

# import matplotlib.pyplot as plt
# import networkx

logger = Logger(os.path.basename(__file__))
report_interval = 1000

# The patch type
Patch = PatchInfo


class PatchInfo_(PatchInfo):
    def __init__(self, patchInfo: PatchInfo):
        super().__init__(MutationSequence=patchInfo.MutationSequence,
                         PatchedFilePath=patchInfo.PatchedFilePath,
                         ModifiedLocations=patchInfo.ModifiedLocations)


class Fitness(base.Fitness):

    soft_weights = None
    soft_wvalues = ()
    gas_info: Optional[Dict[str, int]] = None

    def __init__(self, values=()):
        super().__init__(values)

        if self.soft_weights is None:
            raise NotImplementedError()

    def __soft_getValues(self):
        return tuple(map(truediv, self.soft_wvalues, self.soft_weights))

    def __soft_setValues(self, values):
        assert len(values) == len(self.soft_weights)
        self.soft_wvalues = tuple(map(mul, values, self.soft_weights))

    def __soft_delValues(self):
        self.soft_wvalues = ()

    soft_values = property(__soft_getValues, __soft_setValues,
                           __soft_delValues)

    def __hash__(self):
        return hash(
            frozenset({
                'hard': self.wvalues,
                'soft': self.soft_wvalues
            }.items()))

    def __le__(self, other):

        assert isinstance(other, CR_Fitness)

        if not super().__eq__(other):
            return super().__le__(other)
        elif self.__eq__(other):
            return True
        else:
            return self.__lt__(other)

    def __lt__(self, other):

        assert isinstance(other, CR_Fitness)

        if not super().__eq__(other):
            return super().__lt__(other)
        elif self.__eq__(other):
            return False
        else:
            return (self.soft_wvalues < other.soft_wvalues) and other.gas_dominates(self)

    def __ge__(self, other):
        return not self.__lt__(other)

    def __gt__(self, other):
        return not self.__le__(other)

    def __eq__(self, other):
        assert isinstance(other, CR_Fitness)

        return super().__eq__(
            other) and self.soft_wvalues == other.soft_wvalues and not self.gas_dominates(other) and not other.gas_dominates(self)

    def __deepcopy__(self, memo):
        newCopy = super().__deepcopy__(memo)
        newCopy.soft_weights = self.soft_weights
        return newCopy

    def __repr__(self):
        str_content = F'Hard: {self.values} Soft: {self.soft_values}' if self.valid else 'Invalid'
        return F'{self.__class__.__name__}({str_content})'

    def __str__(self):
        return str({
            'hard': super().__str__(),
            'soft': str(self.soft_values if self.valid else tuple())
        })

    def dominates(self, other, obj=slice(None)):
        if not super().__eq__(other):
            return super().dominates(other, obj)
        else:

            if profiling:
                logger_profiling.info('Dominance relationship using 2nd objectives now')

            not_equal = False
            for self_soft_wvalues, other_soft_wvalues in zip(
                    self.soft_wvalues[obj], other.soft_wvalues[obj]):
                if self_soft_wvalues > other_soft_wvalues:
                    not_equal = True
                elif self_soft_wvalues < other_soft_wvalues:
                    return False

            if other.gas_dominates(self):
                return False

            # assert(not other.gas_dominates(self))

            if not_equal:
                # No matter whether `self.gas_dominates(other) is True`
                return True
            else:
                # All other soft values are equal
                return self.gas_dominates(other)

    def gas_dominates(self, other: "CR_Fitness"):
        assert isinstance(other, CR_Fitness)

        assert isinstance(self.gas_info, dict)
        assert isinstance(other.gas_info, dict)

        if profiling:
                logger_profiling.info('Gas dominance being determined')

        if self.gas_info.keys() != other.gas_info.keys():
            return False

        for k in self.gas_info.keys():
            if self.gas_info[k] > other.gas_info[k]:
                return False

        if self.gas_info == other.gas_info:
            return False

        return True

    def __deepcopy__(self, memo):
        obj = super().__deepcopy__(memo)
        obj.soft_weights = self.soft_weights
        obj.soft_wvalues = self.soft_wvalues
        obj.gas_info = self.gas_info

        return obj


class CR(RepairCore):

    name: str = 'CR'
    problemDetectors: Tuple[ProblemDetector, ...]
    fault_space_specifier: Optional[str]
    seed: Optional[str]
    p_crossover: float = 0.3
    num_init_population: int = 8
    maxSzPopulation: int = 20
    gasRanker: GR
    path_genealogy_graph: Optional[Path]
    max_mutation_distance: Union[int, float]

    def __init__(self,
                 problemDectors: Iterable[Type[ProblemDetector]],
                 _,
                 detectorArgs: Optional[dict] = None,
                 synthesizerArgs: Optional[dict] = None,
                 coreArgs: Optional[Dict[str, str]] = None):
        # Ignore whatever synthesizer requested
        #super().__init__((Slither, ETC), (SolidityM, ),
        super().__init__((Slither, ), (SolidityM, ),
                         detectorArgs, synthesizerArgs)

        assert coreArgs is not None

        self.fault_space_specifier = coreArgs.pop('fault-space-specifier',
                                                  None)

        self.seed = coreArgs.pop('seed', None)

        if 'p-crossover' in coreArgs:
            self.p_crossover = float(coreArgs.pop('p-crossover'))

        if 'num-init-population' in coreArgs:
            self.num_init_population = int(coreArgs.pop('num-init-population'))
        assert self.num_init_population >= 1

        if 'max-size-population' in coreArgs:
            self.maxSzPopulation = int(coreArgs.pop('max-size-population'))
        assert self.maxSzPopulation >= 1

        disable_gas_objective = strToBool(
            coreArgs.pop('disable-gas-objective', str(False)))
        self.gasRanker = GR(
            coreArgs.pop('oyente-docker-image')
        )

        # Save as PNG image
        # TODO: output genealogy graph
        self.path_genealogy_graph = Path(
            coreArgs.pop('path-genealogy-graph'
                         )) if 'path-genealogy-graph' in coreArgs else None

        self.max_mutation_distance = int(
            coreArgs.pop('max-mutation-dist'
                         )) if 'max-mutation-dist' in coreArgs else math.inf

    async def repair(self,
                     path_source: Sequence[Path],
                     targetContractName: str,
                     targetedVul: Optional[Sequence[str]] = None,
                     targetedLoc: Optional[Sequence[CodeRange]] = None,
                     num_plausible: int = 1,
                     repair_target: RepairTarget = RepairTarget(),
                     maxTrial: Optional[int] = None,
                     **extra_args) -> List[PlausiblePatch]:
        """MOGA patch searching
        """

        # Certain library like DEAP doesn't support passing seed as arguments, need to change it globally
        if self.seed is not None:
            random.seed(self.seed)

        toolbox = base.Toolbox()

        paretofront = tools.ParetoFront()

        stats_fitness = tools.Statistics()
        stats_fitness.register(
            'min', lambda inds: min(ind.fitness for ind in inds)
            if len(inds) != 0 else 'N/A')
        stats_fitness.register(
            'max', lambda inds: max(ind.fitness for ind in inds)
            if len(inds) != 0 else 'N/A')

        stats_vul = tools.Statistics()
        stats_vul.register(
            'vuls-best-patch(max: 3)', lambda inds: {
                d: tuple(itertools.islice(iter(vuls), 3))
                for d, vuls in tools.selBest(inds, 1)[0].vulnerability.items()
            } if len(inds) != 0 else "N/A")  # Maximum showing 3 items
        stats_vul.register(
            '#targetedVuls', lambda inds: tuple(
                self.targetedVulnerabilityCount(p, targetedVul, targetedLoc) for p in inds))

        stats_vul.register(
            '#targetedVuls(detailed)', lambda inds: tuple(
                str({
                    detectorName: sum(1 for vul in vuls
                                      if vul.isTargeted(targetedVul, targetedLoc))
                    for detectorName, vuls in p.vulnerability.items()
                }) for p in inds))

        multistats = tools.MultiStatistics(**{
            "fitness values": stats_fitness,
            "vulnerabilities": stats_vul,
        })

        creator.create(
            'FitnessMultiMin_improved',
            Fitness,
            weights=((1.0, ) * len(self.problemDectors)) + (),
            soft_weights=(
                -1.0,  # Mutation Sequence Length
                # -1.0,  # Average Gas Usage
            ))
        creator.create('Individual',
                       PatchInfo_,
                       fitness=creator.FitnessMultiMin_improved,
                       vulnerability=None)

        toolbox.register('selForMutation', tools.selBest)
        toolbox.register('selForCrossover', tools.selBest)
        toolbox.register('select', tools.selNSGA2)
        toolbox.register(
            'evaluate',
            partial(self.calculateFitness,
                    targetContractName=targetContractName,
                    targetedVul=targetedVul,
                    targetedLoc=targetedLoc))

        original_src_path_obj = creator.Individual(
            PatchInfo(MutationSequence=(),
                      PatchedFilePath=path_source[0],
                      ModifiedLocations=()))

        GALogbook = tools.Logbook()
        GALogbook.header = "gen", "evals", "fitness values", "op", "vulnerabilities"
        GALogbook.chapters["fitness values"].header = "min", "max"
        GALogbook.chapters[
            'vulnerabilities'].header = "#targetedVuls", "#targetedVuls(detailed)" "vuls-best-patch(max: 3)"

        populations: List[Patch] = [original_src_path_obj]

        await self.evaluatePopulation(targetContractName,
                                      [original_src_path_obj],
                                      toolbox.evaluate)

        logger.info(
            F'Initial subject contract has the following targeted vulnerabilities:{os.linesep}{original_src_path_obj.vulnerability!r}'
        )

        initialTargetedVulnerabilities = original_src_path_obj.vulnerability
        if not (initialTargetedVulnerabilities):
            logger.warn(F'No targeted vulnerability in the original contract!')
            return [
                PlausiblePatch(
                    PathPatchedCode=original_src_path_obj.PatchedFilePath)
            ]

        if self.fault_space_specifier is None:
            self.fault_space_specifier = faultLocalizationFromDetectionResults(
                original_src_path_obj.vulnerability,
                targetedVul, targetedLoc).toSpecifierStr()

            logger.debug(
                F'Generated init fault space specifier: {self.fault_space_specifier}'
            )

        patchGen = next(iter(self.patchSynthesizers.values())).patchSource(
            path_source, 1, self.fault_space_specifier)

        # Generate initial population
        # Assume patchGen never exhausted here
        firstIndividual = creator.Individual((await patchGen.asend(None))[0])
        await self.evaluatePopulation(targetContractName, (firstIndividual, ),
                                      toolbox.evaluate)
        initPopulation_ = cast(
            List[Optional[creator.Individual]], await
            asyncio.gather(*(self.mutatePatchAndEvaluate(
                (), patchGen, self.fault_space_specifier, targetContractName,
                toolbox.evaluate)
                             for i in range(self.num_init_population - 1))))

        initPopulation = [p for p in initPopulation_ if p is not None]

        initPopulation.insert(0, firstIndividual)
        populations.extend(initPopulation)

        initPopulation.append(original_src_path_obj)

        # Assign crowding distance, not really select
        toolbox.select(populations, len(populations))

        rng = Random(self.seed) if self.seed is not None else Random()

        newPatchCandidates = initPopulation
        op = 'init'

        num_patch_tried = -1

        plausiblePatchFound = False
        try:
            for gen in count(start=0, step=1):

                logger.info(F'Currently done evaluating generation {gen}\a')
                if len(newPatchCandidates) != 0:
                    # Don't record for generation that didn't have new population due to a bug in deap.LogBook
                    # Otherwise, when there are 3 or more records with no new population will make LogBook not printable
                    record = multistats.compile(newPatchCandidates)
                    GALogbook.record(gen=gen,
                                     evals=len(newPatchCandidates),
                                     op=op,
                                     **record)
                    logger.info(GALogbook)

                paretofront.update(newPatchCandidates)
                paretofrontStats = multistats.compile(paretofront)
                logger.info(F'ParetoFront: \n{paretofrontStats}')

                num_patch_tried += len(newPatchCandidates)
                logger.info(F'Evaluated {num_patch_tried} patches')

                plausiblePatches = [
                    patch for patch in newPatchCandidates
                    if self.isPatchPlausible(patch, targetedVul, targetedLoc, repair_target)
                ]

                if plausiblePatches:
                    # Found plausible patch!

                    plausiblePatches.sort(key=attrgetter('fitness'),
                                          reverse=True)

                    # Show info for all plausible patches

                    record = multistats.compile(plausiblePatches)
                    GALogbook.record(gen='plausible-last-gen',
                                     evals=len(plausiblePatches),
                                     op=op,
                                     **record)
                    logger.info(GALogbook)
                    logger.info(
                        F'Plausible patches details:{os.linesep}{plausiblePatches}'
                    )
                    logger.info(F'Evaluated {num_patch_tried} patches')

                    plausiblePatchFound = True
                    return [
                        PlausiblePatch(PathPatchedCode=p.PatchedFilePath)
                        for p in plausiblePatches
                    ]

                if maxTrial is not None and num_patch_tried >= maxTrial:
                    logger.info(
                        F'{num_patch_tried} compilable patches tried. But, no plausible found!'
                    )
                    logger.info(
                        'Maximum number of compilable patches reached, exiting'
                    )
                    return []

                szPopulations = len(populations)
                # populations = toolbox.select(
                #     populations,
                #     math.floor(szPopulations / 4) *
                #     4 if szPopulations < self.maxSzPopulation else self.maxSzPopulation)
                populations = toolbox.select(populations, self.maxSzPopulation)

                if rng.random() >= self.p_crossover:
                    logger.debug('Performing Mutate')
                    # Perform mutate
                    op = 'mutate'
                    offspringParents = toolbox.selForMutation(
                        populations, 4
                    )  # Must select 4 elements at a time and len(populations)%4==0

                    newPatchCandidates = []

                    assert offspringParents, F"No offspring parents being chosen!{os.linesep}Populations: {populations=!r}"

                    for p in offspringParents:

                        logger.debug(F'Chosen patch as parent: {p}')
                        newFaultSpecifier = faultLocalizationFromDetectionResults(
                            p.vulnerability,
                            targetedVul, targetedLoc).toSpecifierStr()

                        newPatch = await self.mutatePatchAndEvaluate(
                            p.MutationSequence, patchGen, newFaultSpecifier
                            if newFaultSpecifier != '' else None,
                            targetContractName, toolbox.evaluate)

                        if newPatch is not None:
                            newPatchCandidates.append(
                                creator.Individual(newPatch))
                        else:
                            # This indicates the population can't be further mutated
                            # Removing
                            populations.remove(p)
                            if not populations:
                                logger.info(
                                    "All individuals can't be further mutated. No plausible patch found..."
                                )
                                return []

                else:
                    logger.debug('Performing Crossover')
                    # Perform crossover
                    op = 'crossover-onepoint'
                    offspringParent = toolbox.selForCrossover(populations, 4)
                    newPatchCandidates = []
                    for p1, p2 in combinations(offspringParent, 2):
                        crosspoint1, crosspoint2 = (rng.randint(
                            -1,
                            len(p.MutationSequence) - 1) for p in (p1, p2))
                        newPatchCandidates.extend(
                            map(
                                creator.Individual, await
                                self.crossoverOnePointPatch(
                                    p1.MutationSequence, crosspoint1,
                                    p2.MutationSequence, crosspoint2,
                                    patchGen)))

                await self.evaluatePopulation(targetContractName,
                                              newPatchCandidates,
                                              toolbox.evaluate)
                populations.extend(newPatchCandidates)

        except Exception as e:

            if isinstance(e, asyncio.CancelledError):
                logger.debug('Received task cancel request')
            raise

        finally:
            logger.info('Terminating...')

            if not plausiblePatchFound:
                paretofrontStats = multistats.compile(paretofront)
                logger.info(F'ParetoFront stats: \n{paretofrontStats}')
                logger.info(F'ParetoFront: {paretofront}')
                better_than_ori_patches = [x for x in paretofront if x.fitness.dominates(original_src_path_obj.fitness)]
                stats_better_than_ori_patches = multistats.compile(better_than_ori_patches)
                combined_better_than_ori_patches = []
                for p, stat in zip(better_than_ori_patches, stats_better_than_ori_patches):
                    p_copied = deepcopy(p)
                    p_copied.stat = stat
                    combined_better_than_ori_patches.append(p_copied)
                logger.info(F'Best patches generated better than the original one: {combined_better_than_ori_patches}')
                logger.info(F'Evaluated {num_patch_tried} patches')

        # Will never reach here
        raise RuntimeError()

    @staticmethod
    def problemDectionScore(problemDetector: ProblemDetector,
                            result: ProblemDetectorResult,
                            targetedVul: Optional[Sequence[str]], targetedLoc: Optional[Sequence[CodeRange]]) -> int:
        """
        The higher the score, the better the result is. Note: the score is only used for ranking not representing as quantity
        """
        processorMap: DefaultDict[str, Callable[
            [ProblemDetectorResult, Optional[Sequence[str]], Optional[Sequence[CodeRange]]], int]] = defaultdict(
                lambda: CR.problemDectionScore_general, {})
        return processorMap[problemDetector.name](result, targetedVul, targetedLoc)

    # TODO: fix parameter types
    async def evaluatePopulation(self, targetContractName: str,
                                 population: Iterable[Any],
                                 evaluateFn: Any) -> None:

        results: Sequence[ProblemDetectorResults] = await asyncio.gather(*(
            self.detectPatch(
                p, targetContractName, p.ModifiedLocations if isinstance(
                    p.ModifiedLocations, Sequence) else None, False)
            for p in population))

        for ind, fitness, rsts in zip(
                population,
            [ await evaluateFn(p, rst)
              for p, rst in zip(population, results)], results):
            ind.fitness.values = fitness[:len(ind.fitness.weights)]
            ind.fitness.soft_values = fitness[len(ind.fitness.weights):]
            ind.vulnerability = {
                d: vuls
                for d, vuls in ((
                    d, [r for r in rs if isinstance(r, DetectedVulnerability)])
                                for d, rs in rsts.items()) if vuls
            }

        return None

    @staticmethod
    def problemDectionScore_general(result: ProblemDetectorResult,
                                    targetedVul: Optional[Sequence[str]],
                                    targetedLoc: Optional[Sequence[CodeRange]]) -> int:
        if result is False:
            return 0
        else:
            return -sum(
                1
                for vul in result if isinstance(vul, DetectedVulnerability)
                and vul.isTargeted(targetedVul, targetedLoc))

    async def fitnessFn_ProblemDection(
            self, patch: PatchInfo,
            detectionResults: Optional[ProblemDetectorResults],
            targetContractName: str,
            targetedVul: Optional[Sequence[str]], targetedLoc: Optional[Sequence[CodeRange]]) -> Tuple[int, ...]:

        if detectionResults is None:
            results = await self.detectPatch(
                patch, targetContractName, patch.ModifiedLocations if
                not (isinstance(patch.ModifiedLocations, Sequence)
                     and len(patch.ModifiedLocations) == 0) else None, False)
        else:
            results = detectionResults

        return tuple(
            self.problemDectionScore(detector, result, targetedVul, targetedLoc)
            for detector, result in zip(self.problemDectors.values(),
                                        results.values()))

    # @staticmethod
    # def fitness_GasUsageRanking() -> int:

    async def calculateFitness(
            self,
            patch: PatchInfo,
            problemDetectorResults: Optional[ProblemDetectorResults],
            targetContractName: str,
            targetedVul: Optional[Sequence[str]],
            targetedLoc: Optional[Sequence[CodeRange]],
    ) -> Tuple[int, ...]:
        result = await asyncio.gather(
            self.fitnessFn_ProblemDection(
                patch,
                targetContractName=targetContractName,
                targetedVul=targetedVul,
                targetedLoc=targetedLoc,
                **({
                    'detectionResults': problemDetectorResults
                } if problemDetectorResults is not None else {}),
            ),
            self.gasRanker.rankGas((patch.PatchedFilePath, ),
                                   targetContractName),
        )

        return (*(result[0]), len(patch.MutationSequence), *(result[1:]))

    @staticmethod
    async def mutatePatch(patch: Optional[MutationSequence],
                          patchGen: AsyncGenerator[Iterable[PatchInfo],
                                                   Optional[RequestObject]],
                          newFaultLocalizationSpecifier: Optional[str]
                          ) -> Optional[PatchInfo]:

        logger.debug(
            F'Sending fault space specifier: {newFaultLocalizationSpecifier}')

        newPatch: Optional[PatchInfo]

        requestObj = RequestObject_Mutate(
            baseMutationSequence=patch,
            overridenFaultSpaceSpecifier=newFaultLocalizationSpecifier
        ) if patch is not None else None

        try:
            newPatch = next(iter(await patchGen.asend(requestObj)))
        except (StopIteration, StopAsyncIteration):
            newPatch = None

        return newPatch

    async def mutatePatchAndEvaluate(
            self,
            patch: MutationSequence,
            patchGen: AsyncGenerator[Iterable[PatchInfo],
                                     Optional[RequestObject]],
            newFaultLocalizationSpecifier: Optional[str],
            targetContractName: str,
            evaluateFn: Any,
    ) -> Optional[Patch]:

        newPatch = await self.mutatePatch(patch, patchGen,
                                          newFaultLocalizationSpecifier)

        if isinstance(newPatch, PatchInfo):
            individual_patch = creator.Individual(newPatch)
            await self.evaluatePopulation(targetContractName,
                                          (individual_patch, ), evaluateFn)
            return individual_patch
        else:
            return None

    @staticmethod
    async def crossoverOnePointPatch(
            patch1: MutationSequence, crosspoint1: int,
            patch2: MutationSequence, crosspoint2: int,
            patchGen: AsyncGenerator[Iterable[PatchInfo], RequestObject]
    ) -> Iterable[PatchInfo]:
        return await patchGen.asend(
            RequestObject_Crossover_OnePoint(MutationSequence1=patch1,
                                             CrossPoint1=crosspoint1,
                                             MutationSequence2=patch2,
                                             CrossPoint2=crosspoint2))

    @staticmethod
    def isPatchPlausible(patch: Any, targetedVul: Optional[Sequence[str]], targetedLoc: Optional[Sequence[CodeRange]],
                         repair_target: RepairTarget) -> bool:
        return repair_target.isTargetFulfilled(patch.vulnerability,
                                               targetedVul, targetedLoc)

    @staticmethod
    def targetedVulnerabilityCount(
            patch: Any, targetedVul: Optional[Sequence[str]],
            targetedLoc: Optional[Sequence[CodeRange]],
            ):
        return sum(
            1 for vul in chain.from_iterable(patch.vulnerability.values())
            if vul.isTargeted(targetedVul, targetedLoc))
