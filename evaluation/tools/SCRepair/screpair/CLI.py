"""
@author: Xiao Liang Yu
"""
from .IN import ProblemDetector, RepairCore, DetectedVulnerability, RepairTarget_Detector_Target, RepairTarget_Detector_Target_Remaining, RepairTarget_Detector_Target_Repaired, RepairTarget
import argparse
import inspect
import sys
from pathlib import Path
from typing import Optional, Tuple, Type, cast, Dict, Any, Sequence
from logbook import Logger, StderrHandler
import logbook
from .StoreKeyValuePairAction import StoreKeyValuePairAction
import asyncio
import re
import math
import time
import datetime
import json
from contextlib import suppress
from json import JSONEncoder
import attr
from .Utils import CodeRange
from .CR import CR
from .ETC import ETC

logger = Logger('CLI')

class JSONEncoder_custom(JSONEncoder):

    def default(self, o):
        return o if not attr.has(o) else attr.asdict(o)

def main() -> None:

    parser = argparse.ArgumentParser(
        description='')

    parser.add_argument('--targetContractName',
                        type=str,
                        required=True,
                        )
    parser.add_argument('--timeout',
                        type=float,
                        required=False,
                        default=math.inf,
                        )
    parser.add_argument('--json',
                        required=False,
                        default=False,
                        action='store_true',
                        )

    arg_group_detector = parser.add_argument_group('Problem Detection')
    arg_group_detector.add_argument('--detectorArg',
                                    type=str,
                                    required=False,
                                    nargs=1,
                                    action=StoreKeyValuePairAction,
                                    metavar='KEY=VALUE',
                                    )
    arg_group_detector.add_argument(
        '--targetVul',
        type=str,
        required=False,
        action='append',
        metavar='vulnerability')
    arg_group_detector.add_argument(
        '--targetLoc',
        type=lambda x: CodeRange(**json.loads(x)),
        required=False,
        action='append',
        metavar='CodeRange object in JSON format',
    )

    arg_group_detector = parser.add_argument_group('Patch Synthesis')
    arg_group_detector.add_argument('--synthesizerArg',
                                    type=str,
                                    nargs=1,
                                    action=StoreKeyValuePairAction,
                                    metavar='KEY=VALUE',
                                    )

    arg_group_repairCore = parser.add_argument_group('Repair Core')
    arg_group_repairCore.add_argument('--core',
                                      type=str,
                                      )
    arg_group_repairCore.add_argument('--coreArg',
                                      type=str,
                                      nargs=1,
                                      action=StoreKeyValuePairAction,
                                      required=False,
                                      metavar='KEY=VALUE',
                                      )

    subparsers = parser.add_subparsers(dest='subcommand')


    subparser_repair = subparsers.add_parser('repair')
    subparser_repair.set_defaults(func=repair)

    subparser_repair.add_argument(
        '--repair_target',
        action=StoreKeyValuePairAction,
        type=str,
        nargs=1,
        metavar=
        'DETECTOR=REMAINING:TARGET_VALUE or DETECTOR=REPAIRED:TARGET_VALUE',
        required=False)

    parser.add_argument('source_file',
                        nargs=1,
                        type=lambda x: Path(x).expanduser().resolve())

    args = parser.parse_args()

    parsed: Dict[str, Any] = {}

    loop = asyncio.get_event_loop()

    try:
        task = loop.create_task(args.func(args, parsed))
        waitTask = asyncio.wait_for(task, args.timeout)
        loop.run_until_complete(waitTask)
    except asyncio.TimeoutError:
        logger.info(F'Timeout {args.timeout=} seconds exceeded')
    finally:

        task.cancel()
        with suppress(asyncio.CancelledError):
            loop.run_until_complete(task)  # To process the cancel request

        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()

async def repair(args, parsed: dict):

    logger.debug('Start repairing problems')

    original_src = args.source_file
    targetContractName = args.targetContractName
    targetVul = args.targetVul
    targetLoc = args.targetLoc

    repairCore = CR((), (),
                                            args.detectorArg,
                                            args.synthesizerArg, args.coreArg)

    # TODO: pass num plausible from CLI
    rst = await repairCore.repair(original_src, targetContractName, targetVul, targetLoc,
                                  1, RepairTarget(), None)

    if not rst:
        print("Unable to find a plausible patch...")
    else:
        print("Source files after applying plausible patches are in:")
        for p in rst:
            print(p.PathPatchedCode)



from logbook import Logger, StderrHandler
import logbook
import os

logHandler = StderrHandler(level=os.environ.get('LOG_LEVEL', logbook.get_level_name(logbook.INFO)) )
with logHandler.applicationbound():
    main()
