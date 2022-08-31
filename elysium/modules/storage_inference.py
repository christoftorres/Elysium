#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import pyevmasm

from .taint_analysis import TaintRunner
sys.path.insert(0, '..')

from utils.utils import *

def get_free_storage_location(cfg):
    all_execution_paths = get_all_execution_paths_accessing_storage(cfg.entry_point, execution_paths=list(), storage_accessed=list(), visited_basic_blocks=list(), current_execution_path=list())
    print("Number of execution paths accessing storage:", len(all_execution_paths))
    used_storage_locations = set()
    for execution_path in all_execution_paths:
        if any([True for ins in execution_path if ins.mnemonic in ["SLOAD", "SSTORE"]]):
            taint_analysis = TaintRunner(debug=False)
            instruction_sequence = ""
            for instruction in execution_path:
                instruction_sequence += str(instruction) + " "
                if instruction.mnemonic.startswith("PUSH"):
                    taint_analysis.introduce_taint(instruction, instruction)
                elif instruction.mnemonic in ["SLOAD", "SSTORE"]:
                    tainted_values, stack_values = taint_analysis.check_taint(instruction)
                    if tainted_values and len([True for t in tainted_values if not isinstance(t, pyevmasm.evmasm.Instruction)]) == 0:
                        fixed_array_size = list()
                        fixed_array_size += re.compile("PUSH[0-9]+ (0x[A-Fa-f0-9]+) DUP[0-9]+ LT PUSH[0-9]+ 0x[A-Fa-f0-9]+ JUMPI JUMPDEST ADD .*?[SLOAD|SSTORE]").findall(instruction_sequence)
                        fixed_array_size += re.compile("PUSH[0-9]+ (0x[A-Fa-f0-9]+) DUP[0-9]+ LT ISZERO PUSH[0-9]+ 0x[A-Fa-f0-9]+ JUMPI ADD PUSH[0-9]+ 0x[A-Fa-f0-9]+ JUMPDEST POP .*?[SLOAD|SSTORE]").findall(instruction_sequence)
                        storage_slot = None
                        try:
                            if len(stack_values) == 1:
                                if len([t.operand for t in tainted_values if isinstance(t, pyevmasm.evmasm.Instruction)]) > 0:
                                    storage_slot = max([t.operand for t in tainted_values if isinstance(t, pyevmasm.evmasm.Instruction)])
                            else:
                                if not None in stack_values:
                                    storage_slot = min([s for s in stack_values])
                                else:
                                    for s in stack_values:
                                        if s != None and s in used_storage_locations and s != 0:
                                            used_storage_locations.remove(s)
                            if storage_slot != None and (len(used_storage_locations) == 0 or abs(max(list(used_storage_locations)) - storage_slot) <= 32):
                                used_storage_locations.add(storage_slot)
                                if fixed_array_size:
                                    fixed_array_size = int(fixed_array_size[0], 16)
                                    used_storage_locations.add(storage_slot + fixed_array_size - 1)
                        except:
                            pass
                    instruction_sequence = ""
                else:
                    taint_analysis.propagate_taint(instruction)
    if not 0 in used_storage_locations:
        used_storage_locations = set()
    if len(used_storage_locations) > 0:
        free_storage_location = max(used_storage_locations) + 1
    else:
        free_storage_location = 0
    return free_storage_location, used_storage_locations

def get_free_storage_location_sequence(free_storage_location):
    push_width = get_push_width(free_storage_location)
    storage_location_sequence = "PUSH"+str(push_width)+"_"+hex(free_storage_location)
    free_storage_location += 1
    return storage_location_sequence, free_storage_location
