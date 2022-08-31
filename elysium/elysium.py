#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import math
import time
import json
import argparse

from web3 import Web3
from pyevmasm import assemble_one
from eth_utils import decode_hex, to_canonical_address

from utils.utils import *
from utils.settings import *

from modules.storage_inference import *
from modules.bytecode_rewriter import *
from modules.taint_analysis import TaintRunner
from modules.evm_cfg_builder.cfg import CFG

from detectors.osiris import run_osiris_bytecode_analyzer
from detectors.oyente import run_oyente_bytecode_analyzer
from detectors.mythril import run_mythril_bytecode_analyzer

def main():
    global args

    print(" ______     __         __  __     ______     __     __  __     __    __    ")
    print('/\  ___\   /\ \       /\ \_\ \   /\  ___\   /\ \   /\ \/\ \   /\ "-./  \   ')
    print("\ \  __\   \ \ \____  \ \____ \  \ \___  \  \ \ \  \ \ \_\ \  \ \ \-./\ \  ")
    print(" \ \_____\  \ \_____\  \/\_____\  \/\_____\  \ \_\  \ \_____\  \ \_\ \ \_\ ")
    print("  \/_____/   \/_____/   \/_____/   \/_____/   \/_/   \/_____/   \/_/  \/_/ ")
    print("                                                                           ")

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-s", "--source-code", type=str, help="Solidity source code file to be patched")
    group.add_argument(
        "-b", "--bytecode", type=str, help="File with EVM deployment bytecode to be patched")
    group.add_argument(
        "-a", "--address", type=str, help="Address of the EVM bytecode to be patched")

    parser.add_argument(
        "-c", "--contract", type=str, help="Contract name to be patched if source code provided containing multiple contracts (default: last contract definition contained in the source code file)")

    parser.add_argument(
        "-d", "--detectors", type=str, help="List of detectors to use. (default: Osiris,Oyente,Mythril)")

    parser.add_argument(
        "-r", "--bug-report", type=str, help="Bug report with all the bugs to be patched as .json file")

    parser.add_argument(
        "-o", "--output", type=str, help="File where the patched bytecode should be saved")

    parser.add_argument(
        "-i", "--inference", help="Only infer context: storage layout and integer types", action="store_true")

    parser.add_argument(
        "--enable-error-handling-inference", help="Enable error handling inference instead of default error handling based on 'REVERT'.", action="store_true")

    parser.add_argument(
        "--cfg", help="Export control-flow graph to .pdf file.", action="store_true")

    parser.add_argument(
        "-v", "--version", action="version", version="Elysium 0.0.1 - 'Elysian Fields'")
    args = parser.parse_args()

    bytecode = None
    deployment_bytecode = None
    deployed_bytecode = None

    if args.bytecode:
        with open(args.bytecode) as f:
            bytecode = f.read().strip("\n").replace("0x", "")
            if not bytecode:
                print("Error: Bytecode file is empty!")
                print("Please provide a file with valid bytecode!")
                sys.exit(-1)
            if contains_deployment_bytecode(bytecode):
                deployment_bytecode = extract_deployment_bytecode(bytecode)
                deployed_bytecode = extract_deployed_bytecode(bytecode)
            else:
                deployed_bytecode = bytecode

    contract_name = ""
    if args.source_code:
        print("Compiling source code...")
        compilation_output = compile(args.source_code)
        if not compilation_output:
            print("Error: The compilation did not produce any output!")
            print("Please check the source code!")
            sys.exit(-5)
        for contract_file in compilation_output["contracts"]:
            if args.contract:
                contract_name = args.contract
                print("Retrieving bytecode for contract", "'"+contract_name+"'.")
                bytecode = compilation_output["contracts"][contract_file][args.contract]["evm"]["bytecode"]["object"]
                bytecode = replace_library_addresses(bytecode)
                deployment_bytecode = extract_deployment_bytecode(bytecode)
                deployed_bytecode = extract_deployed_bytecode(bytecode)
            elif len(compilation_output["contracts"][contract_file]) == 1:
                for name in compilation_output["contracts"][contract_file]:
                    contract_name = name
                    print("Retrieving bytecode for contract", "'"+contract_name+"'.")
                    bytecode = compilation_output["contracts"][contract_file][contract_name]["evm"]["bytecode"]["object"]
                    bytecode = replace_library_addresses(bytecode)
                    deployment_bytecode = extract_deployment_bytecode(bytecode)
                    deployed_bytecode = extract_deployed_bytecode(bytecode)
            else:
                print("Source code file contains multiple contracts:")
                for name in compilation_output["contracts"][contract_file]:
                    print("-", name)
                print("Please select a contract using '--contract' or '-c'.")
                sys.exit(-2)

    if args.address:
        print("Retrieving bytecode from Ethereum mainnet...")
        block_number = None
        address = args.address
        if ":" in address:
            address, block_number = address.split(":")
        if block_number:
            deployed_bytecode = Web3(PROVIDER).eth.getCode(to_canonical_address(address), int(block_number)).hex().replace("0x", "")
        else:
            deployed_bytecode = Web3(PROVIDER).eth.getCode(to_canonical_address(address)).hex().replace("0x", "")
        if not deployed_bytecode:
            print("Error: Address does not contain any bytecode!")
            print("Please check that the address is a contract and that it has not been destroyed!")
            sys.exit(-6)

    if deployed_bytecode:
        metadata = extract_metadata(deployed_bytecode)
        runtime_bytecode = remove_metadata(deployed_bytecode)

    if args.inference:
        print("Recovering control-flow graph...")

        cfg_build_start = time.time()
        try:
            cfg = CFG(runtime_bytecode, symbolic_stack_analysis=False)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("Error: Control-flow graph could not be recovered!")
            print(repr(e))
            sys.exit(-7)
        cfg_build_time_original = time.time() - cfg_build_start
        dead_basic_blocks = 0
        for basic_block in cfg.basic_blocks:
            if len(basic_block.all_incoming_basic_blocks) == 0 and len(basic_block.all_outgoing_basic_blocks) == 0:
                if not (len(basic_block.instructions) == 1 and basic_block.instructions[0].mnemonic in ["STOP", "INVALID"]):
                    dead_basic_blocks += 1
        cfg_percentage_original = (len(cfg.basic_blocks) - dead_basic_blocks) / len(cfg.basic_blocks) * 100
        print("[Original] Recovered", str(cfg_percentage_original)+"%", "of the control-flow graph in", cfg_build_time_original, "second(s). [Original]")

        cfg_build_start = time.time()
        try:
            cfg = CFG(runtime_bytecode, symbolic_stack_analysis=True)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("Error: Control-flow graph could not be recovered!")
            print(repr(e))
            sys.exit(-7)
        cfg_build_time_elysium = time.time() - cfg_build_start
        dead_basic_blocks = 0
        for basic_block in cfg.basic_blocks:
            if len(basic_block.all_incoming_basic_blocks) == 0 and len(basic_block.all_outgoing_basic_blocks) == 0:
                if not (len(basic_block.instructions) == 1 and basic_block.instructions[0].mnemonic in ["STOP", "INVALID"]):
                    dead_basic_blocks += 1
        cfg_percentage_elysium = (len(cfg.basic_blocks) - dead_basic_blocks) / len(cfg.basic_blocks) * 100
        print("[Elysium] Recovered", str(cfg_percentage_elysium)+"%", "of the control-flow graph in", cfg_build_time_elysium, "second(s). [Elysium]")

        free_storage_location, used_storage_locations = get_free_storage_location(cfg)
        print("Used storage locations detected:", used_storage_locations)
        print("Free storage location detected:", free_storage_location)

        out = get_storage_layout(args.source_code)
        if out:
            storage_slots = set()
            for variable in out[contract_name]["storageLayout"]["storage"]:
                storage_slots.add(int(variable["slot"]))
            print("Used storage locations detected from storage layout:", storage_slots)
            free_storage_location_solc = 0
            if storage_slots:
                largest_storage_slot = max(storage_slots)
                largest_storage_slot_type = None
                for variable in out[contract_name]["storageLayout"]["storage"]:
                    if int(variable["slot"]) == largest_storage_slot:
                        largest_storage_slot_type = variable["type"]
                free_storage_location_solc = largest_storage_slot + math.ceil(int(out[contract_name]["storageLayout"]["types"][largest_storage_slot_type]["numberOfBytes"]) / 32)
            print("Free storage location detected from storage layout:", free_storage_location_solc)

        sys.exit(0)

    detectors = "Osiris,Oyente,Mythril"
    if args.detectors:
        detectors = args.detectors

    detected_bugs = list()
    if args.bug_report and os.path.exists(args.bug_report):
        with open(args.bug_report, "r") as f:
            detected_bugs = json.load(f)
            detected_bugs = sorted(detected_bugs, key=lambda bug: bug["pc"])
    elif args.bug_report == None and args.source_code and os.path.exists(args.source_code.replace(".sol", ".bugs.json")):
        with open(args.source_code.replace(".sol", ".bugs.json"), "r") as f:
            detected_bugs = json.load(f)
            detected_bugs = sorted(detected_bugs, key=lambda bug: bug["pc"])
    else:
        print("Please wait. Scanning bytecode for bugs...")
        for detector in detectors.split(","):
            if detector.lower() == "osiris":
                detected_bugs += run_osiris_bytecode_analyzer(runtime_bytecode)
            elif detector.lower() == "oyente":
                detected_bugs += run_oyente_bytecode_analyzer(runtime_bytecode)
            elif detector.lower() == "mythril":
                detected_bugs += run_mythril_bytecode_analyzer(runtime_bytecode)
            else:
                print("Error: Detector not supported:", detector)
                sys.exit(-4)
        detected_bugs = sorted(detected_bugs, key=lambda bug: bug["pc"])
        if args.bug_report:
            with open(args.bug_report, "w") as json_file:
                json.dump(detected_bugs, json_file, indent=4)
        else:
            if args.bytecode:
                _, file_extension = os.path.splitext(args.bytecode)
                with open(args.bytecode.replace(file_extension, ".bugs.json"), "w") as json_file:
                    json.dump(detected_bugs, json_file, indent=4)
            elif args.source_code:
                with open(args.source_code.replace(".sol", ".bugs.json"), "w") as json_file:
                    json.dump(detected_bugs, json_file, indent=4)
            elif args.address:
                with open(args.address+".bugs.json", "w") as json_file:
                    json.dump(detected_bugs, json_file, indent=4)

    report = dict()
    report["patches"] = list()

    execution_start = time.time()
    if len(detected_bugs) > 0:
        print("Detected", len(detected_bugs), "bug(s):")
        for bug in detected_bugs:
            if bug["type"] == "overflow" or bug["type"] == "underflow":
                print("--> Detected", "'"+bug["type"]+"'", "("+bug["opcode"]+")", "bug at program counter address", bug["pc"], "("+hex(bug["pc"])+")", "using", bug["tool"], "with a code coverage of", str(bug["code_coverage"])+"%.")
            else:
                print("--> Detected", "'"+bug["type"]+"'", "bug at program counter address", bug["pc"], "("+hex(bug["pc"])+")", "using", bug["tool"], "with a code coverage of", str(bug["code_coverage"])+"%.")

        # Export control-flow graph
        if args.cfg:
            print("Exporting original control-flow graph...")
            if args.bytecode:
                if deployment_bytecode:
                    export_cfg(CFG(deployment_bytecode), args.bytecode.rsplit('.', 1)[0]+".constructor.original", "pdf")
                export_cfg(CFG(runtime_bytecode), args.bytecode.rsplit('.', 1)[0]+".original", "pdf")
            elif args.source_code:
                export_cfg(CFG(deployment_bytecode), args.source_code.replace(".sol", ".constructor.original"), "pdf")
                export_cfg(CFG(runtime_bytecode), args.source_code.replace(".sol", ".original"), "pdf")
            elif args.address:
                export_cfg(CFG(runtime_bytecode), args.address+".original", "pdf")

        try:
            print("Recovering control-flow graph...")
            t = time.time()
            cfg = CFG(runtime_bytecode)
            report["control_flow_graph_recovery_time"] = time.time() - t
            dead_basic_blocks = 0
            for basic_block in cfg.basic_blocks:
                if len(basic_block.all_incoming_basic_blocks) == 0 and len(basic_block.all_outgoing_basic_blocks) == 0:
                    if not (len(basic_block.instructions) == 1 and basic_block.instructions[0].mnemonic in ["STOP", "INVALID"]):
                        dead_basic_blocks += 1
            print("Recovered", str(round((len(cfg.basic_blocks) - dead_basic_blocks) / len(cfg.basic_blocks) * 100))+"%", "of the control-flow graph")
            report["control_flow_graph_recovery"] = str(round((len(cfg.basic_blocks) - dead_basic_blocks) / len(cfg.basic_blocks) * 100))+"%"
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(repr(e))
            print("Error: Control-flow graph could not be recovered!")
            report["control_flow_graph_recovery"] = repr(e)
            write_report_to_file(args, execution_start, report)
            sys.exit(-7)

        # Create a copy of the original mappings
        for basic_block in cfg.basic_blocks:
            for instruction in basic_block.instructions:
                instruction.pc = instruction.pc, instruction.pc

        if deployment_bytecode:
            constructor_cfg = CFG(deployment_bytecode)
            for basic_block in constructor_cfg.basic_blocks:
                for instruction in basic_block.instructions:
                    instruction.pc = instruction.pc, instruction.pc
            all_codecopy_instructions = get_all_codecopy_instructions(constructor_cfg.entry_point, codecopy_instructions=list())
            if len(all_codecopy_instructions) == 0:
                print("Error: Deployment bytecode is not valid! No CODECOPY instruction found inside deployment bytecode!")
                sys.exit(-3)
            codecopy_pc = all_codecopy_instructions[-1].pc[1]
            codecopy_delete_sequence = ""
            codecopy_basic_block = get_basic_block(constructor_cfg, codecopy_pc)
            for i in range(len(codecopy_basic_block.instructions)):
                if codecopy_basic_block.instructions[i].mnemonic == "CODECOPY":
                    codecopy_delete_sequence = " ".join([str(instruction).replace(" ", "_") for instruction in codecopy_basic_block.instructions[i-4:i+1]])
                    break

        free_storage_location, _ = get_free_storage_location(cfg)

        for bug in detected_bugs:
            # TODO: Future work: Add signedness patch for multiplication
            # TODO: Future work: Combine identical patches into one basicblock and simply jump to that basic block from different locations e.g. trampoline (optimization)
            if bug["type"] == "overflow":
                # Find basic block with the bug
                buggy_basic_block = get_basic_block(cfg, bug["pc"])

                # Identify error handling strategy
                error_handling_sequence = get_error_handling_sequence(buggy_basic_block, args.enable_error_handling_inference)

                # Find integer bounds
                integer_size = None
                backtrace = get_backtrace(buggy_basic_block, list(), list(), bug["pc"])

                taint_analysis = TaintRunner()
                signextend_mappings = dict()
                unsigned = True
                for instruction in backtrace:
                    if instruction.mnemonic.startswith("PUSH"):
                        taint_analysis.introduce_taint(instruction, instruction)
                    # Unsigned
                    elif instruction.mnemonic == "AND":
                        taint_analysis.introduce_taint(instruction, instruction)
                    # Signed
                    elif instruction.mnemonic == "SIGNEXTEND":
                        tainted_values, stack_values = taint_analysis.check_taint(instruction)
                        signextend_mappings[instruction.pc[1]] = [value for value in tainted_values if isinstance(value, pyevmasm.evmasm.Instruction) and value.mnemonic.startswith("PUSH")][0]
                        signextends = [value for value in tainted_values if isinstance(value, pyevmasm.evmasm.Instruction) and value.mnemonic == "SIGNEXTEND"]
                        if len(signextends) > 0:
                            taint_analysis.introduce_taint(signextends[0], instruction)
                        else:
                            taint_analysis.introduce_taint(instruction, instruction)
                    elif instruction.pc[1] == bug["pc"]:
                        tainted_values, stack_values = taint_analysis.check_taint(instruction)
                        if any([True for value in tainted_values if isinstance(value, pyevmasm.evmasm.Instruction) and value.mnemonic == "SIGNEXTEND"]):
                            integer_sizes = [8 * (signextend_mappings[value.pc[1]].operand + 1) for value in tainted_values if isinstance(value, pyevmasm.evmasm.Instruction) and value.mnemonic == "SIGNEXTEND"]
                            if integer_sizes:
                                integer_size = max(integer_sizes)
                                unsigned = False
                        elif any([True for value in tainted_values if isinstance(value, pyevmasm.evmasm.Instruction) and value.mnemonic.startswith("PUSH")]) and any([True for value in tainted_values if isinstance(value, pyevmasm.evmasm.Instruction) and value.mnemonic == "AND"]) :
                            # Check that integer size is a valid multiple of 8
                            try:
                                if stack_values and (max(stack_values) + 1) % 8 == 0:
                                    integer_size = max(stack_values)
                                    unsigned = True
                            except:
                                pass
                    else:
                        taint_analysis.propagate_taint(instruction)

                # Generate and apply patch
                if bug["opcode"] == "ADD":
                    if unsigned:
                        integer_bounds = ""
                        if integer_size:
                            push_width = get_push_width(integer_size)
                            integer_bounds = "PUSH"+str(push_width)+"_"+hex(integer_size)
                        else:
                            integer_bounds = "PUSH"+str(get_push_width(2**256-1))+"_"+hex(2**256-1)
                        report["patches"].append({"bug_type": "integer_overflow", "pc": bug["pc"], "patch": list()})
                        with open(os.path.dirname(os.path.realpath(__file__))+"/templates/unsigned_integer_overflow_addition_patch.json", "r") as f:
                            lines = filter(None, (line.rstrip() for line in f))
                            for patch in lines:
                                patch = patch.replace("integer_bounds", integer_bounds)
                                patch = patch.replace("error_handling_sequence", error_handling_sequence)
                                patch = json.loads(patch)
                                cfg = inject_patch_at_address(cfg, patch, bug["pc"])
                                report["patches"][-1]["patch"].append(patch)
                    else:
                        integer_bounds = "PUSH"+str(get_push_width(int(integer_size / 8 - 1)))+"_"+hex(int(integer_size / 8 - 1))+" SIGNEXTEND"
                        int_max = 2 ** (integer_size - 1) - 1
                        push_int_max = "PUSH"+str(get_push_width(int_max))+"_"+hex(int_max)
                        push_int_min = push_int_max+" NOT"
                        report["patches"].append({"bug_type": "integer_overflow", "pc": bug["pc"], "patch": list()})
                        with open(os.path.dirname(os.path.realpath(__file__))+"/templates/unsigned_integer_overflow_addition_patch.json", "r") as f:
                            lines = filter(None, (line.rstrip() for line in f))
                            for patch in lines:
                                patch = patch.replace("integer_bounds", integer_bounds)
                                patch = patch.replace("error_handling_sequence", error_handling_sequence)
                                patch = patch.replace("push_int_max", push_int_max)
                                patch = patch.replace("push_int_min", push_int_min)
                                patch = json.loads(patch)
                                cfg = inject_patch_at_address(cfg, patch, bug["pc"])
                                report["patches"][-1]["patch"].append(patch)

                elif bug["opcode"] == "MUL":
                    if unsigned:
                        if integer_size:
                            push_width = get_push_width(integer_size)
                            integer_bounds = "PUSH"+str(push_width)+"_"+hex(integer_size)
                            report["patches"].append({"bug_type": "integer_overflow", "pc": bug["pc"], "patch": list()})
                            with open(os.path.dirname(os.path.realpath(__file__))+"/templates/unsigned_integer_overflow_multiplication_patch.json", "r") as f:
                                lines = filter(None, (line.rstrip() for line in f))
                                for patch in lines:
                                    patch = patch.replace("integer_bounds", integer_bounds)
                                    patch = patch.replace("error_handling_sequence", error_handling_sequence)
                                    patch = json.loads(patch)
                                    cfg = inject_patch_at_address(cfg, patch, bug["pc"])
                                    report["patches"][-1]["patch"].append(patch)
                        else:
                            report["patches"].append({"bug_type": "integer_overflow", "pc": bug["pc"], "patch": list()})
                            with open(os.path.dirname(os.path.realpath(__file__))+"/templates/unsigned_integer_overflow_multiplication_256_bit_patch.json", "r") as f:
                                lines = filter(None, (line.rstrip() for line in f))
                                for patch in lines:
                                    patch = patch.replace("error_handling_sequence", error_handling_sequence)
                                    patch = json.loads(patch)
                                    cfg = inject_patch_at_address(cfg, patch, bug["pc"])
                                    report["patches"][-1]["patch"].append(patch)
                    else:
                        # TODO: Future work: Add patch for signed multiplication
                        print("Error: Patch for signed multiplcation is missing!")

            elif bug["type"] == "underflow":
                # Find basic block with the bug
                buggy_basic_block = get_basic_block(cfg, bug["pc"])

                # Identify error handling strategy
                error_handling_sequence = get_error_handling_sequence(buggy_basic_block, args.enable_error_handling_inference)

                # Generate and apply patch
                report["patches"].append({"bug_type": "integer_undeflow", "pc": bug["pc"], "patch": list()})
                with open(os.path.dirname(os.path.realpath(__file__))+"/templates/integer_underflow_patch.json", "r") as f:
                    lines = filter(None, (line.rstrip() for line in f))
                    for patch in lines:
                        patch = patch.replace("error_handling_sequence", error_handling_sequence)
                        patch = json.loads(patch)
                        cfg = inject_patch_at_address(cfg, patch, bug["pc"])
                        report["patches"][-1]["patch"].append(patch)

            elif bug["type"] == "reentrancy":
                # Find basic block with the bug
                buggy_basic_block = get_basic_block(cfg, bug["pc"])

                # Find free storage location
                storage_location_sequence, free_storage_location = get_free_storage_location_sequence(free_storage_location)

                # Identify error handling strategy
                error_handling_sequence = get_error_handling_sequence(buggy_basic_block, args.enable_error_handling_inference)

                # Identify reentrancy origin function and function storage write locations
                reentrany_origin_function = None
                function_storage_write_locations = dict()
                for function in cfg.functions:
                    if not function.name in ["_fallback", "_dispatcher"]:
                        entry_point = None
                        for basic_block in function.basic_blocks:
                            if len(basic_block.incoming_basic_blocks(function.key)) == 0:
                                entry_point = basic_block
                            for instruction in basic_block.instructions:
                                if instruction.pc[1] == bug["pc"]:
                                    reentrany_origin_function = function.name
                        function_storage_write_locations[function.name] = list()
                        if entry_point:
                            all_execution_paths = get_all_execution_paths(entry_point, execution_paths=list(), current_execution_path=list())
                            for execution_path in all_execution_paths:
                                taint_analysis = TaintRunner()
                                for instruction in execution_path:
                                    if instruction.mnemonic.startswith("PUSH"):
                                        taint_analysis.introduce_taint(instruction, instruction)
                                    elif instruction.mnemonic == "SSTORE":
                                        storage_location = None
                                        tainted_values, _ = taint_analysis.check_taint(instruction)
                                        for tainted_value in tainted_values:
                                            if isinstance(tainted_value, pyevmasm.evmasm.Instruction) and tainted_value.pc[1] != 0:
                                                if not storage_location or tainted_value.operand < storage_location[0].operand:
                                                    storage_location = tainted_value, instruction
                                        if storage_location and not storage_location in function_storage_write_locations[function.name]:
                                            function_storage_write_locations[function.name].append(storage_location)
                                    else:
                                        taint_analysis.propagate_taint(instruction)

                patches_to_be_applied = dict()

                # Generate patches for cross function reentrany locations
                cross_function_reentrancy_locations = dict()
                if reentrany_origin_function:
                    reentrany_origin_function_storage_locations = [storage_location[0].operand for storage_location in function_storage_write_locations[reentrany_origin_function]]
                    for function in function_storage_write_locations:
                        if function != reentrany_origin_function:
                            for storage_location in function_storage_write_locations[function]:
                                if storage_location[0].operand in reentrany_origin_function_storage_locations:
                                    address = storage_location[1].pc[1]
                                    if not function in cross_function_reentrancy_locations:
                                        cross_function_reentrancy_locations[function] = list()
                                    cross_function_reentrancy_locations[function].append(address)

                for function in cross_function_reentrancy_locations:
                    max_pc = max(cross_function_reentrancy_locations[function])
                    min_pc = min(cross_function_reentrancy_locations[function])
                    with open(os.path.dirname(os.path.realpath(__file__))+"/templates/reentrancy_patch.json", "r") as f:
                        lines = filter(None, (line.rstrip() for line in f))
                        for patch in lines:
                            patch = patch.replace("free_storage_location", storage_location_sequence)
                            patch = patch.replace("error_handling_sequence", error_handling_sequence)
                            patch = json.loads(patch)
                            if patch["insert_mode"] == "after":
                                address = max_pc
                            else:
                                address = min_pc
                            if not address in patches_to_be_applied:
                                patches_to_be_applied[address] = list()
                            if not patch in patches_to_be_applied[address]:
                                patches_to_be_applied[address].append(patch)

                # Generate patch for reentrany origin
                with open(os.path.dirname(os.path.realpath(__file__))+"/templates/reentrancy_patch.json", "r") as f:
                    lines = filter(None, (line.rstrip() for line in f))
                    for patch in lines:
                        patch = patch.replace("free_storage_location", storage_location_sequence)
                        patch = patch.replace("error_handling_sequence", error_handling_sequence)
                        patch = json.loads(patch)
                        if not bug["pc"] in patches_to_be_applied:
                            patches_to_be_applied[bug["pc"]] = list()
                        patches_to_be_applied[bug["pc"]].append(patch)

                # Apply generated patches
                for address in sorted(patches_to_be_applied.keys()):
                    report["patches"].append({"bug_type": "reentrancy", "pc": address, "patch": list()})
                    for patch in patches_to_be_applied[address]:
                        cfg = inject_patch_at_address(cfg, patch, address)
                        report["patches"][-1]["patch"].append(patch)

            elif bug["type"] == "unhandled exception":
                # Find basic block with the bug
                buggy_basic_block = get_basic_block(cfg, bug["pc"])

                # Identify error handling strategy
                error_handling_sequence = get_error_handling_sequence(buggy_basic_block, args.enable_error_handling_inference)

                # Generate and apply patch
                report["patches"].append({"bug_type": "unhandled_exception", "pc": bug["pc"], "patch": list()})
                with open(os.path.dirname(os.path.realpath(__file__))+"/templates/unhandled_exception_patch.json", "r") as f:
                    lines = filter(None, (line.rstrip() for line in f))
                    for patch in lines:
                        patch = patch.replace("error_handling_sequence", error_handling_sequence)
                        patch = json.loads(patch)
                        cfg = inject_patch_at_address(cfg, patch, bug["pc"])
                        report["patches"][-1]["patch"].append(patch)

            # TODO: Future work: Implement case 2
            elif bug["type"] == "leaking ether" or bug["type"] == "suicidal" or bug["type"] == "unsafe delegatecall":
                # Possible cases:
                # 1. Access control check is completely missing.
                # 2. Access control check is defined and used somewhere, but not in this function.
                # 3. Access control check is defined and used for this function, but access can be set by everyone.

                # Find basic block with the bug
                buggy_basic_block = get_basic_block(cfg, bug["pc"])

                # Identify error handling strategy
                error_handling_sequence = get_error_handling_sequence(buggy_basic_block, args.enable_error_handling_inference)

                # Find free storage location
                storage_location_sequence, free_storage_location = get_free_storage_location_sequence(free_storage_location)

                # Check if buggy function contains an access control check
                backtrace = get_backtrace(buggy_basic_block, list(), list(), bug["pc"])
                push_storage_location, push_address_mask, caller, sload = get_access_control_information(backtrace, TaintRunner())
                # If buggy function contains an access control check, then search for locations that are unprotected and access can be granted
                if push_storage_location and push_address_mask and caller and sload:
                    all_execution_paths = get_all_execution_paths(cfg.entry_point, execution_paths=list(), current_execution_path=list())
                    unprotected_writes_to_storage = list()
                    for execution_path in all_execution_paths:
                        taint_analysis = TaintRunner()
                        for instruction in execution_path:
                            if instruction.mnemonic.startswith("PUSH"):
                                taint_analysis.introduce_taint(instruction, instruction)
                            elif instruction.mnemonic == "SSTORE":
                                tainted_values, _ = taint_analysis.check_taint(instruction)
                                storage_location = min([tainted_value.operand for tainted_value in tainted_values])
                                if storage_location == push_storage_location.operand:
                                    access_control_information = get_access_control_information(get_backtrace(get_basic_block(cfg, instruction.pc[1]), list(), list(), instruction.pc[1]), TaintRunner())
                                    if not (access_control_information[0] and access_control_information[1] and access_control_information[2] and access_control_information[3]):
                                        unprotected_writes_to_storage.append(instruction.pc[1])
                            else:
                                taint_analysis.propagate_taint(instruction)
                    # Generate and apply patch
                    if len(unprotected_writes_to_storage) > 0:
                        if deployment_bytecode:
                            report["patches"].append({"bug_type": bug["type"].replace(" ", "_"), "pc": codecopy_pc, "patch": list()})
                            with open(os.path.dirname(os.path.realpath(__file__))+"/templates/access_control_patch.json", "r") as f:
                                lines = filter(None, (line.rstrip() for line in f))
                                for patch in lines:
                                    patch = patch.replace("free_storage_location", storage_location_sequence)
                                    patch = json.loads(patch)
                                    if patch["constructor"] == True:
                                        constructor_cfg = inject_patch_at_address(constructor_cfg, patch, codecopy_pc)
                                        report["patches"][-1]["patch"].append(patch)
                    for pc in unprotected_writes_to_storage:
                        report["patches"].append({"bug_type": bug["type"].replace(" ", "_"), "pc": pc, "patch": list()})
                        with open(os.path.dirname(os.path.realpath(__file__))+"/templates/access_control_patch.json", "r") as f:
                            lines = filter(None, (line.rstrip() for line in f))
                            for patch in lines:
                                patch = patch.replace("free_storage_location", storage_location_sequence)
                                patch = patch.replace("error_handling_sequence", error_handling_sequence)
                                patch = json.loads(patch)
                                if patch["constructor"] == False:
                                    cfg = inject_patch_at_address(cfg, patch, pc)
                                    report["patches"][-1]["patch"].append(patch)
                else:
                    # Generate and apply patch
                    if deployment_bytecode:
                        report["patches"].append({"bug_type": bug["type"].replace(" ", "_"), "pc": codecopy_pc, "patch": list()})
                        with open(os.path.dirname(os.path.realpath(__file__))+"/templates/access_control_patch.json", "r") as f:
                            lines = filter(None, (line.rstrip() for line in f))
                            for patch in lines:
                                patch = patch.replace("free_storage_location", storage_location_sequence)
                                patch = json.loads(patch)
                                if patch["constructor"] == True:
                                    constructor_cfg = inject_patch_at_address(constructor_cfg, patch, codecopy_pc)
                                    report["patches"][-1]["patch"].append(patch)
                    report["patches"].append({"bug_type": bug["type"].replace(" ", "_"), "pc": bug["pc"], "patch": list()})
                    with open(os.path.dirname(os.path.realpath(__file__))+"/templates/access_control_patch.json", "r") as f:
                        lines = filter(None, (line.rstrip() for line in f))
                        for patch in lines:
                            patch = patch.replace("free_storage_location", storage_location_sequence)
                            patch = patch.replace("error_handling_sequence", error_handling_sequence)
                            patch = json.loads(patch)
                            if patch["constructor"] == False:
                                cfg = inject_patch_at_address(cfg, patch, bug["pc"])
                                report["patches"][-1]["patch"].append(patch)

            elif bug["type"] == "transaction origin":
                report["patches"].append({"bug_type": "transaction_origin", "pc": bug["pc"], "patch": list()})
                with open(os.path.dirname(os.path.realpath(__file__))+"/templates/transaction_origin_patch.json", "r") as f:
                    lines = filter(None, (line.rstrip() for line in f))
                    for patch in lines:
                        patch = json.loads(patch)
                        cfg = inject_patch_at_address(cfg, patch, bug["pc"])
                        report["patches"][-1]["patch"].append(patch)

            else:
                print("Bug type '"+bug["type"]+"' is not supported!")

        # Recompute jump locations
        jump_destinations = dict()
        conflicting_jumps = list()
        for basic_block in sorted(cfg.basic_blocks, key=lambda x: x.start.pc, reverse=False):
            for i in range(len(basic_block.instructions)):
                if basic_block.instructions[i].mnemonic == "JUMPDEST":
                    if isinstance(basic_block.instructions[i].pc, tuple):
                        if basic_block.instructions[i].pc[1] != 0:
                            if hex(basic_block.instructions[i].pc[1]) in jump_destinations:
                                conflicting_jumps.append(hex(basic_block.instructions[i].pc[1]))
                            jump_destinations[hex(basic_block.instructions[i].pc[1])] = hex(basic_block.instructions[i].pc[0])
                        else:
                            if hex(basic_block.instructions[i].pc[0]) in jump_destinations:
                                conflicting_jumps.append(hex(basic_block.instructions[i].pc[0]))
                            jump_destinations[hex(basic_block.instructions[i].pc[0])] = hex(basic_block.instructions[i].pc[0])
        if jump_destinations:
            for basic_block in sorted(cfg.basic_blocks, key=lambda x: x.start.pc, reverse=False):
                for i in range(len(basic_block.instructions)):
                    if basic_block._instructions[i].mnemonic.startswith("PUSH"):
                        if hex(basic_block._instructions[i].operand) in jump_destinations:
                            original_push_width = basic_block._instructions[i].operand_size
                            push_width = get_push_width(int(jump_destinations[hex(basic_block._instructions[i].operand)], 16))
                            if original_push_width < push_width:
                                for destination in sorted(jump_destinations):
                                    if int(jump_destinations[destination], 16) > basic_block._instructions[i].pc[0]:
                                        jump_destinations[destination] = hex(int(jump_destinations[destination], 16) + push_width - original_push_width)
            for basic_block in cfg.basic_blocks:
                for i in range(len(basic_block.instructions)):
                    if basic_block._instructions[i].mnemonic.startswith("PUSH"):
                        if hex(basic_block._instructions[i].operand) in jump_destinations and hex(basic_block._instructions[i].operand) != jump_destinations[hex(basic_block._instructions[i].operand)]:
                            if hex(basic_block._instructions[i].operand) in conflicting_jumps and basic_block._instructions[i].pc[1] == 0:
                                continue
                            push_width = get_push_width(int(jump_destinations[hex(basic_block._instructions[i].operand)], 16))
                            original_push_width = basic_block._instructions[i].operand_size
                            original_pc = basic_block._instructions[i].pc
                            if original_push_width > push_width:
                                push_width = original_push_width
                            basic_block._instructions[i] = assemble_one("PUSH" + str(push_width) + " " + jump_destinations[hex(basic_block._instructions[i].operand)])
                            basic_block._instructions[i].pc = original_pc

        # Remove copy of the original mapping
        for basic_block in cfg.basic_blocks:
            for instruction in basic_block.instructions:
                instruction.pc = instruction.pc[0]

        # Align basic blocks to runtime bytecode
        patched_runtime_bytecode = ""
        sorted_basic_blocks = sorted(cfg.basic_blocks, key=lambda x: x.start.pc, reverse=False)
        for basic_block in sorted_basic_blocks:
            for instruction in basic_block.instructions:
                patched_runtime_bytecode += instruction.bytes.hex()

        if deployment_bytecode:
            # Align basic blocks to deployment bytecode
            patched_deployment_bytecode = ""
            sorted_basic_blocks = sorted(constructor_cfg.basic_blocks, key=lambda x: x.start.pc, reverse=False)
            for basic_block in sorted_basic_blocks:
                for instruction in basic_block.instructions:
                    patched_deployment_bytecode += instruction.bytes.hex()

            # Recompute codecopy location in constructor
            codecopy_insert_sequence = ""
            push_width = len(hex(int(len(patched_runtime_bytecode + metadata) / 2)).replace("0x", ""))
            if push_width % 2 != 0:
                push_width += 1
            push_width = int(push_width / 2)
            codecopy_insert_sequence += "PUSH" + str(push_width) + "_" + hex(int(len(patched_runtime_bytecode + metadata) / 2))
            codecopy_insert_sequence += " DUP1 "
            push_width = len(hex(int(len(patched_deployment_bytecode) / 2)).replace("0x", ""))
            if push_width % 2 != 0:
                push_width += 1
            push_width = int(push_width / 2)
            codecopy_insert_sequence += "PUSH" + str(push_width) + "_" + hex(int(len(patched_deployment_bytecode) / 2))
            codecopy_insert_sequence += " PUSH1_0x0 CODECOPY"
            print("Deployment bytecode size:", int(len(patched_deployment_bytecode) / 2), "bytes (original: "+str(int(len(deployment_bytecode) / 2))+" bytes)", str((float(len(patched_deployment_bytecode) / 2) - float(len(deployment_bytecode) / 2)) / (float(len(deployment_bytecode) / 2) / 100))+"% increase.")
            report["original_deployment_size"] = str(int(len(deployment_bytecode) / 2))+" bytes"
            report["patched_deployment_size"] = str(int(len(patched_deployment_bytecode) / 2))+" bytes"
            constructor_cfg = inject_patch_at_address(constructor_cfg, {"delete": codecopy_delete_sequence, "insert": codecopy_insert_sequence, "insert_mode": "before", "constructor": True}, codecopy_pc)

            # Remove copy of the original mapping
            for basic_block in constructor_cfg.basic_blocks:
                for instruction in basic_block.instructions:
                    instruction.pc = instruction.pc[0]

            # Align basic blocks to bytecode
            patched_deployment_bytecode = ""
            sorted_basic_blocks = sorted(constructor_cfg.basic_blocks, key=lambda x: x.start.pc, reverse=False)
            for basic_block in sorted_basic_blocks:
                for instruction in basic_block.instructions:
                    patched_deployment_bytecode += instruction.bytes.hex()

        print("Runtime bytecode size:", int(len(patched_runtime_bytecode) / 2), "bytes (original: "+str(int(len(runtime_bytecode) / 2))+" bytes)", str((float(len(patched_runtime_bytecode) / 2) - float(len(runtime_bytecode) / 2)) / (float(len(runtime_bytecode) / 2) / 100))+"% increase.")
        report["original_runtime_size"] = str(int(len(runtime_bytecode) / 2))+" bytes"
        report["patched_runtime_size"] = str(int(len(patched_runtime_bytecode) / 2))+" bytes"

        if metadata:
            print("Metadata:", "0x"+metadata)

        # Assemble patched deployment bytecode, patched runtime bytecode, and metadata
        if deployment_bytecode:
            patched_bytecode = patched_deployment_bytecode + patched_runtime_bytecode + metadata
        else:
            patched_bytecode = patched_runtime_bytecode + metadata

        # Write patched bytecode to file
        if args.output:
            with open(args.output, "w") as file:
                file.write(patched_bytecode)
        else:
            if args.bytecode:
                filename, file_extension = os.path.splitext(args.bytecode)
                with open(filename + ".patched" + file_extension, "w") as file:
                    file.write(patched_bytecode)
            elif args.source_code:
                with open(args.source_code.replace(".sol", ".patched.bin"), "w") as file:
                    file.write(patched_bytecode)
            elif args.address:
                with open(args.address + ".patched.bin", "w") as file:
                    file.write(patched_bytecode)

        # Export control-flow graph
        if args.cfg:
            print("Exporting patched control-flow graph...")
            if args.bytecode:
                if deployment_bytecode:
                    export_cfg(CFG(patched_deployment_bytecode), args.bytecode.rsplit('.', 1)[0]+".constructor.patched", "pdf")
                export_cfg(CFG(patched_runtime_bytecode), args.bytecode.rsplit('.', 1)[0]+".patched", "pdf")
            elif args.source_code:
                export_cfg(CFG(patched_deployment_bytecode), args.source_code.replace(".sol", ".constructor.patched"), "pdf")
                export_cfg(CFG(patched_runtime_bytecode), args.source_code.replace(".sol", ".patched"), "pdf")
            elif args.address:
                export_cfg(CFG(patched_runtime_bytecode), args.address+".patched", "pdf")

    else:
        print("No bugs detected! There is nothing to be patched!")

        # Write bytecode to file
        if args.output:
            with open(args.output, "w") as file:
                file.write(deployed_bytecode)
        else:
            if args.bytecode:
                filename, file_extension = os.path.splitext(args.bytecode)
                with open(filename + ".patched" + file_extension, "w") as file:
                    file.write(deployed_bytecode)
            elif args.source_code:
                with open(args.source_code.replace(".sol", ".patched.bin"), "w") as file:
                    file.write(deployed_bytecode)
            elif args.address:
                with open(args.address + ".patched.bin", "w") as file:
                    file.write(deployed_bytecode)

    # Write report to file
    write_report_to_file(args, execution_start, report)

if __name__ == '__main__':
    main()
