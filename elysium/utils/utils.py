#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import copy
import time
import json
import shlex
import solcx
import subprocess

def get_all_execution_paths_accessing_storage(basic_block, depth=0, execution_paths=list(), storage_accessed=list(), visited_basic_blocks=list(), current_execution_path=list()):
    if basic_block:
        if not basic_block in visited_basic_blocks:
            visited_basic_blocks.append(basic_block)
            for instruction in basic_block.instructions:
                current_execution_path.append(instruction)
            if len(basic_block.all_outgoing_basic_blocks) == 0:
                accessed_storage = [i.pc for i in current_execution_path if i.mnemonic in ["SLOAD", "SSTORE"]]
                if any(accessed_storage) and accessed_storage not in storage_accessed:
                    execution_paths.append(copy.copy(current_execution_path))
                    storage_accessed.append(accessed_storage)
            for outgoing_basic_block in basic_block.all_outgoing_basic_blocks:
                if depth <= 7:
                    get_all_execution_paths_accessing_storage(outgoing_basic_block, depth + 1, execution_paths, storage_accessed, copy.copy(visited_basic_blocks), copy.copy(current_execution_path))
                else:
                    get_all_execution_paths_accessing_storage(outgoing_basic_block, depth + 1, execution_paths, storage_accessed, visited_basic_blocks, copy.copy(current_execution_path))
    return execution_paths

def get_all_execution_paths(basic_block, depth=0, execution_paths=list(), visited_basic_blocks=list(), current_execution_path=list()):
    if basic_block:
        if not basic_block in visited_basic_blocks:
            visited_basic_blocks.append(basic_block)
            for instruction in basic_block.instructions:
                current_execution_path.append(instruction)
            if len(basic_block.all_outgoing_basic_blocks) == 0:
                execution_paths.append(copy.copy(current_execution_path))
            for outgoing_basic_block in basic_block.all_outgoing_basic_blocks:
                if depth <= 7:
                    get_all_execution_paths(outgoing_basic_block, depth + 1, execution_paths, copy.copy(visited_basic_blocks), copy.copy(current_execution_path))
                else:
                    get_all_execution_paths(outgoing_basic_block, depth + 1, execution_paths, visited_basic_blocks, copy.copy(current_execution_path))
    return execution_paths

def get_error_handlers(basic_block, error_handlers=list(), visited_basic_blocks=list(), previous_basic_block=None):
    if basic_block:
        if not basic_block in visited_basic_blocks:
            if previous_basic_block:
                for outgoing_basic_block in basic_block.all_outgoing_basic_blocks:
                    if outgoing_basic_block != previous_basic_block:
                        if outgoing_basic_block.instructions[-1].mnemonic in ["REVERT", "ASSERTFAIL", "INVALID", "RETURN"]:
                            error_handlers.append(copy.copy(outgoing_basic_block.instructions))
            visited_basic_blocks.append(basic_block)
            for incoming_basic_block in basic_block.all_incoming_basic_blocks:
                get_error_handlers(incoming_basic_block, error_handlers, visited_basic_blocks, basic_block)
    return error_handlers

def get_push_width(address):
    push_width = len(hex(address).replace("0x", ""))
    if push_width % 2 != 0:
        push_width += 1
    return int(push_width / 2)

def get_backtrace(basic_block, backtrace, visited_basic_blocks=list(), pc=None):
    if basic_block:
        if not basic_block in visited_basic_blocks:
            visited_basic_blocks.append(basic_block)
            for instruction in reversed(basic_block.instructions):
                if pc == None or instruction.pc[1] <= pc:
                    backtrace.insert(0, instruction)
            for incoming_basic_block in basic_block.all_incoming_basic_blocks:
                get_backtrace(incoming_basic_block, backtrace, visited_basic_blocks, pc)
    return backtrace

def get_all_codecopy_instructions(basic_block, visited_basic_blocks=list(), codecopy_instructions=list()):
    if basic_block:
        if not basic_block in visited_basic_blocks:
            visited_basic_blocks.append(basic_block)
            for instruction in basic_block.instructions:
                if instruction.mnemonic == "CODECOPY":
                    codecopy_instructions.append(instruction)
            for outgoing_basic_block in basic_block.all_outgoing_basic_blocks:
                get_all_codecopy_instructions(outgoing_basic_block, visited_basic_blocks, codecopy_instructions)
    return codecopy_instructions

def get_basic_block(cfg, pc):
    basic_block = None
    for bb in cfg.basic_blocks:
        if pc >= bb.start.pc[1] and pc <= bb.end.pc[1]:
            basic_block = bb
            break
    return basic_block

def get_error_handling_sequence(basic_block, enable_error_handling_inference):
    error_handling_sequence = "PUSH1_0x0 DUP1 REVERT"
    if enable_error_handling_inference:
        error_handlers = get_error_handlers(basic_block)
        if len(error_handlers) > 0:
            error_handling_sequence = ""
            for i in range(len(error_handlers[0])):
                instruction = error_handlers[0][i]
                if not (instruction.mnemonic == "JUMPDEST" and error_handlers[0][-1].mnemonic == "REVERT"):
                    if instruction.mnemonic.startswith("PUSH"):
                        error_handling_sequence += instruction.mnemonic+"_"+hex(instruction.operand)
                    else:
                        error_handling_sequence += instruction.mnemonic
                    if i < len(error_handlers[0]) - 1:
                        error_handling_sequence += " "
    return error_handling_sequence

def get_access_control_information(backtrace, taint_analysis):
    push_storage_location = None
    push_address_mask = None
    caller = None
    sload = None
    sloads = list()
    for instruction in backtrace:
        if instruction.mnemonic.startswith("PUSH"):
            taint_analysis.introduce_taint(instruction, instruction)
        elif instruction.mnemonic == "SLOAD":
            tainted_values = taint_analysis.check_taint(instruction)
            if len(tainted_values) == 1:
                push_storage_location = tainted_values[0]
                sloads.append(instruction)
            taint_analysis.introduce_taint(instruction, instruction)
        elif instruction.mnemonic == "CALLER":
            taint_analysis.introduce_taint(instruction, instruction)
        elif instruction.mnemonic == "JUMPI":
            tainted_values = taint_analysis.check_taint(instruction)
            if len(tainted_values) > 3:
                for tainted_value in tainted_values:
                    if str(tainted_value) == "PUSH20 0xffffffffffffffffffffffffffffffffffffffff":
                        push_address_mask = tainted_value
                    elif str(tainted_value) == "SLOAD" and tainted_value in sloads:
                        sload = tainted_value
                    elif str(tainted_value) == "CALLER":
                        caller = tainted_value
        else:
            taint_analysis.propagate_taint(instruction)
    return push_storage_location, push_address_mask, caller, sload

def write_report_to_file(args, execution_start, report):
    report["execution_time"] = time.time() - execution_start
    if args.output:
        with open(args.output + ".report.json", "w") as report_file:
            json.dump(report, report_file, indent=4)
    else:
        if args.bytecode:
            filename, file_extension = os.path.splitext(args.bytecode)
            with open(filename + ".report.json", "w") as report_file:
                json.dump(report, report_file, indent=4)
        elif args.source_code:
            with open(args.source_code.replace(".sol", ".report.json"), "w") as report_file:
                json.dump(report, report_file, indent=4)
        elif args.address:
            with open(args.address + ".report.json", "w") as report_file:
                json.dump(report, report_file, indent=4)

def contains_deployment_bytecode(bytecode):
    if re.search(r"^6080604052.*396000f3006080604052", bytecode) and re.search(r"^6080604052.*396000f3fe6080604052", bytecode):
        return True
    return False

def extract_deployment_bytecode(bytecode):
    try:
        deployment_bytecode = re.search(r".*396000f300", bytecode).group()
        if len(re.compile("396000f300").findall(deployment_bytecode)) == 1:
            return deployment_bytecode
        else:
            return deployment_bytecode.split("396000f300")[0] + "396000f300"
    except:
        try:
            deployment_bytecode = re.search(r".*396000f3fe", bytecode).group()
            if len(re.compile("396000f3fe").findall(deployment_bytecode)) == 1:
                return deployment_bytecode
            else:
                return deployment_bytecode.split("396000f3fe")[0] + "396000f3fe"
        except:
            print("Error: Unknown bytecode format:", bytecode)

def extract_deployed_bytecode(bytecode):
    metadata = extract_metadata(bytecode)
    if metadata:
        try:
            return re.search(r"396000f300.*a165627a7a72305820\S{64}0029$", bytecode).group().replace("396000f300", "")
        except:
            try:
                return re.search(r"396000f3fe.*a26[4-5].*003[2-3]$", bytecode).group().replace("396000f3fe", "")
            except:
                pass
    deployment_bytecode = extract_deployment_bytecode(bytecode)
    return bytecode.replace(deployment_bytecode, "")

def extract_metadata(bytecode):
    try:
        return re.search(r"a165627a7a72305820\S{64}0029$", bytecode).group()
    except:
        try:
            return re.search(r"a26[4-5].*003[2-3]", bytecode).group()
        except:
            return ""

def replace_library_addresses(bytecode):
    library_addresses = set(re.compile(r"__\$(.+?)\$__").findall(bytecode))
    for address in library_addresses:
        bytecode = bytecode.replace("__$"+address+"$__", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    return bytecode

def remove_metadata(bytecode):
    metadata = extract_metadata(bytecode)
    if metadata:
        bytecode_without_metadata = bytes.fromhex(bytecode.split(metadata)[0])
    else:
        bytecode_without_metadata = bytes.fromhex(bytecode)
    i = 0
    previous_opcode = 0
    runtime_bytecode = ""
    while i < len(bytecode_without_metadata):
        opcode = bytecode_without_metadata[i]
        runtime_bytecode += '{0:0{1}x}'.format(opcode, 2)
        if opcode == 254 and previous_opcode != 87 and i+1 < len(bytecode_without_metadata) and bytecode_without_metadata[i+1] != 91:
            break
        if opcode >= 96 and opcode <= 127:
            size = opcode - 96 + 1
            for j in range(1, size+1):
                if i+j < len(bytecode_without_metadata):
                    runtime_bytecode += '{0:0{1}x}'.format(bytecode_without_metadata[i+j], 2)
            i += size
        previous_opcode = opcode
        i += 1
    return runtime_bytecode

def compile(source_code_file, solc_version=None):
    out = None
    with open(source_code_file, 'r') as file:
        source_code = file.read()
        try:
            if solc_version and solc_version != solcx.get_solc_version():
                solcx.set_solc_version(solc_version, True)
            out = solcx.compile_standard({
                'language': 'Solidity',
                'sources': {source_code_file: {'content': source_code}},
                'settings': {
                    "optimizer": {
                        "enabled": True,
                        "runs": 200
                    },
                    "outputSelection": {
                        source_code_file: {
                            "*":
                                [
                                    "abi",
                                    "evm.deployedBytecode",
                                    "evm.bytecode.object",
                                    "evm.legacyAssembly",
                                ],
                        }
                    },
                    'modelChecker': {
                        'engine': 'none'
                    }
                }
            }, allow_paths='.')
        except Exception as e:
            if json.loads(e.stdout_data)["errors"][0]["formattedMessage"] == 'Unknown key "modelChecker"':
                try:
                    out = solcx.compile_standard({
                        'language': 'Solidity',
                        'sources': {source_code_file: {'content': source_code}},
                        'settings': {
                            "optimizer": {
                                "enabled": True,
                                "runs": 200
                            },
                            "outputSelection": {
                                source_code_file: {
                                    "*":
                                        [
                                            "abi",
                                            "evm.deployedBytecode",
                                            "evm.bytecode.object",
                                            "evm.legacyAssembly",
                                        ],
                                }
                            }
                        }
                    }, allow_paths='.')
                except Exception as e:
                    print("Error: Solidity compilation failed!")
                    errors = json.loads(e.stdout_data)["errors"]
                    for error in errors:
                        print(error["formattedMessage"])
            else:
                print("Error: Solidity compilation failed!")
                errors = json.loads(e.stdout_data)["errors"]
                for error in errors:
                    print(error["formattedMessage"])
    return out

def get_storage_layout(source_code_file, solc_version=None):
    out = dict()
    with open(source_code_file, 'r') as file:
        source_code = file.read()
        try:
            # Starting from version 0.5.13 solc includes storageLayout
            if solc_version and solc_version != solcx.get_solc_version():
                solcx.set_solc_version(solc_version, True)
            out = solcx.compile_standard({
                'language': 'Solidity',
                'sources': {source_code_file: {'content': source_code}},
                'settings': {
                    "outputSelection": {
                        source_code_file: {
                            "*":
                                [
                                    "storageLayout"
                                ],
                        }
                    },
                    'modelChecker': {
                        'engine': 'none'
                    }
                }
            }, allow_paths='.')
        except Exception as e:
            if json.loads(e.stdout_data)["errors"][0]["formattedMessage"] == 'Unknown key "modelChecker"':
                try:
                    out = solcx.compile_standard({
                        'language': 'Solidity',
                        'sources': {source_code_file: {'content': source_code}},
                        'settings': {
                            "outputSelection": {
                                source_code_file: {
                                    "*":
                                        [
                                            "storageLayout"
                                        ],
                                }
                            }
                        }
                    }, allow_paths='.')
                except Exception as e:
                    print("Error: Solidity compilation failed!")
                    errors = json.loads(e.stdout_data)["errors"]
                    for error in errors:
                        print(error["formattedMessage"])
            else:
                print("Error: Solidity compilation failed!")
                errors = json.loads(e.stdout_data)["errors"]
                for error in errors:
                    print(error["formattedMessage"])
        # Check if source code contains inline assembly
        if "assembly" in source_code:
            storage_locations = list()
            # Search for sstore
            storage_locations += re.compile("sstore\((0x[A-Fa-f0-9]+), .+?\)").findall(source_code)
            # Search for sload
            storage_locations += re.compile("sload\((0x[A-Fa-f0-9]+)\)").findall(source_code)
            # Add storage locations to storage layout
            for contract_name in out["contracts"][source_code_file]:
                for slot in set(storage_locations):
                    out["contracts"][source_code_file][contract_name]["storageLayout"]["storage"].append({"slot": str(int(slot, 16)), "type": "t_uint256"})
                    out["contracts"][source_code_file][contract_name]["storageLayout"]["types"]
                    if out["contracts"][source_code_file][contract_name]["storageLayout"]["types"] == None:
                        out["contracts"][source_code_file][contract_name]["storageLayout"]["types"] = dict()
                    if not "t_uint256" in out["contracts"][source_code_file][contract_name]["storageLayout"]["types"]:
                        out["contracts"][source_code_file][contract_name]["storageLayout"]["types"]["t_uint256"] = {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"}
    return out["contracts"][source_code_file]

def export_cfg(cfg, filename, extension):
    f = open(filename+'.dot', 'w')
    f.write('digraph CFG {\n')
    f.write('rankdir = TB;\n')
    f.write('size = "240"\n')
    f.write('graph[fontname = Courier, fontsize = 14.0, labeljust = l, nojustify = true];node[shape = record];\n')
    address_width = 10
    for basic_block in cfg.basic_blocks:
        if len(hex(basic_block.end.pc)) > address_width:
            address_width = len(hex(basic_block.end.pc))
    for basic_block in cfg.basic_blocks:
        label = '"'+hex(basic_block.start.pc)+'"[label=<<TABLE BORDER="0" CELLBORDER="0">'
        for i in basic_block.instructions:
            if str(i).startswith("PUSH"):
                label += '<TR><TD ALIGN="LEFT"><FONT COLOR="blue">'+"{0:#0{1}x}".format(i.pc, address_width)+'</FONT></TD><TD ALIGN="LEFT">'+str(i).split(" ")[0]+' <FONT COLOR="orange">'+str(i).split(" ")[1]+'</FONT></TD></TR>'
            else:
                label += '<TR><TD ALIGN="LEFT"><FONT COLOR="blue">'+"{0:#0{1}x}".format(i.pc, address_width)+'</FONT></TD><TD ALIGN="LEFT">'+str(i)+'</TD></TR>'
        f.write(label+'</TABLE>>];\n')
        if basic_block.ends_with_jumpi():
            for outgoing_basic_block in basic_block.all_outgoing_basic_blocks:
                if outgoing_basic_block.start.pc == basic_block.end.pc + 1:
                    color = "red"
                else:
                    color = "green"
                f.write('"'+hex(basic_block.start.pc)+'" -> "'+hex(outgoing_basic_block.start.pc)+'" [label=" '+'",color="'+color+'"];\n')
        else:
            for outgoing_basic_block in basic_block.all_outgoing_basic_blocks:
                f.write('"'+hex(basic_block.start.pc)+'" -> "'+hex(outgoing_basic_block.start.pc)+'" [label=" '+'",color="black"];\n')
    f.write('}\n')
    f.close()
    if not subprocess.call('dot '+filename+'.dot -T'+extension+' -o '+filename+'.'+extension, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        print("Graphviz is not available. Please install Graphviz from https://www.graphviz.org/download/.")
    else:
        os.remove(filename+".dot")
