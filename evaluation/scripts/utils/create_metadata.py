#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import docker

def run_osiris(bytecode, debug=False):
    bugs = list()
    client = docker.from_env()
    container = client.containers.run('christoftorres/osiris', "/bin/bash -c \"echo '"+bytecode+"' > bytecode.evm; python osiris/osiris.py -s bytecode.evm -glt 1800 -b --debug\"", detach=True, remove=True)
    code_coverage, end_of_execution = 0.0, False
    previous_line = ""
    for line in container.logs(stream=True):
        if debug:
            print(line.strip().decode("utf-8"))
        if line.strip().decode("utf-8").startswith("INFO:symExec:	  EVM code coverage:"):
            code_coverage = float(line.strip().decode("utf-8").replace("INFO:symExec:	  EVM code coverage: 	 ", "").replace("%", ""))
        if line.strip().decode("utf-8").startswith("Number of arithmetic errors"):
            end_of_execution = True
        if end_of_execution:
            current_line = line.strip().decode("utf-8")
            if previous_line.startswith("{'") and current_line.startswith('{"'):
                result = json.loads(previous_line.replace("'", '"').replace('<', '"<').replace('>', '>"').lower())
                if result["type"] == "overflow" or result["type"] == "underflow":
                    bug = dict()
                    bug["offset"] = result["pc"]
                    bug["category"] = json.loads(current_line.replace("'", '"').replace('<', '"<').replace('>', '>"').lower())["opcode"].lower()
                    if not bug in bugs:
                        bugs.append(bug)
            previous_line = current_line
        if line.strip().decode("utf-8").startswith("INFO:symExec:	  Reentrancy bug:"):
            bug = dict()
            if line.strip().decode("utf-8").replace("INFO:symExec:	  Reentrancy bug:", "").replace(" 	 ", "") == "True":
                bug["Reentrancy"] = True
            else:
                bug["Reentrancy"] = False
            if not bug in bugs:
                bugs.append(bug)
    return bugs

def run_mythril(bytecode, metadata, ignore_bugs=[], debug=False):
    client = docker.from_env()
    print("Creating metadata...")
    cmd = '-v 5 analyze -m ArbitraryStorage,ArbitraryDelegateCall,TxOrigin,EtherThief,IntegerArithmetics,StateChangeAfterCall,AccidentallyKillable,UncheckedRetval --bin-runtime -c '+bytecode+' --parallel-solving -o json'
    if debug:
        print(cmd)
    container = client.containers.run('christoftorres/mythril', cmd, detach=True, remove=False)
    for line in container.logs(stream=True):
        if debug:
            print(line)
    output = container.logs()
    output = output.decode("utf-8")
    output = output.split('\n')
    code_coverage = 0.0
    for line in output:
        if debug:
            print(line)
        if line.startswith("mythril.laser.plugin.plugins.coverage.coverage_plugin [INFO]: Achieved"):
            code_coverage = float(line.replace("mythril.laser.plugin.plugins.coverage.coverage_plugin [INFO]: Achieved ", "").split("%")[0])
        if line.startswith('{"'):
            result = json.loads(line)
            if result["error"] == None and result["success"] == True:
                for issue in result["issues"]:
                    if not issue["swc-id"] in ignore_bugs:
                        try:
                            if issue["swc-id"] == "107":
                                reentrancy = dict()
                                reentrancy["callOffset"] = issue["address"][0]
                                reentrancy["sStoreOffset"] = issue["address"][1]
                                metadata["Reentrancy"].append(reentrancy)
                            elif issue["swc-id"] == "101":
                                integer_bug = dict()
                                integer_bug["offset"] = issue["address"]
                                integer_bug["category"] = issue["title"].replace("Integer Arithmetic Bugs (", "").replace(")", "")[:3]
                                metadata["IntegerBugs"].append(integer_bug)
                            elif issue["swc-id"] == "104":
                                unhandled_exception = dict()
                                unhandled_exception["offset"] = issue["address"]
                                metadata["UnhandledExceptions"].append(unhandled_exception)
                            elif issue["swc-id"] in ["105", "106", "115"]:
                                access_control = dict()
                                access_control["offset"] = issue["address"]
                                if   issue["swc-id"] == "105":
                                    access_control["category"] = "leaking ether"
                                elif issue["swc-id"] == "106":
                                    access_control["category"] = "suicidal"
                                elif issue["swc-id"] == "115":
                                    access_control["category"] = "transaction origin"
                                metadata["AccessControl"].append(access_control)
                        except:
                            pass
            else:
                print("Error:", result["error"])
    container.remove(force=True)
    return metadata, code_coverage

def create_metadata(bytecode, ignore_bugs=[], use_assistance=False):
    metadata = {
      "Reentrancy": list(),
      "IntegerBugs": list(),
      "UnhandledExceptions": list(),
      "AccessControl": list()
    }
    code_coverage = 0.0
    metadata, code_coverage = run_mythril(bytecode, metadata, ignore_bugs=ignore_bugs)
    if len(metadata["Reentrancy"]) > 0:
        osiris_bugs = run_osiris(bytecode)
        print(osiris_bugs)
        valid_reentrancy = [bug["Reentrancy"] for bug in osiris_bugs if "Reentrancy" in bug]
        print(valid_reentrancy)
        if not any(valid_reentrancy):
            metadata["Reentrancy"] = list()
    return metadata, code_coverage
