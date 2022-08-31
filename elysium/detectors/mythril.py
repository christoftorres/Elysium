#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import json
import docker

def run_mythril_bytecode_analyzer(bytecode, debug=False):
    print("Running Mythril...")
    bugs = list()
    start = time.time()
    client = docker.from_env()
    container = client.containers.run('christoftorres/mythril', '-v 5 analyze -m UncheckedRetval,EtherThief,AccidentallyKillable,ArbitraryDelegateCall,TxOrigin --bin-runtime -c '+bytecode+' --parallel-solving -o json --execution-timeout 120', detach=True, remove=True)
    code_coverage = 0.0
    for line in container.logs(stream=True):
        if line.strip().decode("utf-8").startswith("mythril.laser.plugin.plugins.coverage.coverage_plugin [INFO]: Achieved"):
            code_coverage = float(line.strip().decode("utf-8").replace("mythril.laser.plugin.plugins.coverage.coverage_plugin [INFO]: Achieved ", "").split("%")[0])
        if debug:
            print(line.strip().decode("utf-8"))
        current_line = line.strip().decode("utf-8")
        if current_line.startswith('{"'):
            result = json.loads(current_line)
            if result["error"] == None and result["success"] == True:
                for issue in result["issues"]:
                    if issue["swc-id"] == "104" and not issue["address"] in [bug["pc"] for bug in bugs if bug["type"] == "unhandled exception"]:
                        bug = dict()
                        bug["code_coverage"] = code_coverage
                        bug["execution_time"] = 0.0
                        bug["tool"] = "Mythril"
                        bug["pc"] = issue["address"]
                        bug["type"] = "unhandled exception"
                        bugs.append(bug)
                    elif issue["swc-id"] == "105" and not issue["address"] in [bug["pc"] for bug in bugs if bug["type"] == "leaking ether"]:
                        bug = dict()
                        bug["code_coverage"] = code_coverage
                        bug["execution_time"] = 0.0
                        bug["tool"] = "Mythril"
                        bug["pc"] = issue["address"]
                        bug["type"] = "leaking ether"
                        bugs.append(bug)
                    elif issue["swc-id"] == "106" and not issue["address"] in [bug["pc"] for bug in bugs if bug["type"] == "suicidal"]:
                        bug = dict()
                        bug["code_coverage"] = code_coverage
                        bug["execution_time"] = 0.0
                        bug["tool"] = "Mythril"
                        bug["pc"] = issue["address"]
                        bug["type"] = "suicidal"
                        bugs.append(bug)
                    elif issue["swc-id"] == "112" and not issue["address"] in [bug["pc"] for bug in bugs if bug["type"] == "unsafe delegatecall"]:
                        bug = dict()
                        bug["code_coverage"] = code_coverage
                        bug["execution_time"] = 0.0
                        bug["tool"] = "Mythril"
                        bug["pc"] = issue["address"]
                        bug["type"] = "unsafe delegatecall"
                        bugs.append(bug)
                    elif issue["swc-id"] == "115" and not issue["address"] in [bug["pc"] for bug in bugs if bug["type"] == "transaction origin"]:
                        bug = dict()
                        bug["code_coverage"] = code_coverage
                        bug["execution_time"] = 0.0
                        bug["tool"] = "Mythril"
                        bug["pc"] = issue["address"]
                        bug["type"] = "transaction origin"
                        bugs.append(bug)
                    else:
                        if debug:
                            print(issue)
    end = time.time()
    for bug in bugs:
        bug["code_coverage"] = code_coverage
        bug["execution_time"] = end - start
    print("Finished running Mythril. Execution time", end - start, "seconds.", "Code coverage", str(code_coverage)+"%.")
    return bugs
