#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import json
import docker

def run_osiris_bytecode_analyzer(bytecode, debug=False):
    print("Running Osiris...")
    bugs = list()
    start = time.time()
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
                    if not result["pc"] in [bug["pc"] for bug in bugs]:
                        bug = dict()
                        bug["code_coverage"] = code_coverage
                        bug["execution_time"] = 0.0
                        bug["tool"] = "Osiris"
                        bug["pc"] = result["pc"]
                        bug["type"] = result["type"]
                        bug["opcode"] = json.loads(current_line.replace("'", '"').replace('<', '"<').replace('>', '>"').lower())["opcode"].upper()
                        bugs.append(bug)
            previous_line = current_line
    end = time.time()
    for bug in bugs:
        bug["code_coverage"] = code_coverage
        bug["execution_time"] = end - start
    print("Finished running Osiris. Execution time", end - start, "seconds.", "Code coverage", str(code_coverage)+"%.")
    return bugs
