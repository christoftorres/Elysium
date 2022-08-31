#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import docker

def run_oyente_bytecode_analyzer(bytecode, debug=False):
    print("Running Oyente...")
    bugs = []
    start = time.time()
    client = docker.from_env()
    container = client.containers.run('christoftorres/oyente', "/bin/bash -c \"echo '"+bytecode+"' > bytecode.evm; python3 oyente/oyente.py -s bytecode.evm -b\"", detach=True, remove=True)
    code_coverage = 0.0
    previous_line = ""
    for line in container.logs(stream=True):
        if debug:
            print(line.strip().decode("utf-8"))
        if line.strip().decode("utf-8").startswith("INFO:symExec:	  EVM Code Coverage:"):
            code_coverage = float(line.strip().decode("utf-8").replace("INFO:symExec:	  EVM Code Coverage: 			 ", "").replace("%", ""))
        if line.strip().decode("utf-8").startswith("INFO:symExec:	  Re-Entrancy Vulnerability: 		 True"):
            pc = int(line.strip().decode("utf-8").replace("INFO:symExec:	  Re-Entrancy Vulnerability: 		 True [", "").replace("]", ""))
            if not pc in [bug["pc"] for bug in bugs]:
                bug = dict()
                bug["code_coverage"] = code_coverage
                bug["execution_time"] = 0.0
                bug["tool"] = "Oyente"
                bug["pc"] = pc
                bug["type"] = "reentrancy"
                bugs.append(bug)
    end = time.time()
    for bug in bugs:
        bug["code_coverage"] = code_coverage
        bug["execution_time"] = end - start
    print("Finished running Oyente. Execution time", end - start, "seconds.", "Code coverage", str(code_coverage)+"%.")
    return bugs
