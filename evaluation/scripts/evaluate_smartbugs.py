#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import json
import shlex
import docker
import subprocess
import numpy as np

from pathlib import Path
from solc import compile_standard

from utils.create_metadata import create_metadata
from utils.soliditycontract import SolidityContract

dataset = "../datasets/SmartBugs"

smartbugs_vulnerabilities = {
    "reentrancy": "reentrancy",
    "access_control": "access_control",
    "arithmetic": "integer_overflow",
    "unchecked_low_level_calls": "unhandled_exception"
}

DEBUG = False

class colors:
    INFO = '\033[94m'
    OK = '\033[92m'
    FAIL = '\033[91m'
    END = '\033[0m'

def extract_deployed_bytecode(bytecode):
    swarm_hash = extract_swarm_hash(bytecode)
    if swarm_hash:
        try:
            return re.search(r"396000f300.*a165627a7a72305820\S{64}0029$", bytecode).group().replace("396000f300", "")
        except:
            return bytecode
    return bytecode

def extract_swarm_hash(bytecode):
    try:
        return re.search(r"a165627a7a72305820\S{64}0029$", bytecode).group()
    except:
        return ""

def remove_swarm_hash(bytecode):
    return re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)

def compile(source_code, file_name):
    out = None
    try:
        out = compile_standard({
            'language': 'Solidity',
            'sources': {file_name: {'content': source_code}},
            'settings': {
                "optimizer": {
                    "enabled": True,
                    "runs": 200
                },
                "outputSelection": {
                    file_name: {
                        "*":
                            [
                                "evm.bytecode",
                                "evm.deployedBytecode",
                            ],
                        "": [
                          "ast"
                        ]
                    }
                }
            }
        }, allow_paths='.')
    except Exception as e:
        print(colors.FAIL+"Error: Solidity compilation failed!"+colors.END)
        if DEBUG:
            print(e)

    return out

def get_code_info(address, contract):
    code_info = None
    if address and isinstance(contract, SolidityContract):
        code_info = contract.get_source_info(address)
    return code_info

def main():
    print("Evaluating", dataset.split("/")[-1], "dataset...")

    directory = "../results/"+dataset.split("/")[-1]
    if not os.path.exists(directory):
        os.makedirs(directory)

    stats = dict()

    vulnerabilities_mapping = smartbugs_vulnerabilities
    for vulnerability in vulnerabilities_mapping:
        if vulnerabilities_mapping[vulnerability] not in stats:
            stats[vulnerabilities_mapping[vulnerability]] = {
                "contracts": 0,

                "labeled_vulnerabilities": 0,
                "reported_vulnerabilities": 0,
                "validated_vulnerabilities": 0,

                "smartshield_patched_vulnerabilities": 0,
                "sguard_patched_vulnerabilities": 0,
                "elysium_patched_vulnerabilities": 0,

                "smartshield_size_increase": list(),
                "smartshield_size_increase_percent": list(),
                "sguard_size_increase": list(),
                "sguard_size_increase_percent": list(),
                "elysium_size_increase": list(),
                "elysium_size_increase_percent": list()
            }

    # Load manually labeled vulnerabilities and count them
    labeled_vulnerabilities = dict()
    with open(dataset+"/vulnerabilities.json", "r") as json_file:
        labeled_vulnerabilities = json.load(json_file)
        for contract in labeled_vulnerabilities:
            for vulnerability_info in contract["vulnerabilities"]:
                if vulnerability_info["category"] in smartbugs_vulnerabilities:
                    stats[smartbugs_vulnerabilities[vulnerability_info["category"]]]["labeled_vulnerabilities"] += 1

    paths = Path(dataset).glob('**/*.sol')
    for path in paths:
        path = str(path)

        vulnerability = path.split("/")[-2]
        if vulnerability in vulnerabilities_mapping:
            print("Preparing:", colors.INFO, path, colors.END)

            stats[vulnerabilities_mapping[vulnerability]]["contracts"] += 1

            with open(path, "r") as source_code_file:
                # Read source code
                source_code = source_code_file.read()
                # Remove pragma
                source_code = re.sub(re.compile("pragma.*?\n"), "\n", source_code)
                # Compile source code
                print("Compiling source code...")
                compilation_output = compile(source_code, path)
                if compilation_output:
                    # Extract deployment bytecode and runtime bytecode
                    deployment_bytecode = ""
                    runtime_bytecode = ""
                    solidity_contract = None
                    entries = [entry for entry in labeled_vulnerabilities if path.endswith(entry["name"])]
                    if len(entries) == 1 and "contract" in entries[0]:
                        try:
                            deployment_bytecode = compilation_output["contracts"][path][entries[0]["contract"]]["evm"]["bytecode"]["object"]
                            runtime_bytecode = remove_swarm_hash(extract_deployed_bytecode(deployment_bytecode))
                            solidity_contract = SolidityContract(path, entries[0]["contract"], compilation_output)
                        except:
                            pass
                    else:
                        for contract in compilation_output["contracts"][path]:
                            try:
                                bytes.fromhex(remove_swarm_hash(extract_deployed_bytecode(compilation_output["contracts"][path][contract]["evm"]["bytecode"]["object"])))
                                if remove_swarm_hash(extract_deployed_bytecode(compilation_output["contracts"][path][contract]["evm"]["bytecode"]["object"])).startswith("60") and len(remove_swarm_hash(extract_deployed_bytecode(compilation_output["contracts"][path][contract]["evm"]["bytecode"]["object"]))) > len(runtime_bytecode):
                                    deployment_bytecode = compilation_output["contracts"][path][contract]["evm"]["bytecode"]["object"]
                                    runtime_bytecode = remove_swarm_hash(extract_deployed_bytecode(deployment_bytecode))
                                    solidity_contract = SolidityContract(path, contract, compilation_output)
                            except:
                                pass
                    if deployment_bytecode == "":
                        print(colors.FAIL+"Error: Could not obtain deployment bytecode for:", path, colors.END)
                    if runtime_bytecode == "":
                        print(colors.FAIL+"Error: Could not obtain runtime bytecode for:", path, colors.END)
                    if solidity_contract == None:
                        print(colors.FAIL+"Error: Could not obtain source map for:", path, colors.END)

                    original_bytecode_size = int(len(runtime_bytecode) / 2)

                    # Check if deployment bytecode file does not exist
                    if not os.path.exists(path.replace(".sol", ".bytecode")):
                        # Save deployment bytecode to file
                        with open(path.replace(".sol", ".bytecode"), "w") as binary_file:
                            binary_file.write(deployment_bytecode)

                    # Check if runtime bytecode file does not exist
                    if not os.path.exists(path.replace(".sol", ".bin")):
                        # Save runtime bytecode to file
                        with open(path.replace(".sol", ".bin"), "w") as binary_file:
                            binary_file.write(runtime_bytecode)

                    # Check if metadata file doesn't exist
                    metadata_path = "../results/"+dataset.split("/")[-1]+"/SmartShield/metadata/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".json")
                    if not os.path.exists(metadata_path):
                        # Create metadata file for SmartShield
                        ignore_bugs = []
                        if vulnerabilities_mapping[vulnerability] == "reentrancy": # SWC-ID: 107
                            ignore_bugs = ["101", "104", "105", "106", "115"]
                        elif vulnerabilities_mapping[vulnerability] == "integer_overflow": # SWC-ID: 101
                            ignore_bugs = ["104", "105", "106", "107", "115"]
                        elif vulnerabilities_mapping[vulnerability] == "unhandled_exception": # SWC-ID: 104
                            ignore_bugs = ["101", "105", "106", "107", "115"]
                        elif vulnerabilities_mapping[vulnerability] == "access_control": # SWC-ID: 105, 106, 115
                            ignore_bugs = ["101", "104", "107"]
                        metadata, code_coverage = create_metadata(runtime_bytecode, ignore_bugs=ignore_bugs)
                        print("Created metadata:", metadata, "code coverage:", code_coverage)
                        # Save metadata to a file
                        directory = os.path.dirname(metadata_path)
                        if not os.path.exists(directory):
                            os.makedirs(directory)
                        with open(metadata_path, "w") as json_file:
                            json.dump(metadata, json_file)
                    else:
                        # Load metadata from disk
                        with open(metadata_path, "r") as json_file:
                            metadata = json.load(json_file)

                    # Create SmartShield folder structure
                    directory = "../results/"+dataset.split("/")[-1]+"/SmartShield/reports/"+vulnerabilities_mapping[vulnerability]
                    if not os.path.exists(directory):
                        os.makedirs(directory)
                    directory = "../results/"+dataset.split("/")[-1]+"/SmartShield/patched/"+vulnerabilities_mapping[vulnerability]
                    if not os.path.exists(directory):
                        os.makedirs(directory)

                    # Create sGuard folder structure
                    directory = "../results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]
                    if not os.path.exists(directory):
                        os.makedirs(directory)
                    with open(directory+"/"+path.rsplit("/", 1)[1], "w") as sguard_source_code_file:
                        sguard_source_code_file.write(source_code)
                    with open(directory+"/"+path.rsplit("/", 1)[1].replace(".sol", ".metadata.json"), "w") as sguard_json_file:
                        entries = [entry for entry in labeled_vulnerabilities if path.endswith(entry["name"])]
                        json.dump({
                            "contractFile": "/evaluation/results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1],
                            "fixedFile": "/evaluation/results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".fixed.sol"),
                            "jsonFile": "/evaluation/results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1]+".json",
                            "contractName": entries[0]["contract"] if len(entries) == 1 and "contract" in entries[0] else ""
                        }, sguard_json_file, indent=4)

                    # Create Elysium folder structure
                    directory = "../results/"+dataset.split("/")[-1]+"/Elysium/bugs/"+vulnerabilities_mapping[vulnerability]
                    if not os.path.exists(directory):
                        os.makedirs(directory)
                    directory = "../results/"+dataset.split("/")[-1]+"/Elysium/patched/"+vulnerabilities_mapping[vulnerability]
                    if not os.path.exists(directory):
                        os.makedirs(directory)

                    # Check if bug report exists for Elysium
                    bug_report_path = "../results/"+dataset.split("/")[-1]+"/Elysium/bugs/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".bugs.json")
                    if not os.path.exists(bug_report_path):
                        print("Creating bug report for:", path)
                        bug_report = list()
                        for reentrancy in metadata["Reentrancy"]:
                            bug = dict()
                            bug["code_coverage"] = 0.0
                            bug["execution_time"] = 0.0
                            bug["tool"] = "Mythril"
                            bug["pc"] = reentrancy["callOffset"]
                            bug["type"] = "reentrancy"
                            if not bug in bug_report:
                                bug_report.append(bug)
                        for integer_bug in metadata["IntegerBugs"]:
                            bug = dict()
                            bug["code_coverage"] = 0.0
                            bug["execution_time"] = 0.0
                            bug["tool"] = "Mythril"
                            bug["pc"] = integer_bug["offset"]
                            if integer_bug["category"] == "sub":
                                bug["type"] = "underflow"
                            else:
                                bug["type"] = "overflow"
                            bug["opcode"] = integer_bug["category"].upper()
                            if not bug in bug_report:
                                bug_report.append(bug)
                        for unhandled_exception in metadata["UnhandledExceptions"]:
                            bug = dict()
                            bug["code_coverage"] = 0.0
                            bug["execution_time"] = 0.0
                            bug["tool"] = "Mythril"
                            bug["pc"] = unhandled_exception["offset"]
                            bug["type"] = "unhandled exception"
                            if not bug in bug_report:
                                bug_report.append(bug)
                        for access_control in metadata["AccessControl"]:
                            bug = dict()
                            bug["code_coverage"] = 0.0
                            bug["execution_time"] = 0.0
                            bug["tool"] = "Mythril"
                            bug["pc"] = access_control["offset"]
                            bug["type"] = access_control["category"]
                            if not bug in bug_report:
                                bug_report.append(bug)
                        directory = os.path.dirname(bug_report_path)
                        if not os.path.exists(directory):
                            os.makedirs(directory)
                        with open(bug_report_path, "w") as json_file:
                            json.dump(bug_report, json_file, indent=4)
                    else:
                        # Load bug report from disk
                        with open(bug_report_path, "r") as json_file:
                            bug_report = json.load(json_file)

                    # Check if SmartShield results are missing
                    if  not os.path.exists("../results/"+dataset.split("/")[-1]+"/SmartShield/reports/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".json")) or \
                        not os.path.exists("../results/"+dataset.split("/")[-1]+"/SmartShield/patched/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".patched.bin")):
                        print("Running SmartShield...")
                        # Run SmartShield
                        client = docker.from_env()
                        container = client.containers.run('christoftorres/smartshield', '-b /evaluation/'+path.replace("../", "").replace(".sol", ".bin")+' -m /evaluation/'+metadata_path.replace("../", "")+' -r /evaluation/results/'+dataset.split("/")[-1]+'/SmartShield/reports/'+vulnerabilities_mapping[vulnerability]+'/'+path.rsplit("/", 1)[1].replace(".sol", ".json")+' -o /evaluation/results/'+dataset.split("/")[-1]+'/SmartShield/patched/'+vulnerabilities_mapping[vulnerability]+'/'+path.rsplit("/", 1)[1].replace(".sol", ".patched.bin"), detach=True, remove=True, volumes={os.getcwd().rsplit('/', 1)[0]: {'bind': '/evaluation/', 'mode': 'rw'}})
                        out = ""
                        for line in container.logs(stream=True):
                            out += line.strip().decode("utf-8")
                        if DEBUG:
                            print(out)

                    # Check if sGuard results are missing
                    if  not os.path.exists("../results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".fixed.sol")) or \
                        not os.path.exists("../results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1]+".json"):
                        print("Running sGuard...")
                        # Run sGuard
                        client = docker.from_env()
                        container = client.containers.run('christoftorres/sguard', "timeout 120 npm run dev /evaluation/results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".metadata.json"), detach=True, remove=True, volumes={os.getcwd().rsplit('/', 1)[0]: {'bind': '/evaluation/', 'mode': 'rw'}})
                        out = ""
                        for line in container.logs(stream=True):
                            out += line.strip().decode("utf-8")
                        if DEBUG:
                            print(out)

                    # Check if Elysium results are missing
                    if not os.path.exists("../results/"+dataset.split("/")[-1]+"/Elysium/patched/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".patched.bin")):
                        # Run Elysium
                        print("Running Elysium...")
                        p = subprocess.Popen(shlex.split("timeout 120 python3 ../../elysium/elysium.py -b "+path.replace(".sol", ".bin")+" -r ../results/"+dataset.split("/")[-1]+"/Elysium/bugs/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".bugs.json")+" -o ../results/"+dataset.split("/")[-1]+"/Elysium/patched/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".patched.bin")), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        out = p.communicate()
                        if DEBUG:
                            print(out)

                    fixed_bugs = {"smartshield": [], "sguard": [], "elysium": []}

                    # Check if SmartShield fixed the vulnerabilities
                    print("Checking if SmartShield fixed the vulnerabilities...")
                    patched_metadata_path = '../results/'+dataset.split("/")[-1]+'/SmartShield/patched/'+vulnerabilities_mapping[vulnerability]+'/'+path.rsplit("/", 1)[1].replace(".sol", ".metadata.json")
                    patched_contract_path = '../results/'+dataset.split("/")[-1]+'/SmartShield/patched/'+vulnerabilities_mapping[vulnerability]+'/'+path.rsplit("/", 1)[1].replace(".sol", ".patched.bin")
                    if os.path.exists(patched_contract_path):
                        with open(patched_contract_path, 'r') as patched_file:
                            patched_bytecode = patched_file.read()
                        if not os.path.exists(patched_metadata_path):
                            ignore_bugs = list()
                            if vulnerabilities_mapping[vulnerability] == "reentrancy": # SWC-ID: 107
                                ignore_bugs = ["101", "104", "105", "106", "115"]
                            elif vulnerabilities_mapping[vulnerability] == "integer_overflow": # SWC-ID: 101
                                ignore_bugs = ["104", "105", "106", "107", "115"]
                            elif vulnerabilities_mapping[vulnerability] == "unhandled_exception": # SWC-ID: 104
                                ignore_bugs = ["101", "105", "106", "107", "115"]
                            elif vulnerabilities_mapping[vulnerability] == "access_control": # SWC-ID: 105, 106, 115
                                ignore_bugs = ["101", "104", "107"]
                            patched_metadata, patched_code_coverage = create_metadata(patched_bytecode, ignore_bugs=ignore_bugs)
                            print("SmartShield patched metadata:", patched_metadata, "Patched code coverage:", patched_code_coverage)
                            directory = os.path.dirname(patched_metadata_path)
                            if not os.path.exists(directory):
                                os.makedirs(directory)
                            with open(patched_metadata_path, "w") as json_file:
                                json.dump(patched_metadata, json_file)
                        else:
                            with open(patched_metadata_path, "r") as json_file:
                                patched_metadata = json.load(json_file)
                        smartshield_bytecode_size = int(len(patched_bytecode) / 2)
                        size_increase = smartshield_bytecode_size - original_bytecode_size
                        if size_increase > 0 and vulnerabilities_mapping[vulnerability] in ["reentrancy", "integer_overflow", "unhandled_exception"]:
                            stats[vulnerabilities_mapping[vulnerability]]["smartshield_size_increase"].append(size_increase)
                            stats[vulnerabilities_mapping[vulnerability]]["smartshield_size_increase_percent"].append(size_increase / original_bytecode_size * 100)
                        if vulnerabilities_mapping[vulnerability] == "reentrancy":
                            if len(patched_metadata["Reentrancy"]) == 0:
                                for entry in metadata["Reentrancy"]:
                                    fixed_bugs["smartshield"].append(entry)
                        elif vulnerabilities_mapping[vulnerability] == "integer_overflow":
                            if len(patched_metadata["IntegerBugs"]) == 0:
                                for entry in metadata["IntegerBugs"]:
                                    fixed_bugs["smartshield"].append(entry)
                        elif vulnerabilities_mapping[vulnerability] == "unhandled_exception":
                            if len(patched_metadata["UnhandledExceptions"]) == 0:
                                for entry in metadata["UnhandledExceptions"]:
                                    fixed_bugs["smartshield"].append(entry)

                    # Check if sGuard fixed the vulnerabilities
                    print("Checking if sGuard fixed the vulnerabilities...")
                    patched_metadata_path = "../results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".patched.metadata.json")
                    patched_contract_path = "../results/"+dataset.split("/")[-1]+"/sGuard/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".fixed.sol")
                    if os.path.exists(patched_contract_path):
                        sguard_runtime_bytecode = ""
                        with open(patched_contract_path, 'r') as patched_file:
                            patched_source_code = patched_file.read()
                            compilation_output = compile(patched_source_code, patched_contract_path)
                            if compilation_output:
                                entries = [entry for entry in labeled_vulnerabilities if path.endswith(entry["name"])]
                                if len(entries) == 1 and "contract" in entries[0]:
                                    try:
                                        sguard_deployment_bytecode = compilation_output["contracts"][patched_contract_path][entries[0]["contract"]]["evm"]["bytecode"]["object"]
                                        sguard_runtime_bytecode = remove_swarm_hash(extract_deployed_bytecode(sguard_deployment_bytecode))
                                    except:
                                        pass
                                else:
                                    for contract in compilation_output["contracts"][patched_contract_path]:
                                        try:
                                            bytes.fromhex(remove_swarm_hash(extract_deployed_bytecode(compilation_output["contracts"][patched_contract_path][contract]["evm"]["bytecode"]["object"])))
                                            if remove_swarm_hash(extract_deployed_bytecode(compilation_output["contracts"][patched_contract_path][contract]["evm"]["bytecode"]["object"])).startswith("60") and len(remove_swarm_hash(extract_deployed_bytecode(compilation_output["contracts"][patched_contract_path][contract]["evm"]["bytecode"]["object"]))) > len(sguard_runtime_bytecode):
                                                sguard_deployment_bytecode = compilation_output["contracts"][patched_contract_path][contract]["evm"]["bytecode"]["object"]
                                                sguard_runtime_bytecode = remove_swarm_hash(extract_deployed_bytecode(sguard_deployment_bytecode))
                                        except:
                                            pass
                        if not os.path.exists(patched_metadata_path):
                            if sguard_runtime_bytecode:
                                ignore_bugs = list()
                                if vulnerabilities_mapping[vulnerability] == "reentrancy": # SWC-ID: 107
                                    ignore_bugs = ["101", "104", "105", "106", "115"]
                                elif vulnerabilities_mapping[vulnerability] == "integer_overflow": # SWC-ID: 101
                                    ignore_bugs = ["104", "105", "106", "107", "115"]
                                elif vulnerabilities_mapping[vulnerability] == "unhandled_exception": # SWC-ID: 104
                                    ignore_bugs = ["101", "105", "106", "107", "115"]
                                elif vulnerabilities_mapping[vulnerability] == "access_control": # SWC-ID: 105, 106, 115
                                    ignore_bugs = ["101", "104", "107"]
                                patched_metadata, patched_code_coverage = create_metadata(sguard_runtime_bytecode, ignore_bugs=ignore_bugs)
                                print("sGuard patched metadata:", patched_metadata, "Patched code coverage:", patched_code_coverage)
                                directory = os.path.dirname(patched_metadata_path)
                                if not os.path.exists(directory):
                                    os.makedirs(directory)
                                with open(patched_metadata_path, "w") as json_file:
                                    json.dump(patched_metadata, json_file)
                        else:
                            with open(patched_metadata_path, "r") as json_file:
                                patched_metadata = json.load(json_file)
                        if sguard_runtime_bytecode:
                            sguard_bytecode_size = int(len(sguard_runtime_bytecode) / 2)
                            size_increase = sguard_bytecode_size - original_bytecode_size
                            if size_increase > 0 and vulnerabilities_mapping[vulnerability] in ["reentrancy", "integer_overflow", "access_control"]:
                                stats[vulnerabilities_mapping[vulnerability]]["sguard_size_increase"].append(size_increase)
                                stats[vulnerabilities_mapping[vulnerability]]["sguard_size_increase_percent"].append(size_increase / original_bytecode_size * 100)
                        if vulnerabilities_mapping[vulnerability] == "reentrancy":
                            if len(patched_metadata["Reentrancy"]) == 0:
                                for entry in metadata["Reentrancy"]:
                                    fixed_bugs["sguard"].append(entry)
                        elif vulnerabilities_mapping[vulnerability] == "integer_overflow":
                            if len(patched_metadata["IntegerBugs"]) == 0:
                                for entry in metadata["IntegerBugs"]:
                                    fixed_bugs["sguard"].append(entry)
                        elif vulnerabilities_mapping[vulnerability] == "access_control":
                            if len(patched_metadata["AccessControl"]) == 0:
                                for entry in metadata["AccessControl"]:
                                    if entry["category"] == "transaction origin":
                                        fixed_bugs["sguard"].append(entry)

                    # Check if Elysium fixed the vulnerabilities
                    print("Checking if Elysium fixed the vulnerabilities...")
                    patched_metadata_path = "../results/"+dataset.split("/")[-1]+"/Elysium/patched/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".metadata.json")
                    patched_contract_path = "../results/"+dataset.split("/")[-1]+"/Elysium/patched/"+vulnerabilities_mapping[vulnerability]+"/"+path.rsplit("/", 1)[1].replace(".sol", ".patched.bin")
                    if os.path.exists(patched_contract_path):
                        with open(patched_contract_path, 'r') as patched_file:
                            patched_bytecode = patched_file.read()
                        if not os.path.exists(patched_metadata_path):
                            ignore_bugs = list()
                            if vulnerabilities_mapping[vulnerability] == "reentrancy": # SWC-ID: 107
                                ignore_bugs = ["101", "104", "105", "106", "115"]
                            elif vulnerabilities_mapping[vulnerability] == "integer_overflow": # SWC-ID: 101
                                ignore_bugs = ["104", "105", "106", "107", "115"]
                            elif vulnerabilities_mapping[vulnerability] == "unhandled_exception": # SWC-ID: 104
                                ignore_bugs = ["101", "105", "106", "107", "115"]
                            elif vulnerabilities_mapping[vulnerability] == "access_control": # SWC-ID: 105, 106, 115
                                ignore_bugs = ["101", "104", "107"]
                            patched_metadata, patched_code_coverage = create_metadata(patched_bytecode, ignore_bugs=ignore_bugs)
                            print("Elysium patched metadata:", patched_metadata, "Patched code coverage:", patched_code_coverage)
                            directory = os.path.dirname(patched_metadata_path)
                            if not os.path.exists(directory):
                                os.makedirs(directory)
                            with open(patched_metadata_path, "w") as json_file:
                                json.dump(patched_metadata, json_file)
                        else:
                            with open(patched_metadata_path, "r") as json_file:
                                patched_metadata = json.load(json_file)
                        elysium_bytecode_size = int(len(patched_bytecode) / 2)
                        size_increase = elysium_bytecode_size - original_bytecode_size
                        if size_increase > 0 and vulnerabilities_mapping[vulnerability] in ["reentrancy", "integer_overflow", "unhandled_exception", "access_control"]:
                            stats[vulnerabilities_mapping[vulnerability]]["elysium_size_increase"].append(size_increase)
                            stats[vulnerabilities_mapping[vulnerability]]["elysium_size_increase_percent"].append(size_increase / original_bytecode_size * 100)
                        if vulnerabilities_mapping[vulnerability] == "reentrancy":
                            if len(patched_metadata["Reentrancy"]) == 0:
                                for entry in metadata["Reentrancy"]:
                                    fixed_bugs["elysium"].append(entry)
                        elif vulnerabilities_mapping[vulnerability] == "integer_overflow":
                            if len(patched_metadata["IntegerBugs"]) == 0:
                                for entry in metadata["IntegerBugs"]:
                                    fixed_bugs["elysium"].append(entry)
                        elif vulnerabilities_mapping[vulnerability] == "unhandled_exception":
                            if len(patched_metadata["UnhandledExceptions"]) == 0:
                                for entry in metadata["UnhandledExceptions"]:
                                    fixed_bugs["elysium"].append(entry)
                        elif vulnerabilities_mapping[vulnerability] == "access_control":
                            if len(patched_metadata["AccessControl"]) == 0:
                                for entry in metadata["AccessControl"]:
                                    fixed_bugs["elysium"].append(entry)

                    # Count vulnerabilities
                    if vulnerabilities_mapping[vulnerability] == "reentrancy":
                        reported = list()
                        for reentrancy in metadata["Reentrancy"]:
                            if not reentrancy["callOffset"] in reported:
                                for contract in labeled_vulnerabilities:
                                    if path.endswith(contract["name"]):
                                        for vulnerability_info in contract["vulnerabilities"]:
                                            code_info = get_code_info(reentrancy["callOffset"], solidity_contract)
                                            if code_info and vulnerability_info["category"] == "reentrancy" and any(code_info.lineno + 1 == l or code_info.lineno == l for l in vulnerability_info["lines"]):
                                                stats[vulnerabilities_mapping[vulnerability]]["validated_vulnerabilities"] += 1
                                                if reentrancy in fixed_bugs["smartshield"]:
                                                    stats[vulnerabilities_mapping[vulnerability]]["smartshield_patched_vulnerabilities"] += 1
                                                elif DEBUG:
                                                    print(colors.FAIL+"Error: SmartShield could not reentrancy bug: "+str(reentrancy)+" at line: "+str(code_info.lineno)+colors.END)
                                                if reentrancy in fixed_bugs["sguard"]:
                                                    stats[vulnerabilities_mapping[vulnerability]]["sguard_patched_vulnerabilities"] += 1
                                                elif DEBUG:
                                                    print(colors.FAIL+"Error: sGuard could not reentrancy bug: "+str(reentrancy)+" at line: "+str(code_info.lineno)+colors.END)
                                                if reentrancy in fixed_bugs["elysium"]:
                                                    stats[vulnerabilities_mapping[vulnerability]]["elysium_patched_vulnerabilities"] += 1
                                                elif DEBUG:
                                                    print(colors.FAIL+"Error: Elysium could not reentrancy bug: "+str(reentrancy)+" at line: "+str(code_info.lineno)+colors.END)
                                stats[vulnerabilities_mapping[vulnerability]]["reported_vulnerabilities"] += 1
                                reported.append(reentrancy["callOffset"])
                    if vulnerabilities_mapping[vulnerability] == "integer_overflow":
                        reported = list()
                        for integer_bug in metadata["IntegerBugs"]:
                            if not integer_bug["offset"] in reported:
                                for contract in labeled_vulnerabilities:
                                    if path.endswith(contract["name"]):
                                        for vulnerability_info in contract["vulnerabilities"]:
                                            code_info = get_code_info(integer_bug["offset"], solidity_contract)
                                            if code_info and vulnerability_info["category"] == "arithmetic" and any(l == code_info.lineno + 1 or code_info.lineno == l for l in vulnerability_info["lines"]):
                                                stats[vulnerabilities_mapping[vulnerability]]["validated_vulnerabilities"] += 1
                                                if integer_bug in fixed_bugs["smartshield"]:
                                                    stats[vulnerabilities_mapping[vulnerability]]["smartshield_patched_vulnerabilities"] += 1
                                                elif DEBUG:
                                                    print(colors.FAIL+"Error: SmartShield could not patch integer bug: "+str(integer_bug)+" at line: "+str(code_info.lineno)+colors.END)
                                                if integer_bug in fixed_bugs["sguard"]:
                                                    stats[vulnerabilities_mapping[vulnerability]]["sguard_patched_vulnerabilities"] += 1
                                                elif DEBUG:
                                                    print(colors.FAIL+"Error: sGuard could not patch integer bug: "+str(integer_bug)+" at line: "+str(code_info.lineno)+colors.END)
                                                if integer_bug in fixed_bugs["elysium"]:
                                                    stats[vulnerabilities_mapping[vulnerability]]["elysium_patched_vulnerabilities"] += 1
                                                elif DEBUG:
                                                    print(colors.FAIL+"Error: Elysium could not patch integer bug: "+str(integer_bug)+" at line: "+str(code_info.lineno)+colors.END)
                            stats[vulnerabilities_mapping[vulnerability]]["reported_vulnerabilities"] += 1
                            reported.append(integer_bug["offset"])
                    if vulnerabilities_mapping[vulnerability] == "unhandled_exception":
                        for unhandled_exception in metadata["UnhandledExceptions"]:
                            for contract in labeled_vulnerabilities:
                                if path.endswith(contract["name"]):
                                    for vulnerability_info in contract["vulnerabilities"]:
                                        code_info = get_code_info(unhandled_exception["offset"], solidity_contract)
                                        if vulnerability_info["category"] == "unchecked_low_level_calls" and any(l == code_info.lineno + 1 or code_info.lineno == l for l in vulnerability_info["lines"]):
                                            stats[vulnerabilities_mapping[vulnerability]]["validated_vulnerabilities"] += 1
                                            if unhandled_exception in fixed_bugs["smartshield"]:
                                                stats[vulnerabilities_mapping[vulnerability]]["smartshield_patched_vulnerabilities"] += 1
                                            elif DEBUG:
                                                print(colors.FAIL+"Error: SmartShield could not patch unhandled exception bug: "+str(unhandled_exception)+" at line: "+str(code_info.lineno)+colors.END)
                                            if unhandled_exception in fixed_bugs["elysium"]:
                                                stats[vulnerabilities_mapping[vulnerability]]["elysium_patched_vulnerabilities"] += 1
                                            elif DEBUG:
                                                print(colors.FAIL+"Error: Elysium could not patch unhandled exception bug: "+str(unhandled_exception)+" at line: "+str(code_info.lineno)+colors.END)
                            stats[vulnerabilities_mapping[vulnerability]]["reported_vulnerabilities"] += 1
                    if vulnerabilities_mapping[vulnerability] == "access_control":
                        for access_control in metadata["AccessControl"]:
                            for contract in labeled_vulnerabilities:
                                if path.endswith(contract["name"]):
                                    for vulnerability_info in contract["vulnerabilities"]:
                                        code_info = get_code_info(access_control["offset"], solidity_contract)
                                        if vulnerability_info["category"] == "access_control" and any(l == code_info.lineno + 1 or code_info.lineno == l for l in vulnerability_info["lines"]):
                                            stats[vulnerabilities_mapping[vulnerability]]["validated_vulnerabilities"] += 1
                                            if access_control in fixed_bugs["sguard"]:
                                                stats[vulnerabilities_mapping[vulnerability]]["sguard_patched_vulnerabilities"] += 1
                                            elif DEBUG:
                                                print(colors.FAIL+"Error: sGuard could not patch access control bug: "+str(access_control)+" at line: "+str(code_info.lineno)+colors.END)
                                            if access_control in fixed_bugs["elysium"]:
                                                stats[vulnerabilities_mapping[vulnerability]]["elysium_patched_vulnerabilities"] += 1
                                            elif DEBUG:
                                                print(colors.FAIL+"Error: Elysium could not patch access control bug: "+str(access_control)+" at line: "+str(code_info.lineno)+colors.END)
                            stats[vulnerabilities_mapping[vulnerability]]["reported_vulnerabilities"] += 1
            print()

    for vulnerability in stats:
        if not stats[vulnerability]["smartshield_size_increase"]:
            stats[vulnerability]["smartshield_size_increase"].append(0.0)
        if not stats[vulnerability]["smartshield_size_increase_percent"]:
            stats[vulnerability]["smartshield_size_increase_percent"].append(0.0)
        stats[vulnerability]["smartshield_size_increase"] = np.mean(stats[vulnerability]["smartshield_size_increase"])
        stats[vulnerability]["smartshield_size_increase_percent"] = np.mean(stats[vulnerability]["smartshield_size_increase_percent"])

        if not stats[vulnerability]["sguard_size_increase"]:
            stats[vulnerability]["sguard_size_increase"].append(0.0)
        if not stats[vulnerability]["sguard_size_increase_percent"]:
            stats[vulnerability]["sguard_size_increase_percent"].append(0.0)
        stats[vulnerability]["sguard_size_increase"] = np.mean(stats[vulnerability]["sguard_size_increase"])
        stats[vulnerability]["sguard_size_increase_percent"] = np.mean(stats[vulnerability]["sguard_size_increase_percent"])

        if not stats[vulnerability]["elysium_size_increase"]:
            stats[vulnerability]["elysium_size_increase"].append(0.0)
        if not stats[vulnerability]["elysium_size_increase_percent"]:
            stats[vulnerability]["elysium_size_increase_percent"].append(0.0)
        stats[vulnerability]["elysium_size_increase"] = np.mean(stats[vulnerability]["elysium_size_increase"])
        stats[vulnerability]["elysium_size_increase_percent"] = np.mean(stats[vulnerability]["elysium_size_increase_percent"])

    # Write dataset stats to disk
    with open("../results/"+dataset.split("/")[-1]+"/"+dataset.split("/")[-1]+"-results.json", "w") as json_file:
        json.dump(stats, json_file, indent=4)

    total_contracts, total_labeled_vulnerabilities, total_reported_vulnerabilities, total_validated_vulnerabilities, total_smartshield_patched_vulnerabilities, total_sguard_patched_vulnerabilities, total_elysium_patched_vulnerabilities = 0, 0, 0, 0, 0, 0, 0
    print("              \t \t            \t| Vulnerabilities               \t \t| Vulnerabilities Patched       \t \t| Deployment Cost Increase (Bytes)")
    print("Vulnerability \t \t| Contracts \t| Labeled \t Detected \t Validated \t| SmartShield \t sGuard \t Elysium \t| SmartShield \t sGuard \t Elysium")
    print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    for vulnerability in stats:
        total_contracts += stats[vulnerability]["contracts"]
        total_labeled_vulnerabilities += stats[vulnerability]["labeled_vulnerabilities"]
        total_reported_vulnerabilities += stats[vulnerability]["reported_vulnerabilities"]
        total_validated_vulnerabilities += stats[vulnerability]["validated_vulnerabilities"]
        total_smartshield_patched_vulnerabilities += stats[vulnerability]["smartshield_patched_vulnerabilities"]
        total_sguard_patched_vulnerabilities += stats[vulnerability]["sguard_patched_vulnerabilities"]
        total_elysium_patched_vulnerabilities += stats[vulnerability]["elysium_patched_vulnerabilities"]
        name = vulnerability.capitalize().replace("_", " ")
        print(
            name+"\t \t|" if len(name) < 16 else name+" \t|",
            stats[vulnerability]["contracts"], "\t \t|",
            stats[vulnerability]["labeled_vulnerabilities"], "\t \t", stats[vulnerability]["reported_vulnerabilities"], "\t \t", stats[vulnerability]["validated_vulnerabilities"], "\t \t|",
            stats[vulnerability]["smartshield_patched_vulnerabilities"], "\t \t", stats[vulnerability]["sguard_patched_vulnerabilities"], "\t \t", stats[vulnerability]["elysium_patched_vulnerabilities"], "\t \t|",
            str(int(stats[vulnerability]["smartshield_size_increase"]))+" ("+'{0:.2f}'.format(stats[vulnerability]["smartshield_size_increase_percent"])+"%)", "\t",
            str(int(stats[vulnerability]["sguard_size_increase"]))+" ("+'{0:.2f}'.format(stats[vulnerability]["sguard_size_increase_percent"])+"%)", "\t",
            str(int(stats[vulnerability]["elysium_size_increase"]))+" ("+'{0:.2f}'.format(stats[vulnerability]["elysium_size_increase_percent"])+"%)"
        )
    print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    print("Total", "\t \t \t|", total_contracts, "\t \t|", total_labeled_vulnerabilities, "\t \t", total_reported_vulnerabilities, "\t \t", total_validated_vulnerabilities, "\t \t|", total_smartshield_patched_vulnerabilities, "\t \t", total_sguard_patched_vulnerabilities, "\t \t", total_elysium_patched_vulnerabilities, "\t \t|")

if __name__ == "__main__":
    main()
