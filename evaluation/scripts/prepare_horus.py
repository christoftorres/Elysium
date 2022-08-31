#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import json
import time
import shlex
import shutil
import hashlib
import requests
import subprocess

from web3 import Web3
from pathlib import Path
from eth_utils import to_canonical_address

RPC_HOST = "localhost"
RPC_PORT = 8545

MAX_BLOCK_HEIGHT = 11000000

ETHERSCAN_API_TOKEN = "VZ7EMQBT4GNH5F6FBV8FKXAFF6GS4MPKAU"

PROVIDER = Web3.HTTPProvider("http://"+RPC_HOST+":"+str(RPC_PORT))

DATASET = "../datasets/Horus"

DEBUG = False

def dict_raise_on_duplicates(ordered_pairs):
    """Reject duplicate keys."""
    d = {}
    c = 0
    for k, v in ordered_pairs:
        if k in d:
            if DEBUG:
                print("Duplicate key: %r" % (k,))
                c += 1
        else:
           d[k] = v
    if DEBUG and c > 0:
        print("Error: Duplicates:", c)
    return d

def main():
    print("Preparing", DATASET.split("/")[-1], "dataset...")
    print()
    paths = Path(DATASET).glob('**/*.json')
    stats = dict()

    w3 = Web3(PROVIDER)

    access_control = {
        "contracts": set(),
        "bugs": dict(),
        "attacking_transactions": set(),
        "benign_transactions": set(),
        "total_transactions": set()
    }

    unique = {
        "contracts": set(),
        "bugs": dict(),
        "attacking_transactions": set(),
        "benign_transactions": set(),
        "total_transactions": set()
    }

    contract_address_to_bytecode = dict()

    for path in paths:
        path = str(path)
        if path.split("/")[-1].count(".") == 1:
            bug_type = path.split("/")[-2]

            if not path.endswith(bug_type+"_attacking_transactions.json"):
                continue

            if DEBUG:
                print("Analyzing:", path)
            stats[bug_type] = dict()

            if not os.path.exists(os.path.join(path.rsplit('/', 1)[0], "bugs")):
                os.makedirs(os.path.join(path.rsplit('/', 1)[0], "bugs"))

            if not os.path.exists(os.path.join(path.rsplit('/', 1)[0], "contracts")):
                os.makedirs(os.path.join(path.rsplit('/', 1)[0], "contracts"))

            attacks = dict()
            attacks_total = 0
            with open(path) as json_file:
                attacks = json.load(json_file, object_pairs_hook=dict_raise_on_duplicates)

            benign_transactions = dict()
            benign_transactions_total = 0
            if os.path.exists(os.path.join(path.rsplit('/', 1)[0], bug_type+"_benign_transactions.json")):
                with open(os.path.join(path.rsplit('/', 1)[0], bug_type+"_benign_transactions.json")) as json_file:
                    benign_transactions = json.load(json_file)

            bugs = dict()

            for contract in attacks:
                if DEBUG:
                    print("Preparing contract:", contract)
                attacks_total += len(attacks[contract])

                # Retrieve and store smart contract bytecode
                if not os.path.exists(os.path.join(path.rsplit('/', 1)[0]+"/contracts", contract+".bin")):
                    bytecode = w3.eth.getCode(to_canonical_address(contract), w3.eth.getTransaction(attacks[contract][0])["blockNumber"]-1).hex().replace("0x", "")
                    with open(os.path.join(path.rsplit('/', 1)[0]+"/contracts", contract+".bin"), "w") as bytecode_file:
                        bytecode_file.write(bytecode)
                else:
                    with open(os.path.join(path.rsplit('/', 1)[0]+"/contracts", contract+".bin"), "r") as bytecode_file:
                        bytecode = bytecode_file.read()
                contract_address_to_bytecode[contract] = hashlib.sha256(bytecode.encode('utf-8')).hexdigest()

                # Retrieve and store benign transactions
                if not contract in benign_transactions:
                    transactions = list()
                    inputs = set()
                    page = 1
                    start = time.time()
                    while True:
                        api_response = requests.get("https://api.etherscan.io/api?module=account&action=txlist&address="+contract.lower()+"&startblock=0&endblock="+str(MAX_BLOCK_HEIGHT)+"&page="+str(page)+"&offset=10000&sort=asc&apikey="+ETHERSCAN_API_TOKEN).json()
                        if not api_response or "error" in api_response:
                            if "error" in api_response:
                                print("An error occured in retrieving the list of transactions from Etherscan: "+str(api_response["error"]))
                            else:
                                print("An unknown error ocurred in retrieving the list of transactions!")
                        elif "result" in api_response:
                            if not api_response["result"] or len(api_response["result"]) == 0:
                                break
                            else:
                                page += 1
                                for transaction in api_response["result"]:
                                    if transaction["isError"] == "0" and transaction["to"] != "" and int(transaction["gasUsed"]) > 21000 and not transaction["input"] in inputs and not transaction["hash"] in transactions and not transaction["hash"] in attacks[contract]:
                                        if bug_type.startswith("parity_wallet_hack"):
                                            # In case of a partiy wallet contract, only retrieve unprivileged transactions: # isOwner(address), m_numOwners(), m_lastDay(), m_spentToday(), m_required(), hasConfirmed(bytes32,address), getOwner(uint256), m_dailyLimit()
                                            if transaction["input"] == "0x" or transaction["input"][0:10] in ["0x2f54bf6e", "0x4123cb6b", "0x52375093", "0x659010e7", "0x746c9171", "0xc2cf7326", "0xc41a360a", "0xf1736d86"]:
                                                inputs.add(transaction["input"])
                                                transactions.append(transaction["hash"])
                                        else:
                                            inputs.add(transaction["input"])
                                            transactions.append(transaction["hash"])
                        else:
                            break
                    stop = time.time()
                    if DEBUG:
                        print("Retrieval took:", stop - start, "second(s).")
                    benign_transactions[contract] = transactions
                    with open(os.path.join(path.rsplit('/', 1)[0], bug_type+"_benign_transactions.json"), "w") as json_file:
                        json.dump(benign_transactions, json_file)
                if DEBUG:
                    print("Retrieved", len(benign_transactions[contract]), "benign transaction(s).")
                benign_transactions_total += len(benign_transactions[contract])

                # Retrieve and store bug reports
                bug_report = list()
                metadata = {
                  "Reentrancy": [],
                  "IntegerBugs": [],
                  "UnhandledExceptions": [],
                  "AccessControl": []
                }
                if DEBUG:
                    print("Retrieving bug reports...")
                for attack_tx in attacks[contract]:
                    if bug_type in ["reentrancy", "integer_overflow", "unhandled_exception"]:
                        if not os.path.exists(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".bugreport.json")) or not os.path.exists(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".metadata.json")):
                            if os.path.exists("./facts"):
                                shutil.rmtree("./facts")
                            cmd = "python3 ../tools/Horus/horus/horus.py -e --host "+RPC_HOST+" --port "+str(RPC_PORT)+" -tx "+attack_tx
                            if DEBUG:
                                print(cmd)
                            p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            out = p.communicate()
                            if DEBUG:
                                print(out[0].decode('utf-8'))
                                print(out[1].decode('utf-8'))
                            if os.path.exists("./facts"):
                                if os.path.exists("./results"):
                                    shutil.rmtree("./results")
                                cmd = "python3 ../tools/Horus/horus/horus.py -a -d ../tools/Horus/horus/analyzer/datalog/attacks.dl"
                                if DEBUG:
                                    print(cmd)
                                p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                out = p.communicate()
                                if DEBUG:
                                    print(out[0].decode('utf-8'))
                                    print(out[1].decode('utf-8'))
                                if os.path.exists("./results"):
                                    if bug_type == "unhandled_exception":
                                        with open("./results/UnhandledException.csv") as csv_file:
                                            reader = csv.reader(csv_file, delimiter='\t')
                                            for row in reader:
                                                bug = {
                                                    "code_coverage": 0.0,
                                                    "execution_time": 0.0,
                                                    "tool": "Horus",
                                                    "pc": int(row[2]),
                                                    "type": "unhandled exception"
                                                }
                                                if bug not in bug_report:
                                                    bug_report.append(bug)
                                                bug = {
                                                    "offset": int(row[2])
                                                }
                                                if bug not in metadata["UnhandledExceptions"]:
                                                    metadata["UnhandledExceptions"].append(bug)
                                    elif bug_type == "reentrancy":
                                        with open("./results/Reentrancy.csv") as csv_file:
                                            reader = csv.reader(csv_file, delimiter='\t')
                                            for row in reader:
                                                bug = {
                                                    "code_coverage": 0.0,
                                                    "execution_time": 0.0,
                                                    "tool": "Horus",
                                                    "pc": int(row[2]),
                                                    "type": "reentrancy"
                                                }
                                                if bug not in bug_report:
                                                    bug_report.append(bug)
                                                bug = {
                                                    "callOffset": int(row[2]),
                                                    "sStoreOffset": int(row[3]),
                                                }
                                                if bug not in metadata["Reentrancy"]:
                                                    metadata["Reentrancy"].append(bug)
                                        with open("./results/ReentrancyToken.csv") as csv_file:
                                            reader = csv.reader(csv_file, delimiter='\t')
                                            for row in reader:
                                                bug = {
                                                    "code_coverage": 0.0,
                                                    "execution_time": 0.0,
                                                    "tool": "Horus",
                                                    "pc": int(row[2]),
                                                    "type": "reentrancy"
                                                }
                                                if bug not in bug_report:
                                                    bug_report.append(bug)
                                                bug = {
                                                    "callOffset": int(row[2]),
                                                    "sStoreOffset": int(row[3]),
                                                }
                                                if bug not in metadata["Reentrancy"]:
                                                    metadata["Reentrancy"].append(bug)
                                    elif bug_type == "integer_overflow":
                                        with open("./results/IntegerOverflow.csv") as csv_file:
                                            reader = csv.reader(csv_file, delimiter='\t')
                                            for row in reader:
                                                bug = {
                                                    "code_coverage": 0.0,
                                                    "execution_time": 0.0,
                                                    "tool": "Horus",
                                                    "pc": int(row[2]),
                                                    "type": "underflow" if row[3] == "SUB" else "overflow",
                                                    "opcode": row[3]
                                                }
                                                if bug not in bug_report:
                                                    bug_report.append(bug)
                                                bug = {
                                                    "offset": int(row[2]),
                                                    "category": row[3].lower(),
                                                }
                                                if bug not in metadata["IntegerBugs"]:
                                                    metadata["IntegerBugs"].append(bug)
                            if os.path.exists("./facts"):
                                shutil.rmtree("./facts")
                            if os.path.exists("./results"):
                                shutil.rmtree("./results")
                    else:
                        if not os.path.exists(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".bugreport.json")):
                            if os.path.exists("./facts"):
                                shutil.rmtree("./facts")
                            cmd = "python3 ../tools/Horus/horus/horus.py -e --host "+RPC_HOST+" --port "+str(RPC_PORT)+" -c "+contract
                            p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            if DEBUG:
                                print(cmd)
                            out = p.communicate()
                            if DEBUG:
                                print(out[0].decode('utf-8'))
                                print(out[1].decode('utf-8'))
                            if os.path.exists("./facts"):
                                if os.path.exists("./results"):
                                    shutil.rmtree("./results")
                                cmd = "python3 ../tools/Horus/horus/horus.py -a -d ../tools/Horus/horus/analyzer/datalog/attacks.dl"
                                p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                if DEBUG:
                                    print(cmd)
                                out = p.communicate()
                                if DEBUG:
                                    print(out[0].decode('utf-8'))
                                    print(out[1].decode('utf-8'))
                                if os.path.exists("./results"):
                                    if bug_type == "parity_wallet_hack_1":
                                        with open("./results/ParityWalletHack1.csv") as csv_file:
                                            reader = csv.reader(csv_file, delimiter='\t')
                                            for row in reader:
                                                bug = {
                                                    "code_coverage": 0.0,
                                                    "execution_time": 0.0,
                                                    "tool": "Horus",
                                                    "pc": int(row[2]),
                                                    "type": "leaking ether"
                                                }
                                                if bug not in bug_report:
                                                    bug_report.append(bug)
                                                bug = {
                                                    "offset": int(row[2])
                                                }
                                                if bug not in metadata["AccessControl"]:
                                                    metadata["AccessControl"].append(bug)
                                    elif bug_type == "parity_wallet_hack_2":
                                        with open("./results/ParityWalletHack2.csv") as csv_file:
                                            reader = csv.reader(csv_file, delimiter='\t')
                                            for row in reader:
                                                bug = {
                                                    "code_coverage": 0.0,
                                                    "execution_time": 0.0,
                                                    "tool": "Horus",
                                                    "pc": int(row[2]),
                                                    "type": "suicidal"
                                                }
                                                if bug not in bug_report:
                                                    bug_report.append(bug)
                                                bug = {
                                                    "offset": int(row[2])
                                                }
                                                if bug not in metadata["AccessControl"]:
                                                    metadata["AccessControl"].append(bug)
                            if os.path.exists("./facts"):
                                shutil.rmtree("./facts")
                            if os.path.exists("./results"):
                                shutil.rmtree("./results")
                if bug_type in ["reentrancy", "integer_overflow", "unhandled_exception"]:
                    if bug_report:
                        with open(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".bugreport.json"), "w") as bug_report_file:
                            json.dump(bug_report, bug_report_file)
                    else:
                        with open(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".bugreport.json"), "r") as bug_report_file:
                            bug_report = json.load(bug_report_file)
                    if metadata["UnhandledExceptions"] or metadata["Reentrancy"] or metadata["IntegerBugs"]:
                        with open(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".metadata.json"), "w") as metadata_file:
                            json.dump(metadata, metadata_file)
                    else:
                        with open(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".metadata.json"), "r") as metadata_file:
                            metadata = json.load(metadata_file)
                else:
                    if bug_report:
                        with open(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".bugreport.json"), "w") as bug_report_file:
                            json.dump(bug_report, bug_report_file)
                    else:
                        with open(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".bugreport.json"), "r") as bug_report_file:
                            bug_report = json.load(bug_report_file)
                    if metadata["AccessControl"]:
                        with open(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".metadata.json"), "w") as metadata_file:
                            json.dump(metadata, metadata_file)
                    else:
                        with open(os.path.join(path.rsplit('/', 1)[0]+"/bugs", contract+".metadata.json"), "r") as metadata_file:
                            metadata = json.load(metadata_file)

                if not contract_address_to_bytecode[contract] in bugs:
                    bugs[contract_address_to_bytecode[contract]] = 0
                bugs[contract_address_to_bytecode[contract]] += len(bug_report)

                if bug_type.startswith("parity_wallet_hack"):
                    if not contract_address_to_bytecode[contract] in access_control["bugs"]:
                        access_control["bugs"][contract_address_to_bytecode[contract]] = 0
                    access_control["bugs"][contract_address_to_bytecode[contract]] += len(bug_report)

                if not contract_address_to_bytecode[contract] in unique["bugs"]:
                    unique["bugs"][contract_address_to_bytecode[contract]] = 0
                unique["bugs"][contract_address_to_bytecode[contract]] += len(bug_report)

            if bug_type.startswith("parity_wallet_hack"):
                access_control["contracts"].update(list(attacks.keys()) + list(benign_transactions.keys()))
                for value in attacks.values():
                    access_control["attacking_transactions"].update(value)
                for value in benign_transactions.values():
                    access_control["benign_transactions"].update(value)
                access_control["total_transactions"].update(list(access_control["attacking_transactions"]) + list(access_control["benign_transactions"]))

            unique["contracts"].update(list(attacks.keys()) + list(benign_transactions.keys()))
            for value in attacks.values():
                unique["attacking_transactions"].update(value)
            for value in benign_transactions.values():
                unique["benign_transactions"].update(value)
            unique["total_transactions"].update(list(unique["attacking_transactions"]) + list(unique["benign_transactions"]))

            print("----- "+bug_type.replace("_", " ").title()+" Statistics -----")
            print("Contracts:", len(attacks))
            print("Bugs:", sum([bugs[x] for x in bugs]))
            print("Total transactions:", benign_transactions_total + attacks_total)
            print("Benign transactions:", benign_transactions_total, "(Contracts: "+str(len(benign_transactions))+")")
            for a in benign_transactions:
                if not a in attacks:
                    print(a)
            print("Attacking transactions:", attacks_total)
            print("----------------------")
            print()

    print("----- Access Control Statistics -----")
    print("Contracts:", len(access_control["contracts"]))
    print("Bugs:", sum([access_control["bugs"][x] for x in access_control["bugs"]]))
    print("Total transactions:", len(access_control["total_transactions"]))
    print("Benign transactions:", len(access_control["benign_transactions"]))
    print("Attacking transactions:", len(access_control["attacking_transactions"]))
    print("-------------------------------------")
    print()
    print("----- Total Unique -----")
    print("Contracts:", len(unique["contracts"]))
    print("Bugs:", sum([unique["bugs"][x] for x in unique["bugs"]]))
    print("Total transactions:", len(unique["total_transactions"]))
    print("Benign transactions:", len(unique["benign_transactions"]))
    print("Attacking transactions:", len(unique["attacking_transactions"]))
    print("------------------------")

if __name__ == "__main__":
    main()
