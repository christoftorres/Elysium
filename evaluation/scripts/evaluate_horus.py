#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import csv
import json
import shlex
import docker
import traceback
import subprocess
import numpy as np
import multiprocessing

from web3 import Web3
from tqdm import tqdm
from pathlib import Path
from eth_utils import decode_hex, to_canonical_address

sys.path.insert(0, '../..')
from validation.emulator import Emulator

PROVIDER = Web3.HTTPProvider("http://localhost:8545")

dataset = "../datasets/Horus"

DEBUG = True

class colors:
    INFO = '\033[94m'
    OK = '\033[92m'
    FAIL = '\033[91m'
    END = '\033[0m'

def is_execution_identical(original, patched):
    if  original[0].is_success  == patched[0].is_success and \
        original[0].is_error    == patched[0].is_error and \
        original[0].return_data == patched[0].return_data and \
        original[0].output      == patched[0].output and \
        original[1]             >= patched[1]: # Check if patched version used up more or the same gas as compared to the original version
        # Check if the patched version executed all instructions from the original version
        original_instructions = [instruction["opcode"] if not instruction["opcode"].startswith("PUSH") else "PUSH" for instruction in original[2]]
        patched_instructions = [instruction["opcode"] if not instruction["opcode"].startswith("PUSH") else "PUSH" for instruction in patched[2]]
        i, j = 0, 0
        identical_instructions = list()
        while i < len(original_instructions):
            if j < len(patched_instructions):
                if original_instructions[i] == patched_instructions[j]:
                    identical_instructions.append(original_instructions[i])
                    i += 1
                    j += 1
                else:
                    j += 1
            else:
                break
        if len(identical_instructions) != len(original_instructions):
            return False
        # Check if the error message is the same in case there was and error for both versions
        if original[0].is_error == True and patched[0].is_error == True and original[0].error != patched[0].error:
            return False
        return True
    return False

def replay_transaction(transaction_hash):
    try:
        print("Replaying transaction:", transaction_hash)
        try:
            transaction = w3.eth.getTransaction(transaction_hash)
            block = w3.eth.getBlock(transaction["blockNumber"], True)
        except Exception as e:
            print(colors.FAIL)
            traceback.print_exc()
            print("Error:", str(e)+". Could not retrieve transaction information!", colors.END)
            return contract_address, transaction_hash, None, (None, None, str(e)), (None, None, str(e))

        emu = Emulator(PROVIDER, block)
        try:
            emu.prepare_state(transaction)
        except:
            print(colors.FAIL+"Error: State could not be prepared!", transaction["blockNumber"], colors.END)
            emu = Emulator(PROVIDER, block)
        emu.create_snapshot()

        try:
            emu.restore_from_snapshot()
            result_original, trace_original, balance_original = emu.send_transaction(transaction)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(e)
            print(colors.FAIL+"Error: Original transaction", transaction_hash, "could not be executed!", colors.END)
            return contract_address, transaction_hash, None, (None, None, None), (None, None, None)

        try:
            emu.restore_from_snapshot()
            result_smartshield, trace_smartshield, balance_smartshield = emu.send_transaction(transaction, code={contract_address: decode_hex(smartshield_bytecode)})
            smartshield_execution = is_execution_identical((result_original, balance_original, trace_original), (result_smartshield, balance_smartshield, trace_smartshield))
            smartshield_gas_used = result_smartshield.get_gas_used()
            if result_smartshield.is_error == True and result_smartshield.error:
                smartshield_error = str(result_smartshield.error)
                if smartshield_error == "Invalid Jump Destination":
                    smartshield_error += ": "+trace_smartshield[-1]["stack"][-1]
            else:
                smartshield_error = None
        except Exception as e:
            print(e)
            print(colors.FAIL+"Error: SmartShield transaction", transaction_hash, "could not be executed!", colors.END)
            smartshield_execution, smartshield_gas_used, smartshield_error = None, None, None

        try:
            emu.restore_from_snapshot()
            result_elysium, trace_elysium, balance_elysium = emu.send_transaction(transaction, code={contract_address: decode_hex(elysium_bytecode)})
            elysium_execution = is_execution_identical((result_original, balance_original, trace_original), (result_elysium, balance_elysium, trace_elysium))
            elysium_gas_used = result_elysium.get_gas_used()
            if result_elysium.is_error == True and result_elysium.error:
                elysium_error = str(result_elysium.error)
                if elysium_error == "Invalid Jump Destination":
                    elysium_error += ": "+trace_elysium[-1]["stack"][-1]
            else:
                elysium_error = None
        except Exception as e:
            print(colors.FAIL)
            import traceback
            traceback.print_exc()
            print("Error: "+str(e)+". Elysium transaction", transaction_hash, "could not be executed!", colors.END)
            elysium_execution, elysium_gas_used, elysium_error = None, None, None
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(colors.FAIL+"Error:", e, colors.END)
        return contract_address, transaction_hash, None, (None, None, str(e)), (None, None, str(e))

    return contract_address, transaction_hash, result_original.get_gas_used(), (smartshield_execution, smartshield_gas_used, smartshield_error), (elysium_execution, elysium_gas_used, elysium_error)

def init_process(_contract_address, _smartshield_bytecode, _elysium_bytecode):
    global w3
    global contract_address
    global smartshield_bytecode
    global elysium_bytecode

    w3 = Web3(PROVIDER)
    contract_address = _contract_address
    smartshield_bytecode = _smartshield_bytecode
    elysium_bytecode = _elysium_bytecode

def main():
    multiprocessing.set_start_method('fork')

    print("Evaluating", dataset.split("/")[-1], "dataset...")
    directory = "../results/"+dataset.split("/")[-1]
    if not os.path.exists(directory):
        os.makedirs(directory)
    paths = Path(dataset).glob('**/*.json')
    w3 = Web3(PROVIDER)
    stats = dict()

    access_control_attacks = set()

    total_unique = dict()
    total_unique["smartshield"] = dict()
    total_unique["smartshield"]["benign"] = set()
    total_unique["smartshield"]["attacks"] = set()
    total_unique["elysium"] = dict()
    total_unique["elysium"]["benign"] = set()
    total_unique["elysium"]["attacks"] = set()

    for path in paths:
        path = str(path)
        if path.split("/")[-1].count(".") > 1:
            continue

        bug_type = path.split("/")[-2]
        if not path.endswith(bug_type+"_attacking_transactions.json"):
            continue

        if DEBUG:
            print(path)

        stats[bug_type] = dict()
        stats[bug_type]["contracts"] = list()
        stats[bug_type]["transactions"] = list()
        stats[bug_type]["benign"] = list()
        stats[bug_type]["attacks"] = list()

        stats[bug_type]["smartshield"] = dict()
        stats[bug_type]["smartshield"]["benign"] = 0
        stats[bug_type]["smartshield"]["attacks"] = 0
        stats[bug_type]["smartshield"]["errors"] = dict()
        stats[bug_type]["smartshield"]["errors"]["out_of_gas"] = 0
        stats[bug_type]["smartshield"]["errors"]["invalid_jump"] = 0
        stats[bug_type]["smartshield"]["gas_increase"] = list()
        stats[bug_type]["smartshield"]["gas_increase_percent"] = list()
        stats[bug_type]["smartshield"]["size_increase"] = list()
        stats[bug_type]["smartshield"]["size_increase_percent"] = list()

        stats[bug_type]["elysium"] = dict()
        stats[bug_type]["elysium"]["benign"] = 0
        stats[bug_type]["elysium"]["attacks"] = 0
        stats[bug_type]["elysium"]["errors"] = dict()
        stats[bug_type]["elysium"]["errors"]["out_of_gas"] = 0
        stats[bug_type]["elysium"]["errors"]["invalid_jump"] = 0
        stats[bug_type]["elysium"]["gas_increase"] = list()
        stats[bug_type]["elysium"]["gas_increase_percent"] = list()
        stats[bug_type]["elysium"]["size_increase"] = list()
        stats[bug_type]["elysium"]["size_increase_percent"] = list()

        if not os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield")):
            os.makedirs(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield"))

        if not os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium")):
            os.makedirs(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium"))

        print("===== Replaying Attack transactions =====")
        attacks = list()
        with open(path) as json_file:
            attacks = json.load(json_file)
        stats[bug_type]["contracts"] = len(list(attacks.keys()))
        stats[bug_type]["attacks"] = sum([len(values) for values in list(attacks.values())])

        results = list()
        if os.path.exists("../results/"+dataset.split("/")[-1]+"/"+bug_type+"/"+bug_type+"-attack-results.csv"):
            with open("../results/"+dataset.split("/")[-1]+"/"+bug_type+"/"+bug_type+"-attack-results.csv", "r") as csv_file:
                reader = csv.reader(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                first_row_skipped = False
                for row in reader:
                    if not first_row_skipped:
                        first_row_skipped = True
                    else:
                        if row[0] in attacks:
                            if row[1] in attacks[row[0]]:
                                attacks[row[0]].remove(row[1])
                                if len(attacks[row[0]]) == 0:
                                    del attacks[row[0]]
                        if row[2] == "":
                            row[2] = None
                        else:
                            row[2] = int(row[2])

                        row[3] = row[3].replace("\'", "").replace("\\", "").replace('"', '').replace(", b)", ", )")
                        if row[3] == "(None, None, None)":
                            row[3] = (None, None, None)
                        else:
                            row[3] = row[3].replace("(", "").replace(")", "").split(", ")
                            row[3] = (True if row[3][0] == "True" else False, int(row[3][1]), None if row[3][2] == "None" else row[3][2])

                        row[4] = row[4].replace("\'", "").replace("\\", "").replace('"', '').replace(", b)", ", )")
                        if row[4] == "(None, None, None)":
                            row[4] = (None, None, None)
                        else:
                            row[4] = row[4].replace("(", "").replace(")", "").split(", ")
                            row[4] = (True if row[4][0] == "True" else False, int(row[4][1]), None if row[4][2] == "None" else row[4][2])

                        results.append(row)

        for contract in attacks:
            print("Contract", contract, "Transactions", len(attacks[contract]))

            if not os.path.exists('../datasets/'+dataset.split("/")[-1]+'/'+bug_type+'/bugs/'+contract+'.metadata.json') or \
               not os.path.exists('../datasets/'+dataset.split("/")[-1]+'/'+bug_type+'/bugs/'+contract+'.bugreport.json'):
               print(colors.FAIL+"Skipping contract due to missing bug report or bug metadata..."+colors.END)
               continue

            # Run SmartShield
            if not os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield")+"/"+contract+".patched.bin"):
                print("Running SmartShield...")
                client = docker.from_env()
                container = client.containers.run('christoftorres/smartshield', '-b /evaluation/datasets/'+dataset.split("/")[-1]+'/'+bug_type+'/contracts/'+contract+'.bin -m /evaluation/datasets/'+dataset.split("/")[-1]+'/'+bug_type+'/bugs/'+contract+'.metadata.json -r /evaluation/results/'+dataset.split("/")[-1]+'/'+bug_type+'/smartshield/'+contract+'.report.json -o /evaluation/results/'+dataset.split("/")[-1]+'/'+bug_type+'/smartshield/'+contract+'.patched.bin', detach=True, remove=True, volumes={os.getcwd().rsplit('/', 1)[0]: {'bind': '/evaluation/', 'mode': 'rw'}})
                for line in container.logs(stream=True):
                    output = line.strip().decode("utf-8")
                    if DEBUG:
                        print(output)
            smartshield_bytecode = None
            if os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield")+"/"+contract+".patched.bin"):
                with open(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield")+"/"+contract+".patched.bin", "r") as file:
                    smartshield_bytecode = file.read().strip()

            # Run Elysium
            if not os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium")+"/"+contract+".patched.bin"):
                print("Running Elysium...")
                p = subprocess.Popen(shlex.split('python3 ../../elysium/elysium.py -b ../datasets/'+dataset.split("/")[-1]+'/'+bug_type+'/contracts/'+contract+'.bin -r ../datasets/'+dataset.split("/")[-1]+'/'+bug_type+'/bugs/'+contract+'.bugreport.json -o ../results/'+dataset.split("/")[-1]+'/'+bug_type+'/elysium/'+contract+'.patched.bin'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = p.communicate()
                if DEBUG:
                    print(output[0].decode("utf-8"))
                    print(output[1].decode("utf-8"))
            elysium_bytecode = None
            if os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium")+"/"+contract+".patched.bin"):
                with open(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium")+"/"+contract+".patched.bin", "r") as file:
                    elysium_bytecode = file.read().strip()

            with multiprocessing.Pool(processes=multiprocessing.cpu_count(), initializer=init_process, initargs=(contract, smartshield_bytecode, elysium_bytecode, )) as pool:
                results += pool.map(replay_transaction, attacks[contract])

            with open("../results/"+dataset.split("/")[-1]+"/"+bug_type+"/"+bug_type+"-attack-results.csv", "w") as csv_file:
                writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(["Contract Address", "Transaction Hash", "Original Gas Used", "SmartShield (Success, Gas Used, Error Message)", "Elysium (Success, Gas Used, Error Message)"])
                for result in results:
                    writer.writerow(result)

        with open("../results/"+dataset.split("/")[-1]+"/"+bug_type+"/"+bug_type+"-attack-results.csv", "w") as csv_file:
            writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["Contract Address", "Transaction Hash", "Original Gas Used", "SmartShield (Success, Gas Used, Error Message)", "Elysium (Success, Gas Used, Error Message)"])
            for result in results:
                writer.writerow(result)

        for i in tqdm(range(len(results))):
            result = results[i]

            if result[3][0] == False:
                stats[bug_type]["smartshield"]["attacks"] += 1
                total_unique["smartshield"]["attacks"].add(result[1])
            if result[4][0] == False:
                stats[bug_type]["elysium"]["attacks"] += 1
                total_unique["elysium"]["attacks"].add(result[1])

            if os.path.exists(os.path.join(path.rsplit('/', 1)[0]+"/contracts", result[0]+".bin")):
                with open(os.path.join(path.rsplit('/', 1)[0]+"/contracts", result[0]+".bin"), "r") as file:
                    deployed_bytecode = file.read().strip()
                    deployed_bytecode_size = int(len(deployed_bytecode) / 2)
                    swarm_hash = ""
                    try:
                        swarm_hash = re.search(r"a165627a7a72305820\S{64}0029$", deployed_bytecode).group()
                    except:
                        pass
                    if os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield")+"/"+result[0]+".patched.bin"):
                        with open(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield")+"/"+result[0]+".patched.bin", "r") as file:
                            smartshield_bytecode = file.read().strip()
                            smartshield_bytecode_size = int(len(smartshield_bytecode + swarm_hash) / 2)
                            stats[bug_type]["smartshield"]["size_increase"].append(smartshield_bytecode_size - deployed_bytecode_size)
                            stats[bug_type]["smartshield"]["size_increase_percent"].append((smartshield_bytecode_size - deployed_bytecode_size) / deployed_bytecode_size * 100)
                    if os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium")+"/"+result[0]+".patched.bin"):
                        with open(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium")+"/"+result[0]+".patched.bin", "r") as file:
                            elysium_bytecode = file.read().strip()
                            elysium_bytecode_size = int(len(elysium_bytecode) / 2)
                            stats[bug_type]["elysium"]["size_increase"].append(elysium_bytecode_size - deployed_bytecode_size)
                            stats[bug_type]["elysium"]["size_increase_percent"].append((elysium_bytecode_size - deployed_bytecode_size) / deployed_bytecode_size * 100)

        print()
        print("===== Replaying Benign transactions =====")
        benign = list()
        if os.path.exists(path.rsplit("/", 1)[0]+"/"+bug_type+"_benign_transactions.json"):
            with open(path.rsplit("/", 1)[0]+"/"+bug_type+"_benign_transactions.json", "r") as json_file:
                benign = json.load(json_file)
        stats[bug_type]["benign"] = sum([len(values) for values in list(benign.values())])
        stats[bug_type]["transactions"] = stats[bug_type]["benign"] + stats[bug_type]["attacks"]

        results = list()
        if os.path.exists("../results/"+dataset.split("/")[-1]+"/"+bug_type+"/"+bug_type+"-benign-results.csv"):
            import sys
            csv.field_size_limit(sys.maxsize)
            with open("../results/"+dataset.split("/")[-1]+"/"+bug_type+"/"+bug_type+"-benign-results.csv", "r") as csv_file:
                reader = csv.reader(csv_file, delimiter=',')
                first_row_skipped = False
                for row in reader:
                    if not first_row_skipped:
                        first_row_skipped = True
                    else:
                        if row[0] in benign:
                            if row[1] in benign[row[0]]:
                                benign[row[0]].remove(row[1])
                        if row[2] == "":
                            row[2] = None
                        else:
                            row[2] = int(row[2])

                        row[3] = row[3].replace("\'", "").replace("\\", "").replace('"', '')
                        if row[3] == "(None, None, None)":
                            row[3] = (None, None, None)
                        elif "not found" in row[3]:
                            row[3] = row[3].replace("(", "").replace(")", "").split(", ")
                            row[3] = (None, None, row[3][2])
                        else:
                            row[3] = row[3].replace("(", "").replace(")", "").split(", ")
                            row[3] = (True if row[3][0] == "True" else False, None if row[3][1] == "None" else int(row[3][1]), None if row[3][2] == "None" else row[3][2])

                        row[4] = row[4].replace("\'", "").replace("\\", "").replace('"', '')
                        if row[4] == "(None, None, None)":
                            row[4] = (None, None, None)
                        elif "not found" in row[4]:
                            row[4] = row[4].replace("(", "").replace(")", "").split(", ")
                            row[4] = (None, None, row[4][2])
                        else:
                            row[4] = row[4].replace("(", "").replace(")", "").split(", ")
                            row[4] = (True if row[4][0] == "True" else False, None if row[4][1] == "None" else int(row[4][1]), None if row[4][2] == "None" else row[4][2])
                        results.append(row)

        for contract in list(benign.keys()):
            if len(benign[contract]) == 0:
                del benign[contract]

        for contract in benign:
            print("Contract", contract, "Transactions", len(benign[contract]))

            smartshield_bytecode = None
            if os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield")+"/"+contract+".patched.bin"):
                with open(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "smartshield")+"/"+contract+".patched.bin", "r") as file:
                    smartshield_bytecode = file.read().strip()

            elysium_bytecode = None
            if os.path.exists(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium")+"/"+contract+".patched.bin"):
                with open(os.path.join("../results/"+dataset.split("/")[-1]+"/"+bug_type, "elysium")+"/"+contract+".patched.bin", "r") as file:
                    elysium_bytecode = file.read().strip()

            with multiprocessing.Pool(processes=multiprocessing.cpu_count(), initializer=init_process, initargs=(contract, smartshield_bytecode, elysium_bytecode, )) as pool:
                results += pool.map(replay_transaction, benign[contract])

            with open("../results/"+dataset.split("/")[-1]+"/"+bug_type+"/"+bug_type+"-benign-results.csv", "w") as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                writer.writerow(["Contract Address", "Transaction Hash", "Original Gas Used", "SmartShield (Success, Gas Used, Error Message)", "Elysium (Success, Gas Used, Error Message)"])
                for result in results:
                    writer.writerow(result)

        with open("../results/"+dataset.split("/")[-1]+"/"+bug_type+"/"+bug_type+"-benign-results.csv", "w") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(["Contract Address", "Transaction Hash", "Original Gas Used", "SmartShield (Success, Gas Used, Error Message)", "Elysium (Success, Gas Used, Error Message)"])
            for result in results:
                writer.writerow(result)

        for i in tqdm(range(len(results))):
            result = results[i]

            if result[3][1] != None and result[2] != None:
                if result[3][0] == True or (result[3][0] == False and result[3][1] == result[2]) or (bug_type.startswith("parity_wallet_hack") and result[3][0] == False and result[2] == 0):
                    if not bug_type.startswith("parity_wallet_hack"):
                        stats[bug_type]["smartshield"]["benign"] += 1
                        total_unique["smartshield"]["benign"].add(result[1])
                        gas_delta = result[3][1] - result[2]
                        if gas_delta > 0 and result[2] > 0 and result[3][0] == True:
                            stats[bug_type]["smartshield"]["gas_increase"].append(gas_delta)
                            stats[bug_type]["smartshield"]["gas_increase_percent"].append(gas_delta / result[2] * 100)

            if result[4][1] != None and result[2] != None:
                if result[4][0] == True or (result[4][0] == False and result[4][1] == result[2]) or (bug_type.startswith("parity_wallet_hack") and result[4][0] == False and result[2] == 0):
                    if bug_type.startswith("parity_wallet_hack"):
                        access_control_attacks.add(result[1])
                    stats[bug_type]["elysium"]["benign"] += 1
                    total_unique["elysium"]["benign"].add(result[1])
                    gas_delta = result[4][1] - result[2]
                    if gas_delta > 0 and result[2] > 0 and result[4][0] == True:
                        stats[bug_type]["elysium"]["gas_increase"].append(gas_delta)
                        stats[bug_type]["elysium"]["gas_increase_percent"].append(gas_delta / result[2] * 100)

            if result[3][2] != None:
                if "Out of gas" in result[3][2]:
                    stats[bug_type]["smartshield"]["errors"]["out_of_gas"] += 1
                if "Invalid Jump Destination" in result[3][2]:
                    stats[bug_type]["smartshield"]["errors"]["invalid_jump"] += 1

            if result[4][2] != None:
                if "Out of gas" in result[4][2]:
                    stats[bug_type]["elysium"]["errors"]["out_of_gas"] += 1
                if "Invalid Jump Destination" in result[4][2]:
                    stats[bug_type]["elysium"]["errors"]["invalid_jump"] += 1

    for bug_type in stats:
        if len(stats[bug_type]["smartshield"]["size_increase"]) > 0:
            stats[bug_type]["smartshield"]["size_increase"] = np.mean(stats[bug_type]["smartshield"]["size_increase"])
        else:
            stats[bug_type]["smartshield"]["size_increase"] = 0
        if len(stats[bug_type]["smartshield"]["size_increase_percent"]) > 0:
            stats[bug_type]["smartshield"]["size_increase_percent"] = np.mean(stats[bug_type]["smartshield"]["size_increase_percent"])
        else:
            stats[bug_type]["smartshield"]["size_increase_percent"] = 0

        if len(stats[bug_type]["smartshield"]["gas_increase"]) > 0:
            stats[bug_type]["smartshield"]["gas_increase"] = np.median(stats[bug_type]["smartshield"]["gas_increase"])
        else:
            stats[bug_type]["smartshield"]["gas_increase"] = 0
        if len(stats[bug_type]["smartshield"]["gas_increase_percent"]) > 0:
            stats[bug_type]["smartshield"]["gas_increase_percent"] = np.median(stats[bug_type]["smartshield"]["gas_increase_percent"])
        else:
            stats[bug_type]["smartshield"]["gas_increase_percent"] = 0

        if len(stats[bug_type]["elysium"]["size_increase"]) > 0:
            stats[bug_type]["elysium"]["size_increase"] = np.mean(stats[bug_type]["elysium"]["size_increase"])
        else:
            stats[bug_type]["elysium"]["size_increase"] = 0
        if len(stats[bug_type]["elysium"]["size_increase_percent"]) > 0:
            stats[bug_type]["elysium"]["size_increase_percent"] = np.mean(stats[bug_type]["elysium"]["size_increase_percent"])
        else:
            stats[bug_type]["elysium"]["size_increase_percent"] = 0

        if len(stats[bug_type]["elysium"]["gas_increase"]) > 0:
            stats[bug_type]["elysium"]["gas_increase"] = np.median(stats[bug_type]["elysium"]["gas_increase"])
        else:
            stats[bug_type]["elysium"]["gas_increase"] = 0
        if len(stats[bug_type]["elysium"]["gas_increase_percent"]) > 0:
            stats[bug_type]["elysium"]["gas_increase_percent"] = np.median(stats[bug_type]["elysium"]["gas_increase_percent"])
        else:
            stats[bug_type]["elysium"]["gas_increase_percent"] = 0

    stats["parity_wallet_hack_1"]["smartshield"]["gas_increase"] = 0
    stats["parity_wallet_hack_1"]["smartshield"]["gas_increase_percent"] = 0
    stats["parity_wallet_hack_2"]["smartshield"]["gas_increase"] = 0
    stats["parity_wallet_hack_2"]["smartshield"]["gas_increase_percent"] = 0

    # Write dataset stats to disk
    with open("../results/"+dataset.split("/")[-1]+"/"+dataset.split("/")[-1]+"-results.json", "w") as json_file:
        json.dump(stats, json_file, indent=4)

    print()
    print("              \t \t|           \t| Transactions      \t \t \t \t| Benign \t \t \t| Attacks \t \t \t| Deployment Code Increase (Bytes) \t| Transaction Overhead (Gas)")
    print("Vulnerability \t \t| Contracts \t| Total \t Benign \t Attacks \t| SmartShield \t Elysium \t| SmartShield \t Elysium \t| SmartShield \t \t Elysium \t| SmartShield \t Elysium")
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    for bug_type in stats:
        print(
            bug_type.capitalize().replace("_", " ") + " \t" if len(bug_type) < 16 else bug_type.capitalize().replace("_", " "), "\t|",
            stats[bug_type]["contracts"], "\t \t|",
            str(stats[bug_type]["transactions"])+" \t \t" if stats[bug_type]["transactions"] < 10000 else str(stats[bug_type]["transactions"])+" \t",
            stats[bug_type]["benign"], "\t \t", stats[bug_type]["attacks"], "\t \t|",
            str(stats[bug_type]["smartshield"]["benign"])+" \t" if stats[bug_type]["smartshield"]["benign"] > 9999 else str(stats[bug_type]["smartshield"]["benign"])+"\t \t",
            stats[bug_type]["elysium"]["benign"], "("+str(round((stats[bug_type]["elysium"]["benign"] / stats[bug_type]["benign"]) * 100))+"%)", "\t \t|",
            stats[bug_type]["smartshield"]["attacks"], "\t \t", stats[bug_type]["elysium"]["attacks"], "\t \t|",
            '{0:.0f}'.format(stats[bug_type]["smartshield"]["size_increase"]), '({0:.2f}%)'.format(stats[bug_type]["smartshield"]["size_increase_percent"]) + " \t \t",
            '{0:.0f}'.format(stats[bug_type]["elysium"]["size_increase"]),'({0:.2f}%)'.format(stats[bug_type]["elysium"]["size_increase_percent"])+ " \t|",
            '{0:.0f}'.format(stats[bug_type]["smartshield"]["gas_increase"]), '({0:.2f}%)'.format(stats[bug_type]["smartshield"]["gas_increase_percent"]) + " \t",
            '{0:.0f}'.format(stats[bug_type]["elysium"]["gas_increase"]),'({0:.2f}%)'.format(stats[bug_type]["elysium"]["gas_increase_percent"])
        )
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    print("Total Unique", "\t \t \t \t \t \t \t \t \t \t|", len(total_unique["smartshield"]["benign"]), "\t", len(total_unique["elysium"]["benign"]), "\t|", len(total_unique["smartshield"]["attacks"]), "\t \t", len(total_unique["elysium"]["attacks"]))

if __name__ == "__main__":
    main()
