#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import csv
import json
import numpy as np
import multiprocessing

from web3 import Web3
from tqdm import tqdm
from pathlib import Path
from eth_utils import decode_hex

sys.path.insert(0, '../..')
from validation.emulator import Emulator

PROVIDER = Web3.HTTPProvider("http://localhost:8545")

dataset = "../datasets/CVEs"

def is_execution_identical(original, patched):
    if  original[0].is_success        == patched[0].is_success and \
        original[0].is_error          == patched[0].is_error and \
        original[0].get_log_entries() == patched[0].get_log_entries() and \
        original[0].return_data       == patched[0].return_data and \
        original[0].output            == patched[0].output and \
        original[1]                   >= patched[1]:
        if original[0].is_error == True and patched[0].is_error == True:
            if original[0].error  == patched[0].error:
                return True
            else:
                return False
        return True
    return False

def replay_transaction(transaction_hash):
    print(transaction_hash)
    transaction = w3.eth.getTransaction(transaction_hash)
    block = w3.eth.getBlock(transaction["blockNumber"], True)

    emu = Emulator(PROVIDER, block)
    try:
        emu.prepare_state(transaction)
    except:
        emu = Emulator(PROVIDER, block)
    emu.create_snapshot()

    try:
        emu.restore_from_snapshot()
        result_original, _, balance_original = emu.send_transaction(transaction, code={contract_address: decode_hex(original_bytecode)})
    except Exception as e:
        try:
            emu = Emulator(PROVIDER, block)
            emu.prepare_state(transaction, consider_all_transactions=True)
            emu.create_snapshot()
            emu.restore_from_snapshot()
            result_original, _, balance_original = emu.send_transaction(transaction, code={contract_address: decode_hex(original_bytecode)})
        except Exception as e:
            print(e)
            print("Error: Original transaction", transaction_hash, "could not be executed!")
            return transaction_hash, None, (None, None, None), (None, None, None), (None, None, None)

    try:
        emu.restore_from_snapshot()
        result_evmpatch, _, balance_evmpatch = emu.send_transaction(transaction, code={contract_address: decode_hex(evmpatch_bytecode)})
        evmpatch_execution = is_execution_identical((result_original, balance_original), (result_evmpatch, balance_evmpatch))
        evmpatch_gas_used = result_evmpatch.get_gas_used()
        if result_evmpatch.is_error == True:
            evmpatch_error = str(result_evmpatch.error)
        else:
            evmpatch_error = None
    except Exception as e:
        print(e)
        print("Error: EVMPatch transaction", transaction_hash, "could not be executed!")
        evmpatch_execution, evmpatch_gas_used, evmpatch_error = None, None, None

    try:
        emu.restore_from_snapshot()
        result_smartshield, _, balance_smartshield = emu.send_transaction(transaction, code={contract_address: decode_hex(smartshield_bytecode)})
        smartshield_execution = is_execution_identical((result_original, balance_original), (result_smartshield, balance_smartshield))
        smartshield_gas_used = result_smartshield.get_gas_used()
        if result_smartshield.is_error == True:
            smartshield_error = str(result_smartshield.error)
        else:
            smartshield_error = None
    except Exception as e:
        print(e)
        print("Error: SmartShield transaction", transaction_hash, "could not be executed!")
        smartshield_execution, smartshield_gas_used, smartshield_error = None, None, None

    try:
        emu.restore_from_snapshot()
        result_elysium, _, balance_elysium = emu.send_transaction(transaction, code={contract_address: decode_hex(elysium_bytecode)})
        elysium_execution = is_execution_identical((result_original, balance_original), (result_elysium, balance_elysium))
        elysium_gas_used = result_elysium.get_gas_used()
        if result_elysium.is_error == True:
            elysium_error = str(result_elysium.error)
        else:
            elysium_error = None
    except Exception as e:
        print(e)
        print("Error: Elysium transaction", transaction_hash, "could not be executed!")
        elysium_execution, elysium_gas_used, elysium_error = None, None, None

    return transaction_hash, result_original.get_gas_used(), (evmpatch_execution, evmpatch_gas_used, evmpatch_error), (smartshield_execution, smartshield_gas_used, smartshield_error), (elysium_execution, elysium_gas_used, elysium_error)

def init_process(_contract_address, _original_bytecode, _evmpatch_bytecode, _smartshield_bytecode, _elysium_bytecode):
    global w3
    global contract_address
    global original_bytecode
    global evmpatch_bytecode
    global smartshield_bytecode
    global elysium_bytecode

    w3 = Web3(PROVIDER)
    contract_address = _contract_address
    original_bytecode = _original_bytecode
    evmpatch_bytecode = _evmpatch_bytecode
    smartshield_bytecode = _smartshield_bytecode
    elysium_bytecode = _elysium_bytecode

def main():
    print("Evaluating", dataset.split("/")[-1], "dataset...")
    directory = "../results/"+dataset.split("/")[-1]
    if not os.path.exists(directory):
        os.makedirs(directory)
    paths = Path(dataset).glob('**/*.bugs.json')
    stats = dict()

    for path in paths:
        path = str(path)
        contract_name = path.split("/")[-2]
        contract_address = path.split("/")[-1].split(".")[0]
        print()
        print("Analyzing contract", contract_name, "("+contract_address+")...")

        stats[contract_name] = dict()

        deployed_bytecode = None
        with open(os.path.join(os.path.dirname(path), contract_address+".bin"), "r") as file:
            deployed_bytecode = file.read().strip()
        deployed_bytecode_size = int(len(deployed_bytecode) / 2)
        stats[contract_name]["deployed_bytecode_size"] = deployed_bytecode_size

        evmpatch_bytecode = None
        with open(os.path.join(os.path.dirname(path), contract_address+".evmpatch.bin"), "r") as file:
            evmpatch_bytecode = file.read().strip()
        evmpatch_bytecode_size = int(len(evmpatch_bytecode) / 2)
        stats[contract_name]["evmpatch"] = dict()
        stats[contract_name]["evmpatch"]["bytecode_size"] = evmpatch_bytecode_size
        stats[contract_name]["evmpatch"]["size_increase"] = evmpatch_bytecode_size - deployed_bytecode_size
        stats[contract_name]["evmpatch"]["size_increase_percent"] = stats[contract_name]["evmpatch"]["size_increase"] / deployed_bytecode_size * 100
        stats[contract_name]["evmpatch"]["benign_success"] = 0
        stats[contract_name]["evmpatch"]["benign_failed"] = 0
        stats[contract_name]["evmpatch"]["out_of_gas"] = 0
        stats[contract_name]["evmpatch"]["attacks_success"] = 0
        stats[contract_name]["evmpatch"]["attacks_failed"] = 0
        stats[contract_name]["evmpatch"]["gas_increase"] = list()
        stats[contract_name]["evmpatch"]["gas_increase_percent"] = list()

        smartshield_bytecode = None
        with open(os.path.join(os.path.dirname(path), contract_address+".smartshield.bin"), "r") as file:
            smartshield_bytecode = file.read().strip()
        smartshield_bytecode_size = int(len(smartshield_bytecode) / 2)
        stats[contract_name]["smartshield"] = dict()
        stats[contract_name]["smartshield"]["bytecode_size"] = smartshield_bytecode_size
        stats[contract_name]["smartshield"]["size_increase"] = smartshield_bytecode_size - deployed_bytecode_size
        stats[contract_name]["smartshield"]["size_increase_percent"] = stats[contract_name]["smartshield"]["size_increase"] / deployed_bytecode_size * 100
        stats[contract_name]["smartshield"]["benign_success"] = 0
        stats[contract_name]["smartshield"]["benign_failed"] = 0
        stats[contract_name]["smartshield"]["out_of_gas"] = 0
        stats[contract_name]["smartshield"]["attacks_success"] = 0
        stats[contract_name]["smartshield"]["attacks_failed"] = 0
        stats[contract_name]["smartshield"]["gas_increase"] = list()
        stats[contract_name]["smartshield"]["gas_increase_percent"] = list()

        elysium_bytecode = None
        with open(os.path.join(os.path.dirname(path), contract_address+".elysium.bin"), "r") as file:
            elysium_bytecode = file.read().strip()
        elysium_bytecode_size = int(len(elysium_bytecode) / 2)
        stats[contract_name]["elysium"] = dict()
        stats[contract_name]["elysium"]["bytecode_size"] = elysium_bytecode_size
        stats[contract_name]["elysium"]["size_increase"] = elysium_bytecode_size - deployed_bytecode_size
        stats[contract_name]["elysium"]["size_increase_percent"] = stats[contract_name]["elysium"]["size_increase"] / deployed_bytecode_size * 100
        stats[contract_name]["elysium"]["benign_success"] = 0
        stats[contract_name]["elysium"]["benign_failed"] = 0
        stats[contract_name]["elysium"]["out_of_gas"] = 0
        stats[contract_name]["elysium"]["attacks_success"] = 0
        stats[contract_name]["elysium"]["attacks_failed"] = 0
        stats[contract_name]["elysium"]["gas_increase"] = list()
        stats[contract_name]["elysium"]["gas_increase_percent"] = list()

        benign = list()
        with open(os.path.join(os.path.dirname(path), "benign.txt"), "r") as file:
            benign = file.read().splitlines()
            stats[contract_name]["benign"] = len(benign)
        print("Analyzing", len(benign), "benign transactions...")

        results = list()
        if os.path.exists("../results/"+dataset.split("/")[-1]+"/"+contract_name+"-benign.csv"):
            with open("../results/"+dataset.split("/")[-1]+"/"+contract_name+"-benign.csv", "r") as csv_file:
                reader = csv.reader(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                first_row_skipped = False
                for row in reader:
                    if not first_row_skipped:
                        first_row_skipped = True
                    else:
                        row[1] = int(row[1]) if row[1].isdigit() else None

                        if row[2] == '(None, None, None)':
                            row[2] = (None, None, None)
                        else:
                            row[2] = row[2].replace("(", "").replace(")", "").split(", ")
                            row[2] = (True if row[2][0] == "True" else False, int(row[2][1]), row[2][2])

                        if row[3] == '(None, None, None)':
                            row[3] = (None, None, None)
                        else:
                            row[3] = row[3].replace("(", "").replace(")", "").split(", ")
                            row[3] = (True if row[3][0] == "True" else False, int(row[3][1]), row[3][2])

                        if row[4] == '(None, None, None)':
                            row[4] = (None, None, None)
                        else:
                            row[4] = row[4].replace("(", "").replace(")", "").split(", ")
                            row[4] = (True if row[4][0] == "True" else False, int(row[4][1]), row[4][2])
                        results.append(row)

        if len(benign) != len(results):
            missing = list()
            for hash in benign:
                if not hash in [result[0] for result in results]:
                    missing.append(hash)
            if len(missing) > 0:
                with multiprocessing.Pool(processes=multiprocessing.cpu_count(), initializer=init_process, initargs=(contract_address, deployed_bytecode, evmpatch_bytecode, smartshield_bytecode, elysium_bytecode, )) as pool:
                    results += pool.map(replay_transaction, missing)
                    with open("../results/"+dataset.split("/")[-1]+"/"+contract_name+"-benign.csv", "w") as csv_file:
                        writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow(["Transaction Hash", "Original Gas Used", "EVMPatch (Success, Gas Used, Error)", "SmartShield (Success, Gas Used, Error)", "Elysium (Success, Gas Used, Error)"])
                        for result in results:
                            writer.writerow(result)

        for i in tqdm(range(len(results))):
            result = results[i]

            if result[2][0] == True:
                stats[contract_name]["evmpatch"]["benign_success"] += 1
                gas_delta = result[2][1] - result[1]
                if gas_delta > 0:
                    stats[contract_name]["evmpatch"]["gas_increase"].append(gas_delta)
                    stats[contract_name]["evmpatch"]["gas_increase_percent"].append(gas_delta / result[1] * 100)
            elif result[2][2] and "Out of gas" in result[2][2]:
                stats[contract_name]["evmpatch"]["out_of_gas"] += 1
            else:
                print("Error:", result)
                stats[contract_name]["evmpatch"]["benign_failed"] += 1

            if result[3][0] == True:
                stats[contract_name]["smartshield"]["benign_success"] += 1
                gas_delta = result[3][1] - result[1]
                if gas_delta > 0:
                    stats[contract_name]["smartshield"]["gas_increase"].append(gas_delta)
                    stats[contract_name]["smartshield"]["gas_increase_percent"].append(gas_delta / result[1] * 100)
            elif result[3][2] and "Out of gas" in result[3][2]:
                stats[contract_name]["smartshield"]["out_of_gas"] += 1
            else:
                print("Error:", result)
                stats[contract_name]["smartshield"]["benign_failed"] += 1

            if result[4][0] == True:
                stats[contract_name]["elysium"]["benign_success"] += 1
                gas_delta = result[4][1] - result[1]
                if gas_delta > 0:
                    stats[contract_name]["elysium"]["gas_increase"].append(gas_delta)
                    stats[contract_name]["elysium"]["gas_increase_percent"].append(gas_delta / result[1] * 100)
            elif result[4][2] and "Out of gas" in result[4][2]:
                stats[contract_name]["elysium"]["out_of_gas"] += 1
            else:
                print("Error:", result)
                stats[contract_name]["elysium"]["benign_failed"] += 1

        if not stats[contract_name]["evmpatch"]["gas_increase"]:
            stats[contract_name]["evmpatch"]["gas_increase"].append(0.0)
            stats[contract_name]["evmpatch"]["gas_increase_percent"] = 0.0
        if not stats[contract_name]["smartshield"]["gas_increase"]:
            stats[contract_name]["smartshield"]["gas_increase"].append(0.0)
            stats[contract_name]["smartshield"]["gas_increase_percent"] = 0.0
        if not stats[contract_name]["elysium"]["gas_increase"]:
            stats[contract_name]["elysium"]["gas_increase"].append(0.0)
            stats[contract_name]["elysium"]["gas_increase_percent"] = 0.0

        attacks = list()
        with open(os.path.join(os.path.dirname(path), "attacks.txt"), "r") as file:
            attacks = file.read().splitlines()
            stats[contract_name]["attacks"] = len(attacks)
        print("Analyzing", len(attacks), "attacks...")

        results = list()
        if os.path.exists("../results/"+dataset.split("/")[-1]+"/"+contract_name+"-attacks.csv"):
            with open("../results/"+dataset.split("/")[-1]+"/"+contract_name+"-attacks.csv", "r") as csv_file:
                reader = csv.reader(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                first_row_skipped = False
                for row in reader:
                    if not first_row_skipped:
                        first_row_skipped = True
                    else:
                        row[1] = int(row[1])
                        row[2] = row[2].replace("(", "").replace(")", "").split(", ")
                        row[2] = (True if row[2][0] == "True" else False, int(row[2][1]))
                        row[3] = row[3].replace("(", "").replace(")", "").split(", ")
                        row[3] = (True if row[3][0] == "True" else False, int(row[3][1]))
                        row[4] = row[4].replace("(", "").replace(")", "").split(", ")
                        row[4] = (True if row[4][0] == "True" else False, int(row[4][1]))
                        results.append(row)
        else:
            with multiprocessing.Pool(processes=multiprocessing.cpu_count(), initializer=init_process, initargs=(contract_address, deployed_bytecode, evmpatch_bytecode, smartshield_bytecode, elysium_bytecode, )) as pool:
                results = pool.map(replay_transaction, attacks)
                with open("../results/"+dataset.split("/")[-1]+"/"+contract_name+"-attacks.csv", "w") as csv_file:
                    writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    writer.writerow(["Transaction Hash", "Original Gas Used", "EVMPatch (Success, Gas used)", "SmartShield (Success, Gas used)", "Elysium (Success, Gas used)"])
                    for result in results:
                        writer.writerow(result)
        for i in tqdm(range(len(results))):
            result = results[i]
            if result[2][0] == True:
                stats[contract_name]["evmpatch"]["attacks_success"] += 1
            else:
                stats[contract_name]["evmpatch"]["attacks_failed"] += 1
            if result[3][0] == True:
                stats[contract_name]["smartshield"]["attacks_success"] += 1
            else:
                stats[contract_name]["smartshield"]["attacks_failed"] += 1
            if result[4][0] == True:
                stats[contract_name]["elysium"]["attacks_success"] += 1
            else:
                stats[contract_name]["elysium"]["attacks_failed"] += 1

        transactions = attacks + benign
        stats[contract_name]["transactions"] = len(transactions)

    for contract in stats:
        stats[contract]["evmpatch"]["gas_increase"] = np.mean(stats[contract]["evmpatch"]["gas_increase"])
        stats[contract]["smartshield"]["gas_increase"] = np.mean(stats[contract]["smartshield"]["gas_increase"])
        stats[contract]["elysium"]["gas_increase"] = np.mean(stats[contract]["elysium"]["gas_increase"])
        stats[contract]["evmpatch"]["gas_increase_percent"] = np.mean(stats[contract]["evmpatch"]["gas_increase_percent"])
        stats[contract]["smartshield"]["gas_increase_percent"] = np.mean(stats[contract]["smartshield"]["gas_increase_percent"])
        stats[contract]["elysium"]["gas_increase_percent"] = np.mean(stats[contract]["elysium"]["gas_increase_percent"])

    # Write dataset stats to disk
    with open("../results/"+dataset.split("/")[-1]+"/"+dataset.split("/")[-1]+"-results.json", "w") as json_file:
        json.dump(stats, json_file, indent=4)

    print()
    print("         | Transactions | Benign \t \t \t \t \t| Attacks \t \t \t \t \t| Deployment Cost Increase (Bytes) \t \t| Benign Transaction Overhead (Gas)")
    print("Contract | Total        | EVMPatch \t SmartShield \t Elysium \t| EVMPatch \t SmartShield \t Elysium \t| EVMPatch \t SmartShield \t Elysium \t| EVMPatch \t SmartShield \t Elysium")
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    for contract in stats:
        print(
            contract, "\t |",
            str(stats[contract]["transactions"])+" \t|" if stats[contract]["transactions"] > 9999 else str(stats[contract]["transactions"])+"\t \t|",

            str(stats[contract]["evmpatch"]["benign_success"]+stats[contract]["evmpatch"]["out_of_gas"])+"/"+str(stats[contract]["benign"]), "\t",
            str(stats[contract]["smartshield"]["benign_success"]+stats[contract]["smartshield"]["out_of_gas"])+"/"+str(stats[contract]["benign"]), "\t",
            str(stats[contract]["elysium"]["benign_success"]+stats[contract]["elysium"]["out_of_gas"])+"/"+str(stats[contract]["benign"]), "\t|",

            str(stats[contract]["evmpatch"]["attacks_failed"])+"/"+str(stats[contract]["attacks"]),
            "\t" if len(str(stats[contract]["evmpatch"]["attacks_failed"])+"/"+str(stats[contract]["attacks"])) > 4 else "\t \t",
            str(stats[contract]["smartshield"]["attacks_failed"])+"/"+str(stats[contract]["attacks"]), "\t \t",
            str(stats[contract]["elysium"]["attacks_failed"])+"/"+str(stats[contract]["attacks"]), "\t \t|",

            str(stats[contract]["evmpatch"]["size_increase"])+" ("+'{0:.2f}'.format(stats[contract]["evmpatch"]["size_increase_percent"])+"%) " if stats[contract]["evmpatch"]["size_increase"] > 999 else str(stats[contract]["evmpatch"]["size_increase"])+" ("+'{0:.2f}'.format(stats[contract]["evmpatch"]["size_increase_percent"])+"%) \t",
            stats[contract]["smartshield"]["size_increase"], "("+'{0:.2f}'.format(stats[contract]["smartshield"]["size_increase_percent"])+"%)", "\t",
            stats[contract]["elysium"]["size_increase"], "("+'{0:.2f}'.format(stats[contract]["elysium"]["size_increase_percent"])+"%)", "\t|",

            '{0:.0f}'.format(stats[contract]["evmpatch"]["gas_increase"]), "("+'{0:.2f}'.format(stats[contract]["evmpatch"]["gas_increase_percent"])+"%)", "\t",
            '{0:.0f}'.format(stats[contract]["smartshield"]["gas_increase"]), "("+'{0:.2f}'.format(stats[contract]["smartshield"]["gas_increase_percent"])+"%)", "\t",
            '{0:.0f}'.format(stats[contract]["elysium"]["gas_increase"]), "("+'{0:.2f}'.format(stats[contract]["elysium"]["gas_increase_percent"])+"%)"
        )
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

if __name__ == "__main__":
    main()
