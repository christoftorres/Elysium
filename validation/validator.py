#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import argparse

from web3 import Web3
from eth_utils import decode_hex, to_canonical_address

from utils.settings import *
from emulator import Emulator

def main():
    global args

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-b", "--bytecode", type=str, help="Bytecode file of patched contract")
    parser.add_argument(
        "-t", "--transaction", type=str, help="Transaction hash or list of transactions to be validated")
    parser.add_argument(
        "-a", "--address", type=str, help="Address of patched contract")

    parser.add_argument(
        "-v", "--version", action="version", version="Tester 0.0.1")
    args = parser.parse_args()

    patched_bytecode = None
    if not args.bytecode:
        print("Warning: Bytecode file of patched contract not provided!")
        print("Executing original transaction only!")
    else:
        with open(args.bytecode) as f:
            patched_bytecode = f.read().strip("\n").replace("0x", "")

    if not args.transaction:
        print("Error: Transaction hash file to be tested not provided!")
        sys.exit(-1)

    if not args.address:
        print("Error: Address of patched contract not provided!")
        sys.exit(-2)

    w3 = Web3(PROVIDER)

    print(w3.eth.getCode(to_canonical_address(args.address)).hex())

    transactions = list()
    if args.transaction.startswith("0x"):
        transactions.append(args.transaction)
    else:
        with open(args.transaction, "r") as f:
            transactions = f.read().splitlines()

    success, failure = 0, 0
    for transaction_hash in transactions:
        start = time.time()
        print("Testing transaction:", transaction_hash)
        print()
        transaction = w3.eth.getTransaction(transaction_hash)
        block = w3.eth.getBlock(transaction["blockNumber"], True)

        emu = Emulator(PROVIDER, block)
        result_original, execution_trace_original, balance_original = emu.send_transaction(transaction)

        for instruction in execution_trace_original:
            #if instruction["opcode"] == "SHA3":
            #    print("address:", instruction["storage_address"], instruction["opcode"], hex(instruction["pc"]), "offset:", int(instruction["stack"][-1], 16), "size:", int(instruction["stack"][-2], 16), "memory:", instruction["memory"])
            if instruction["opcode"] == "SSTORE":
                print("address:", instruction["storage_address"], instruction["opcode"], hex(instruction["pc"]), "index:", instruction["stack"][-1], "value:", instruction["stack"][-2])

        print("================ Original ================")
        print("Last 20 executed instructions:")
        for i in range(len(execution_trace_original)-20, len(execution_trace_original)):
            ins = execution_trace_original[i]
            print("\t", ins["opcode"])
        print("Number of executed instructions:", len(execution_trace_original))
        print("Success:",result_original.is_success)
        print("Error:", result_original.is_error)
        if result_original.is_error:
            print("Error message:", str(result_original.error))
        print("Logs:")
        for log in result_original.get_log_entries():
            print("\t", "Address:", "0x"+log[0].hex())
            print("\t", "Topics:")
            for topic in log[1]:
                print("\t \t", hex(topic))
            print("\t", "Data:", "0x"+log[2].hex())
            print()
        print("Return data:", "0x"+result_original.return_data.hex())
        print("Output:", "0x"+result_original.output.hex())
        print("Sender balance:", Web3.fromWei(balance_original, 'ether'), "ETH")
        print()

        if args.bytecode:
            emu = Emulator(PROVIDER, block)
            result_patched, execution_trace_patched, balance_patched = emu.send_transaction(transaction, code={to_canonical_address(args.address): decode_hex(patched_bytecode)})

            print("================ Patched ================")
            print("Last 20 executed instructions:")
            for i in range(len(execution_trace_patched)-20, len(execution_trace_patched)):
                ins = execution_trace_patched[i]
                print("\t", ins["opcode"])
            print("Number of executed instructions:", len(execution_trace_patched))
            print("Success:",result_patched.is_success)
            print("Error:", result_patched.is_error)
            if result_patched.is_error:
                print("Error message:", str(result_patched.error))
            print("Logs:")
            for log in result_patched.get_log_entries():
                print("\t", "Address:", "0x"+log[0].hex())
                print("\t", "Topics:")
                for topic in log[1]:
                    print("\t \t", hex(topic))
                print("\t", "Data:", "0x"+log[2].hex())
                print()
            print("Return data:", "0x"+result_patched.return_data.hex())
            print("Output:", "0x"+result_patched.output.hex())
            print("Sender balance:", Web3.fromWei(balance_patched, 'ether'), "ETH")
            print()

            if  result_original.is_success == result_patched.is_success and \
                result_original.is_error == result_patched.is_error and \
                result_original.get_log_entries() == result_patched.get_log_entries() and \
                result_original.return_data == result_patched.return_data and \
                result_original.output == result_patched.output and \
                balance_original >= balance_patched:
                if result_original.is_error == True and result_patched.is_error == True:
                    if result_original.error == result_patched.error:
                        success += 1
                        print("\033[92mSuccess: Patched execution is identical to the original one.\033[0m")
                    else:
                        print("Error original:", result_original.error)
                        print("Error patched:", result_patched.error)
                        print("\033[1m\033[91mWarning: Patched execution is different to the original one.\033[0m")
                        print("\033[1m\033[91mThis can be due to an attack, a reported false positive, or an issue with the patching.\033[0m")
                else:
                    success += 1
                    print("\033[92mSuccess: Patched execution is identical to the original one.\033[0m")
            elif result_patched.is_error == True and str(result_patched.error).startswith("Out of gas"):
                failure += 1
                print("\033[1m\033[91mWarning: Patched execution is different to the original one because the execution ran out of gas!\033[0m")
                print("\033[1m\033[91m"+str(result_patched.error)+".\033[0m")
            else:
                failure += 1
                print("\033[1m\033[91mWarning: Patched execution is different to the original one.\033[0m")
                print("\033[1m\033[91mThis can be due to an attack, a reported false positive, or an issue with the patching.\033[0m")

            print("Gas used by original transaction:", result_original.get_gas_used())
            print("Gas used by patched transaction:", result_patched.get_gas_used())

            print("Execution time:", time.time() - start, "seconds")

    if args.bytecode:
        print("Successful executions:", success, "-", "Failed executions:", failure)

if __name__ == '__main__':
    main()
