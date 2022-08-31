#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import copy
import json
import collections

def print_stack(stack):
    string = "Stack: ["
    for element in stack:
        string += " " + str(element) + " "
    string += "]"
    print(string)

def print_tainted_stack(stack):
    string = "Tainted Stack: ["
    for element in stack:
        if not isinstance(element, list):
            string += " " + str(element) + " "
        else:
            string += " ["
            for taint in element:
                string += " " + str(taint) + " "
            string += "] "
    string += "]"
    print(string)

def print_memory(memory):
    string = "Memory: {"
    for address in memory:
        string += " " + str(address) + ": " + str(memory[address]) + " "
    string += "}"
    print(string)

def print_tainted_memory(memory):
    string = "Tainted Memory: {"
    for address in memory:
        string += " " + str(address) + ": "
        if not isinstance(memory[address], list):
            string += " " + str(memory[address]) + " "
        else:
            string += " ["
            for taint in memory[address]:
                string += " " + str(taint) + " "
            string += "] "
    string += "}"
    print(string)

def print_storage(storage):
    string = "Storage: {"
    for index in storage:
        string += " " + str(index) + ": " + str(storage[index]) + " "
    string += "}"
    print(string)

def print_tainted_storage(storage):
    string = "Tainted Storage: {"
    for index in storage:
        string += " " + str(index) + ": "
        if not isinstance(storage[index], list):
            string += " " + str(storage[index]) + " "
        else:
            string += " ["
            for taint in storage[index]:
                string += " " + str(taint) + " "
            string += "] "
    string += "}"
    print(string)

class TaintRecord:
    def __init__(self):
        """ Builds a taint record """
        # Machine and world state
        self.stack = list()
        self.memory = dict()
        self.storage = dict()

        # Tainted state
        self.tainted_stack = list()
        self.tainted_memory = dict()
        self.tainted_storage = dict()

    def __str__(self):
        return json.dumps(self.__dict__)

    def clone(self):
        """ Clones this record"""
        clone = TaintRecord()
        clone.stack = copy.copy(self.stack)
        clone.memory = copy.copy(self.memory)
        clone.storage = copy.copy(self.storage)
        clone.tainted_stack = copy.copy(self.tainted_stack)
        clone.tainted_memory = copy.copy(self.tainted_memory)
        clone.tainted_storage = copy.copy(self.tainted_storage)
        return clone

class TaintRunner:
    def __init__(self, debug=False):
        self.debug = debug
        self.execution_trace = list()
        self.storage = dict()

    def introduce_taint(self, taint, instruction):
        if self.debug:
            if isinstance(instruction.pc, int):
                print(hex(instruction.pc), instruction.mnemonic)
            else:
                print(hex(instruction.pc[0]), instruction.mnemonic)
        mutator = TaintRunner.stack_taint_table[instruction.mnemonic]
        if len(self.execution_trace) == 0:
            execution = TaintRecord()
        else:
            execution = self.execution_trace[-1]
        if instruction.mnemonic.startswith("PUSH"):
            execution.stack.append(instruction.operand)
            execution.tainted_stack.append([taint])
        else:
            stack_elements = list()
            tainted_elements = list()
            for _ in range(mutator[0]):
                if len(execution.stack) > 0:
                    stack_element = execution.stack.pop()
                    if stack_element != None:
                        stack_elements.append(stack_element)
                if len(execution.tainted_stack) > 0:
                    tainted_element = execution.tainted_stack.pop()
                    if isinstance(tainted_element, list):
                        tainted_elements += tainted_element
            tainted_elements.append(taint)
            for _ in range(mutator[1]):
                if len(stack_elements) == 1:
                    execution.stack.append(stack_elements[0])
                else:
                    execution.stack.append(None)
                execution.tainted_stack.append(tainted_elements)
        self.execution_trace.append(execution)
        if self.debug:
            print_stack(execution.stack)
            print_tainted_stack(execution.tainted_stack)
            if instruction.mnemonic in ["MLOAD", "MSTORE", "SHA3"]:
                print("----------------------------------------------------")
                print_memory(execution.memory)
                print_tainted_memory(execution.tainted_memory)
                print("----------------------------------------------------")
            elif instruction.mnemonic in ["SLOAD", "SSTORE"]:
                print("----------------------------------------------------")
                print_storage(execution.storage)
                print_tainted_storage(execution.tainted_storage)
                print("----------------------------------------------------")

    def propagate_taint(self, instruction):
        if self.debug:
            if isinstance(instruction.pc, int):
                print(hex(instruction.pc), instruction.mnemonic)
            else:
                print(hex(instruction.pc[0]), instruction.mnemonic)
        if len(self.execution_trace) != 0:
            try:
                execution = TaintRunner.execute(self.execution_trace[-1], self.storage, instruction)
                if self.debug:
                    print_stack(execution.stack)
                    print_tainted_stack(execution.tainted_stack)
                    if instruction.mnemonic in ["MLOAD", "MSTORE", "SHA3"]:
                        print("----------------------------------------------------")
                        print_memory(execution.memory)
                        print_tainted_memory(execution.tainted_memory)
                        print("----------------------------------------------------")
                    elif instruction.mnemonic in ["SLOAD", "SSTORE"]:
                        print("----------------------------------------------------")
                        print_storage(execution.storage)
                        print_tainted_storage(execution.tainted_storage)
                        print("----------------------------------------------------")
                self.execution_trace.append(execution)
            except:
                pass

    def check_taint(self, instruction):
        if self.debug:
            if isinstance(instruction.pc, int):
                print(hex(instruction.pc), instruction.mnemonic)
            else:
                print(hex(instruction.pc[0]), instruction.mnemonic)
        stack_values, tainted_values = list(), list()
        execution = self.execution_trace[-1]
        if self.debug:
            print_stack(execution.stack)
            print_tainted_stack(execution.tainted_stack)
            if instruction.mnemonic in ["MLOAD", "MSTORE", "SHA3"]:
                print("----------------------------------------------------")
                print_memory(execution.memory)
                print_tainted_memory(execution.tainted_memory)
                print("----------------------------------------------------")
            elif instruction.mnemonic in ["SLOAD", "SSTORE"]:
                print("----------------------------------------------------")
                print_storage(execution.storage)
                print_tainted_storage(execution.tainted_storage)
                print("----------------------------------------------------")
        mutator = TaintRunner.stack_taint_table[instruction.mnemonic]
        for i in range(1, mutator[0] + 1):
            if i <= len(execution.stack):
                stack_values.append(execution.stack[-i])
            if i <= len(execution.tainted_stack):
                if execution.tainted_stack[-i] != None:
                    tainted_values += execution.tainted_stack[-i]
                else:
                    tainted_values.append(None)
        return tainted_values, stack_values

    def clear_machine_state(self):
        self.call_stack = []

    @staticmethod
    def execute(record, storage, instruction):
        new_record = record.clone()

        op = instruction.mnemonic
        if op.startswith("DUP"):
            TaintRunner.mutate_dup(new_record, op)
        elif op.startswith("SWAP"):
            TaintRunner.mutate_swap(new_record, op)
        elif op == "MLOAD":
            TaintRunner.mutate_mload(new_record, instruction)
        elif op.startswith("MSTORE"):
            TaintRunner.mutate_mstore(new_record, instruction)
        elif op == "SLOAD":
            TaintRunner.mutate_sload(new_record, storage, instruction)
        elif op == "SSTORE":
            TaintRunner.mutate_sstore(new_record, storage, instruction)
        elif op.startswith("LOG"):
            TaintRunner.mutate_log(new_record, op)
        elif op == "SHA3":
            TaintRunner.mutate_sha3(new_record, instruction)
        elif op == "CALLVALUE":
            TaintRunner.mutate_call_value(new_record, instruction)
        elif op == "CALLDATALOAD":
            TaintRunner.mutate_call_data_load(new_record, instruction)
        elif op in ("CALLDATACOPY", "CODECOPY", "RETURNDATACOPY", "EXTCODECOPY"):
            TaintRunner.mutate_copy(new_record, op, instruction)
        elif op in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            TaintRunner.mutate_call(new_record, op, instruction)
        elif op in TaintRunner.stack_taint_table.keys():
            TaintRunner.mutate_stack(new_record, instruction)
        else:
            print("Unknown operation encountered: {}".format(op))

        return new_record

    @staticmethod
    def to_unsigned(number):
        if number < 0:
            return number + 2 ** 256
        return number

    @staticmethod
    def to_signed(number):
        if number > 2**(256 - 1):
            return (2**(256) - number) * (-1)
        else:
            return number

    @staticmethod
    def mutate_stack(record, instruction):
        if instruction.mnemonic.startswith("PUSH"):
            execution.stack.append(instruction.operand)
        else:
            mutator = TaintRunner.stack_taint_table[instruction.mnemonic]
            taint = None
            stack_values = list()
            stack_undeflow = False
            for _ in range(mutator[0]):
                try:
                    stack_values.append(record.stack.pop())
                    values = record.tainted_stack.pop()
                    if values:
                        if taint == None:
                            taint = list()
                        for i in range(len(values)):
                            if not values[i] in taint:
                                taint.append(values[i])
                except IndexError:
                    stack_undeflow = True
                    pass
            for _ in range(mutator[1]):
                if len(stack_values) == 0 or stack_undeflow:
                    record.stack.append(None)
                elif None in stack_values:
                    concrete_values = [value for value in stack_values if value != None]
                    if concrete_values:
                        if len(concrete_values) == 1:
                            record.stack.append(concrete_values[0])
                        else:
                            record.stack.append(concrete_values)
                    else:
                        record.stack.append(None)
                else:
                    if   instruction.mnemonic == "ADD":
                        record.stack.append((stack_values[0] + stack_values[1]) % (2 ** 256))
                    elif instruction.mnemonic == "MUL":
                        record.stack.append((stack_values[0] * stack_values[1]) & (2 ** 256 - 1))
                    elif instruction.mnemonic == "SUB":
                        record.stack.append((stack_values[0] - stack_values[1]) % (2 ** 256))
                    elif instruction.mnemonic == "DIV":
                        record.stack.append(0) if stack_values[1] == 0 else record.stack.append(int(TaintRunner.to_unsigned(stack_values[0]) / TaintRunner.to_unsigned(stack_values[1])))
                    elif instruction.mnemonic == "SDIV":
                        if stack_values[1] == 0:
                            record.stack.append(0)
                        elif stack_values[0] == -2 ** 255 and stack_values[1] == -1:
                            record.stack.append(-2 ** 255)
                        else:
                            sign = -1 if (stack_values[0] / stack_values[1]) < 0 else 1
                            record.stack.append(int(sign * (abs(stack_values[0]) / abs(stack_values[1]))))
                    elif instruction.mnemonic == "MOD":
                        record.stack.append(0) if stack_values[1] == 0 else record.stack.append((TaintRunner.to_unsigned(stack_values[0]) % TaintRunner.to_unsigned(stack_values[1])) & (2 ** 256 - 1))
                    elif instruction.mnemonic == "SMOD":
                        if stack_values[1] == 0:
                            record.stack.append(0)
                        else:
                            sign = -1 if to_signed(first) < 0 else 1
                            record.stack.append(sign * (abs(TaintRunner.to_signed(first)) % abs(TaintRunner.to_signed(second))))
                    elif instruction.mnemonic == "ADDMOD":
                        record.stack.append(0) if stack_values[2] == 0 else record.stack.append((stack_values[0] + stack_values[1]) % stack_values[2])
                    elif instruction.mnemonic == "MULMOD":
                        record.stack.append(0) if stack_values[2] == 0 else record.stack.append((stack_values[0] * stack_values[1]) % stack_values[2])
                    elif instruction.mnemonic == "EXP":
                        record.stack.append(pow(stack_values[0], stack_values[1], 2 ** 256))
                    elif instruction.mnemonic == "LT" or instruction.mnemonic == "SLT":
                        record.stack.append(1) if stack_values[0] < stack_values[1] else record.stack.append(0)
                    elif instruction.mnemonic == "GT" or instruction.mnemonic == "SGT":
                        record.stack.append(1) if stack_values[0] > stack_values[1] else record.stack.append(0)
                    elif instruction.mnemonic == "EQ":
                        record.stack.append(1) if stack_values[0] == stack_values[1] else record.stack.append(0)
                    elif instruction.mnemonic == "ISZERO":
                        record.stack.append(1) if stack_values[0] == 0 else record.stack.append(0)
                    elif instruction.mnemonic == "AND":
                        record.stack.append(stack_values[0] & stack_values[1])
                    elif instruction.mnemonic == "OR":
                        record.stack.append(stack_values[0] | stack_values[1])
                    elif instruction.mnemonic == "XOR":
                        record.stack.append(stack_values[0] ^ stack_values[1])
                    elif instruction.mnemonic == "NOT":
                        record.stack.append((~stack_values[0]) & (2 ** 256 - 1))
                    elif instruction.mnemonic == "SHL":
                        record.stack.append(0) if stack_values[0] >= 256 else record.stack.append((stack_values[1] << stack_values[0]) & (2 ** 256 - 1))
                    elif instruction.mnemonic == "SHR":
                        record.stack.append(0) if stack_values[0] >= 256 else record.stack.append((stack_values[1] >> stack_values[0]) & (2 ** 256 - 1))
                    else:
                        record.stack.append(None)
                record.tainted_stack.append(taint)

    @staticmethod
    def mutate_dup(record, op):
        depth = int(op[3:])
        elements = depth - len(record.stack)
        for i in range(elements):
            record.stack.insert(0, None)
            record.tainted_stack.insert(0, None)
        index = len(record.stack) - depth
        record.stack.append(record.stack[index])
        record.tainted_stack.append(record.tainted_stack[index])

    @staticmethod
    def mutate_swap(record, op):
        depth = int(op[4:])
        while depth + 1 > len(record.stack):
            record.stack.insert(0, None)
            record.tainted_stack.insert(0, None)
        l = len(record.stack) - 1
        i = l - depth
        record.stack[l], record.stack[i] = record.stack[i], record.stack[l]
        record.tainted_stack[l], record.tainted_stack[i] = record.tainted_stack[i], record.tainted_stack[l]

    @staticmethod
    def mutate_mload(record, instruction):
        index = record.stack.pop()
        record.tainted_stack.pop()
        try:
            record.stack.append(record.memory[index])
            record.tainted_stack.append(record.tainted_memory[index])
        except:
            record.stack.append(None)
            record.tainted_stack.append(None)

    @staticmethod
    def mutate_mstore(record, instruction):
        index = record.stack.pop()
        record.tainted_stack.pop()
        record.memory[index] = record.stack.pop()
        record.tainted_memory[index] = record.tainted_stack.pop()

    @staticmethod
    def mutate_sload(record, storage, instruction):
        index = record.stack.pop()
        record.tainted_stack.pop()
        try:
            record.stack.append(record.storage[index])
            record.tainted_stack.append(record.tainted_storage[index])
        except:
            record.stack.append(None)
            record.tainted_stack.append(None)

    @staticmethod
    def mutate_sstore(record, storage, instruction):
        index = record.stack.pop()
        record.tainted_stack.pop()
        record.storage[index] = record.stack.pop()
        record.tainted_storage[index] = record.tainted_stack.pop()

    @staticmethod
    def mutate_log(record, op):
        depth = int(op[3:])
        for _ in range(depth + 2):
            record.stack.pop()
            record.tainted_stack.pop()

    @staticmethod
    def mutate_sha3(record, instruction):
        offset = record.stack.pop()
        size = record.stack.pop()
        record.tainted_stack.pop()
        record.tainted_stack.pop()
        taint = list()
        if offset != None and size != None:
            for index in record.tainted_memory:
                if index != None and index >= offset and index < size and index >= size-32:
                    if record.tainted_memory[index] != None:
                        taint += record.tainted_memory[index]
                        break
        if taint:
            record.stack.append(None)
            record.tainted_stack.append(taint)
        else:
            record.stack.append(None)
            record.tainted_stack.append(None)

    @staticmethod
    def mutate_call_data_load(record, instruction):
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.append(None)
        record.tainted_stack.append(None)

    @staticmethod
    def mutate_call_value(record, instruction):
        record.stack.append(None)
        record.tainted_stack.append(None)

    @staticmethod
    def mutate_copy(record, op, instruction):
        if op == "EXTCODECOPY":
            record.stack.pop()
            record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()

    @staticmethod
    def mutate_create(record, instruction):
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.append(None)
        record.tainted_stack.append(None)

    @staticmethod
    def mutate_call(record, op, instruction):
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()
        if op in ["CALL", "CALLCODE"]:
            record.stack.pop()
            record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.pop()
        record.tainted_stack.pop()
        record.stack.append(None)
        record.tainted_stack.append(None)

    stack_taint_table = {
        # instruction: (taint source, taint target)
        # 0s: Stop and Arithmetic Operations
        'STOP': (0, 0),
        'ADD': (2, 1),
        'MUL': (2, 1),
        'SUB': (2, 1),
        'DIV': (2, 1),
        'SDIV': (2, 1),
        'MOD': (2, 1),
        'SMOD': (2, 1),
        'ADDMOD': (3, 1),
        'MULMOD': (3, 1),
        'EXP': (2, 1),
        'SIGNEXTEND': (2, 1),
        # 10s: Comparison & Bitwise Logic Operations
        'LT': (2, 1),
        'GT': (2, 1),
        'SLT': (2, 1),
        'SGT': (2, 1),
        'EQ': (2, 1),
        'ISZERO': (1, 1),
        'AND': (2, 1),
        'OR': (2, 1),
        'XOR': (2, 1),
        'NOT': (1, 1),
        'BYTE': (2, 1),
        'SHL': (2, 1),
        'SHR': (2, 1),
        'SAR': (2, 1),
        # 20s: SHA3
        'SHA3': (2, 1),
        # 30s: Environmental Information
        'ADDRESS': (0, 1),
        'BALANCE': (1, 1),
        'ORIGIN': (0, 1),
        'CALLER': (0, 1),
        'CALLVALUE': (0, 1),
        'CALLDATALOAD': (1, 1),
        'CALLDATASIZE': (0, 1),
        'CALLDATACOPY': (3, 0),
        'CODESIZE': (0, 1),
        'CODECOPY': (3, 0),
        'GASPRICE': (0, 1),
        'EXTCODESIZE': (1, 1),
        'EXTCODECOPY': (4, 0),
        'RETURNDATASIZE': (0, 1),
        'RETURNDATACOPY': (3, 0),
        'EXTCODEHASH': (1, 1),
        # 40s: Block Information
        'BLOCKHASH': (1, 1),
        'COINBASE': (0, 1),
        'TIMESTAMP': (0, 1),
        'NUMBER': (0, 1),
        'DIFFICULTY': (0, 1),
        'GASLIMIT': (0, 1),
        'CHAINID': (0, 1),
        'SELFBALANCE': (0, 1),
        # 50s: Stack, Memory, Storage and Flow Operations
        'POP': (1, 0),
        'MLOAD': (1, 1),
        'MSTORE': (2, 0),
        'MSTORE8': (2, 0),
        'SLOAD': (1, 1),
        'SSTORE': (2, 0),
        'JUMP': (1, 0),
        'JUMPI': (2, 0),
        'PC': (0, 1),
        'MSIZE': (0, 1),
        'GAS': (0, 1),
        'JUMPDEST': (0, 0),
        # 60s & 70s: Push Operations
        'PUSH1': (0, 1),
        'PUSH2': (0, 1),
        'PUSH3': (0, 1),
        'PUSH4': (0, 1),
        'PUSH5': (0, 1),
        'PUSH6': (0, 1),
        'PUSH7': (0, 1),
        'PUSH8': (0, 1),
        'PUSH9': (0, 1),
        'PUSH10': (0, 1),
        'PUSH11': (0, 1),
        'PUSH12': (0, 1),
        'PUSH13': (0, 1),
        'PUSH14': (0, 1),
        'PUSH15': (0, 1),
        'PUSH16': (0, 1),
        'PUSH17': (0, 1),
        'PUSH18': (0, 1),
        'PUSH19': (0, 1),
        'PUSH20': (0, 1),
        'PUSH21': (0, 1),
        'PUSH22': (0, 1),
        'PUSH23': (0, 1),
        'PUSH24': (0, 1),
        'PUSH25': (0, 1),
        'PUSH26': (0, 1),
        'PUSH27': (0, 1),
        'PUSH28': (0, 1),
        'PUSH29': (0, 1),
        'PUSH30': (0, 1),
        'PUSH31': (0, 1),
        'PUSH32': (0, 1),
        # 80s: Duplication Operations
        'DUP1': (1, 2),
        'DUP2': (2, 3),
        'DUP3': (3, 4),
        'DUP4': (4, 5),
        'DUP5': (5, 6),
        'DUP6': (6, 7),
        'DUP7': (7, 8),
        'DUP8': (8, 9),
        'DUP9': (9, 10),
        'DUP10': (10, 11),
        'DUP11': (11, 12),
        'DUP12': (12, 13),
        'DUP13': (13, 14),
        'DUP14': (14, 15),
        'DUP15': (15, 16),
        'DUP16': (16, 17),
        # 90s: Exchange Operations
        'SWAP1': (2, 2),
        'SWAP2': (3, 3),
        'SWAP3': (4, 4),
        'SWAP4': (5, 5),
        'SWAP5': (6, 6),
        'SWAP6': (7, 7),
        'SWAP7': (8, 8),
        'SWAP8': (9, 9),
        'SWAP9': (10, 10),
        'SWAP10': (11, 11),
        'SWAP11': (12, 12),
        'SWAP12': (13, 13),
        'SWAP13': (14, 14),
        'SWAP14': (15, 15),
        'SWAP15': (16, 16),
        'SWAP16': (17, 17),
        # a0s: Logging Operations
        'LOG0': (2, 0),
        'LOG1': (3, 0),
        'LOG2': (4, 0),
        'LOG3': (5, 0),
        'LOG4': (6, 0),
        # f0s: System Operations
        'CREATE': (3, 1),
        'CREATE2': (4, 1),
        'CALL': (7, 1),
        'CALLCODE': (7, 1),
        'RETURN': (2, 0),
        'DELEGATECALL': (6, 1),
        'STATICCALL': (6, 1),
        'REVERT': (2, 0),
        'INVALID': (0, 0),
        'SELFDESTRUCT': (1, 0)
    }
