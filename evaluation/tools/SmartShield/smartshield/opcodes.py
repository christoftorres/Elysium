# schema: [opcode, ins, outs, gas]

listing = {
    0x00: ['STOP', 0, 0, 0],
    0x01: ['ADD', 2, 1, 3],
    0x02: ['MUL', 2, 1, 5],
    0x03: ['SUB', 2, 1, 3],
    0x04: ['DIV', 2, 1, 5],
    0x05: ['SDIV', 2, 1, 5],
    0x06: ['MOD', 2, 1, 5],
    0x07: ['SMOD', 2, 1, 5],
    0x08: ['ADDMOD', 3, 1, 8],
    0x09: ['MULMOD', 3, 1, 8],
    0x0a: ['EXP', 2, 1, 10],
    0x0b: ['SIGNEXTEND', 2, 1, 5],
    0x10: ['LT', 2, 1, 3],
    0x11: ['GT', 2, 1, 3],
    0x12: ['SLT', 2, 1, 3],
    0x13: ['SGT', 2, 1, 3],
    0x14: ['EQ', 2, 1, 3],
    0x15: ['ISZERO', 1, 1, 3],
    0x16: ['AND', 2, 1, 3],
    0x17: ['OR', 2, 1, 3],
    0x18: ['XOR', 2, 1, 3],
    0x19: ['NOT', 1, 1, 3],
    0x1a: ['BYTE', 2, 1, 3],
    0x20: ['SHA3', 2, 1, 30],
    0x30: ['ADDRESS', 0, 1, 2],
    0x31: ['BALANCE', 1, 1, 20],  # now 400
    0x32: ['ORIGIN', 0, 1, 2],
    0x33: ['CALLER', 0, 1, 2],
    0x34: ['CALLVALUE', 0, 1, 2],
    0x35: ['CALLDATALOAD', 1, 1, 3],
    0x36: ['CALLDATASIZE', 0, 1, 2],
    0x37: ['CALLDATACOPY', 3, 0, 3],
    0x38: ['CODESIZE', 0, 1, 2],
    0x39: ['CODECOPY', 3, 0, 3],
    0x3a: ['GASPRICE', 0, 1, 2],
    0x3b: ['EXTCODESIZE', 1, 1, 20],  # now 700
    0x3c: ['EXTCODECOPY', 4, 0, 20],  # now 700
    0x3d: ['RETURNDATASIZE', 0, 1, 2],
    0x3e: ['RETURNDATACOPY', 3, 0, 3],
    0x40: ['BLOCKHASH', 1, 1, 20],
    0x41: ['COINBASE', 0, 1, 2],
    0x42: ['TIMESTAMP', 0, 1, 2],
    0x43: ['NUMBER', 0, 1, 2],
    0x44: ['DIFFICULTY', 0, 1, 2],
    0x45: ['GASLIMIT', 0, 1, 2],
    0x50: ['POP', 1, 0, 2],
    0x51: ['MLOAD', 1, 1, 3],
    0x52: ['MSTORE', 2, 0, 3],
    0x53: ['MSTORE8', 2, 0, 3],
    0x54: ['SLOAD', 1, 1, 50],  # 200 now
    # actual cost 5000-20000 depending on circumstance
    0x55: ['SSTORE', 2, 0, 0],
    0x56: ['JUMP', 1, 0, 8],
    0x57: ['JUMPI', 2, 0, 10],
    0x58: ['PC', 0, 1, 2],
    0x59: ['MSIZE', 0, 1, 2],
    0x5a: ['GAS', 0, 1, 2],
    0x5b: ['JUMPDEST', 0, 0, 1],
    0xa0: ['LOG0', 2, 0, 375],
    0xa1: ['LOG1', 3, 0, 750],
    0xa2: ['LOG2', 4, 0, 1125],
    0xa3: ['LOG3', 5, 0, 1500],
    0xa4: ['LOG4', 6, 0, 1875],
    # 0xe1: ['SLOADBYTES', 3, 0, 50], # to be discontinued
    # 0xe2: ['SSTOREBYTES', 3, 0, 0], # to be discontinued
    # 0xe3: ['SSIZE', 1, 1, 50], # to be discontinued
    0xf0: ['CREATE', 3, 1, 32000],
    0xf1: ['CALL', 7, 1, 40],  # 700 now
    0xf2: ['CALLCODE', 7, 1, 40],  # 700 now
    0xf3: ['RETURN', 2, 0, 0],
    0xf4: ['DELEGATECALL', 6, 1, 40],  # 700 now
    0xf5: ['CALLBLACKBOX', 7, 1, 40],
    0xfa: ['STATICCALL', 6, 1, 40],
    0xfd: ['REVERT', 2, 0, 0],
    0xff: ['SUICIDE', 1, 0, 0],  # 5000 now
}

for i in range(1, 33):
    listing[0x5f + i] = ['PUSH' + str(i), 0, 1, 3]

for i in range(1, 17):
    listing[0x7f + i] = ['DUP' + str(i), i, i + 1, 3]
    listing[0x8f + i] = ['SWAP' + str(i), i + 1, i + 1, 3]

for i in range(0x100):
    if i not in listing:
        listing[i] = ['INVALID', 0, 0, 0]


def is_push(op):
    """
    Identify PUSH opcodes
    """
    if 0x60 <= op < 0x80:
        return True
    return False


def is_dup(op):
    """
    Identify DUP opcodes
    """
    if 0x80 <= op < 0x90:
        return True
    return False


def is_swap(op):
    """
    Identify SWAP opcodes
    """
    if 0x90 <= op < 0xa0:
        return True
    return False


def operand_size(op):
    """
    Calculate size of op's operand
    """
    if not is_push(op):
        return 0
    return op - 0x60 + 1
