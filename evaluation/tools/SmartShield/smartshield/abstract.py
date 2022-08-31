import logging
import opcodes

log = logging.getLogger(__name__)
contr = None
dfg = None
cfg = None
trace = None
relocate = None

TT256 = 2 ** 256
TT256M1 = 2 ** 256 - 1
TT255 = 2 ** 255
MAX_DEPTH = 1024


class State:
    """
    Storage class, storing a structured hashable state during abstract execution
    """
    def __init__(self, next_block, stack, memory, storage, sequence):
        self.next_block = next_block
        self.stack = stack
        self.memory = memory
        self.storage = storage
        self.sequence = sequence

    def __eq__(self, other):
        if isinstance(other, State):
            return (id(self.next_block) == id(other.next_block) and self.stack == other.stack and
                    self.memory == other.memory and self.storage == other.storage and self.sequence == other.sequence)
        else:
            return NotImplemented

    def __hash__(self):
        frozen_memory = {key: frozenset(value) for key, value in self.memory.items()}
        frozen_storage = {key: frozenset(value) for key, value in self.storage.items()}
        frozen_sequence = {key: frozenset(value) for key, value in self.sequence.items()}
        return hash((id(self.next_block), tuple(self.stack), frozenset(frozen_memory.items()),
                     frozenset(frozen_storage.items()), frozenset(frozen_sequence.items())))


class OperandStackElement:
    """
    Storage class, storing a structured element of operand stack during abstract execution, referencing data flow
    source instruction and storing stack value
    """
    def __init__(self, pc, instruction, value=None, source=None):
        self.pc = pc
        self.instruction = instruction
        self.value = value  # Stack value
        self.source = source  # Source PUSH producing stack value

    def __eq__(self, other):
        if isinstance(other, OperandStackElement):
            return self.pc == other.pc and id(self.instruction) == id(other.instruction)
        else:
            return NotImplemented

    def __hash__(self):
        return hash((self.pc, id(self.instruction)))


class ExecutionStackElement:
    """
    Storage class, storing a structured element of execution stack during abstract execution
    """
    def __init__(self, state):
        self.state = state
        self.executed = False  # Current state has been executed or not
        self.num = 0  # Number of return values to wait


def convert_to_signed(x):
    """
    Convert an operand from unsigned to signed
    """
    if x is None:
        return None
    elif x < TT255:
        return x
    else:
        return x - TT256


def backtrack_instruction_sources(pc, instr, operands, ins):
    """
    Backtrack instruction operand sources and add edges to DFG
    """
    global dfg
    op = instr.op
    # Label operand sources of SWAP and DUP
    if opcodes.is_swap(op) or opcodes.is_dup(op):
        for i in range(ins):
            operands[i].instruction.reserved = True
    else:
        # Add IDG edges, representing data flow dependencies between instructions
        for i in range(ins):
            dfg.graph.add_edge(operands[i].pc, pc)


def advance(elm):
    """
    Execute next block abstractly and advance current state
    """
    global contr
    global trace
    global relocate
    stat = elm.state
    blk = stat.next_block
    pc = blk.offset
    stack = stat.stack.copy()
    memory = stat.memory.copy()
    storage = stat.storage.copy()
    sequence = stat.sequence.copy()

    # Mark current state as executed
    elm.executed = True

    for instr in blk.instructions:
        op = instr.op
        name = instr.name
        old_stack = stack.copy()
        ins = opcodes.listing[op][1]
        if ins > len(stack):
            raise RuntimeError('Stack underflow. pc: {:#x}'.format(pc))

        operands = []
        for i in range(ins):
            operand = stack.pop(0)
            operands.append(operand)
        backtrack_instruction_sources(pc, instr, operands, ins)

        # Trace executed instructions from CALL to SSTORE, omit JUMPDEST, SWAP and DUP
        if name != 'JUMPDEST' and not opcodes.is_swap(op) and not opcodes.is_dup(op):
            for off in sequence:
                sequence[off].add(pc)

        if name == 'STOP' or name == 'SUICIDE':
            # Current block is NOT revert block
            return False
        elif name == 'INVALID':
            # Current block is revert block
            return True
        elif name == 'ADD':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, (op0 + op1) & TT256M1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'SUB':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, (op0 - op1) & TT256M1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'MUL':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, (op0 * op1) & TT256M1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'DIV':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, 0 if op1 == 0 else op0 // op1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'MOD':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, 0 if op1 == 0 else op0 % op1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'SDIV':
            op0 = convert_to_signed(operands[0].value)
            op1 = convert_to_signed(operands[1].value)
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr,
                                                    0 if op1 == 0 else (abs(op0) // abs(op1) *
                                                                        (-1 if op0 * op1 < 0 else 1)) & TT256M1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'SMOD':
            op0 = convert_to_signed(operands[0].value)
            op1 = convert_to_signed(operands[1].value)
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr,
                                                    0 if op1 == 0 else (abs(op0) % abs(op1) *
                                                                        (-1 if op0 < 0 else 1)) & TT256M1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'ADDMOD':
            op0 = operands[0].value
            op1 = operands[1].value
            op2 = operands[2].value
            if op0 is not None and op1 is not None and op2 is not None:
                stack.insert(0, OperandStackElement(pc, instr, (op0 + op1) % op2 if op2 else 0))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'MULMOD':
            op0 = operands[0].value
            op1 = operands[1].value
            op2 = operands[2].value
            if op0 is not None and op1 is not None and op2 is not None:
                stack.insert(0, OperandStackElement(pc, instr, (op0 * op1) % op2 if op2 else 0))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'EXP':
            base = operands[0].value
            exponent = operands[1].value
            if base is not None and exponent is not None:
                stack.insert(0, OperandStackElement(pc, instr, pow(base, exponent, TT256)))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'SIGNEXTEND':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                if op0 <= 31:
                    test_bit = op0 * 8 + 7
                    if op1 & (1 << test_bit):
                        stack.insert(0, OperandStackElement(pc, instr, op1 | (TT256 - (1 << test_bit))))
                    else:
                        stack.insert(0, OperandStackElement(pc, instr, op1 & ((1 << test_bit) - 1)))
                else:
                        stack.insert(0, OperandStackElement(pc, instr, op1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'LT':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, 1 if op0 < op1 else 0))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'GT':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, 1 if op0 > op1 else 0))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'SLT':
            op0 = convert_to_signed(operands[0].value)
            op1 = convert_to_signed(operands[1].value)
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, 1 if op0 < op1 else 0))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'SGT':
            op0 = convert_to_signed(operands[0].value)
            op1 = convert_to_signed(operands[1].value)
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, 1 if op0 > op1 else 0))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'EQ':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, 1 if op0 == op1 else 0))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'ISZERO':
            op0 = operands[0].value
            if op0 is not None:
                stack.insert(0, OperandStackElement(pc, instr, 0 if op0 else 1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'AND':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                if op0 == 0xffffffff:
                    stack.insert(0, OperandStackElement(pc, instr, op0 & op1, operands[1].source))
                elif op1 == 0xffffffff:
                    stack.insert(0, OperandStackElement(pc, instr, op0 & op1, operands[0].source))
                else:
                    stack.insert(0, OperandStackElement(pc, instr, op0 & op1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'OR':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, op0 | op1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'XOR':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                stack.insert(0, OperandStackElement(pc, instr, op0 ^ op1))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'NOT':
            op0 = operands[0].value
            if op0 is not None:
                stack.insert(0, OperandStackElement(pc, instr, TT256M1 - op0))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'BYTE':
            op0 = operands[0].value
            op1 = operands[1].value
            if op0 is not None and op1 is not None:
                if op0 >= 32:
                    stack.insert(0, OperandStackElement(pc, instr, 0))
                else:
                    stack.insert(0, OperandStackElement(pc, instr, (op1 // 256 ** (31 - op0)) % 256))
            else:
                stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'RETURN':
            address = operands[0].value
            size = operands[1].value
            # Resolve read address and read size, record memory dependencies
            if address is not None and size is not None:
                for i in range(size):
                    if address + i in memory:
                        instr.dependence.update(memory[address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address or read size, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
            # Current block is NOT revert block
            return False
        elif name == 'REVERT':
            address = operands[0].value
            size = operands[1].value
            # Resolve read address and read size, record memory dependencies
            if address is not None and size is not None:
                for i in range(size):
                    if address + i in memory:
                        instr.dependence.update(memory[address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address or read size, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
            # Current block is revert block
            return True
        elif opcodes.is_push(op):
            stack.insert(0, OperandStackElement(pc, instr, instr.arg, pc))
        elif opcodes.is_dup(op):
            old_stack.insert(0, operands[-1])
            stack = old_stack
        elif opcodes.is_swap(op):
            tmp = old_stack[0]
            old_stack[0] = old_stack[ins - 1]
            old_stack[ins - 1] = tmp
            stack = old_stack
        elif name == 'JUMP':
            src_pc = operands[0].source
            dst_pc = operands[0].value
            if src_pc is None or dst_pc is None:
                raise ValueError('Error resolving JUMP address. pc: {:#x}, source: {:#x}'
                                 .format(pc, operands[0].pc))
            if dst_pc not in contr.jump_destination:
                # Current block is revert block
                return True
            else:
                dst_blk = contr.jump_destination[dst_pc]
                # Construct relocation table
                relocate.sources[src_pc] = None
                relocate.destinations[dst_pc] = None
                # Add CFG edges, representing control flow dependencies between basic blocks
                cfg.graph.add_edge(blk.offset, dst_blk.offset, type='JUMP')
                # Update number of return values to wait
                elm.num += 1
                return [State(dst_blk, stack, memory, storage, sequence)]
        elif name == 'JUMPI':
            src_pc = operands[0].source
            dst_pc = operands[0].value
            if src_pc is None or dst_pc is None:
                raise ValueError('Error resolving JUMPI address. pc: {:#x}, source: {:#x}'
                                 .format(pc, operands[0].pc))
            ret = []
            if dst_pc in contr.jump_destination:
                dst_blk = contr.jump_destination[dst_pc]
                # Construct relocation table
                relocate.sources[src_pc] = None
                relocate.destinations[dst_pc] = None
                # Add CFG edges, representing control flow dependencies between basic blocks
                cfg.graph.add_edge(blk.offset, dst_blk.offset, type='JUMPI')
                # Update number of return values to wait
                elm.num += 1
                ret.append(State(dst_blk, stack, memory, storage, sequence))
            if blk.next is not None:
                # Add CFG edges, representing control flow dependencies between basic blocks
                cfg.graph.add_edge(blk.offset, blk.next.offset, type='JUMPI')
                # Update number of return values to wait
                elm.num += 1
                ret.append(State(blk.next, stack, memory, storage, sequence))
            if not ret:
                # Current block is revert block
                return True
            else:
                return ret
        elif name == 'SHA3':
            address = operands[0].value
            size = operands[1].value
            # Resolve read address and read size, record memory dependencies
            if address is not None and size is not None:
                for i in range(size):
                    if address + i in memory:
                        instr.dependence.update(memory[address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address or read size, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
            stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'LOG0' or name == 'LOG1' or name == 'LOG2' or name == 'LOG3' or name == 'LOG4':
            address = operands[0].value
            size = operands[1].value
            # Resolve read address and read size, record memory dependencies
            if address is not None and size is not None:
                for i in range(size):
                    if address + i in memory:
                        instr.dependence.update(memory[address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address or read size, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
        elif name == 'MLOAD':
            address = operands[0].value
            # Resolve read address, record memory dependencies
            if address is not None:
                for i in range(32):
                    if address + i in memory:
                        instr.dependence.update(memory[address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
            stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'CREATE':
            address = operands[0].value
            size = operands[1].value
            # Resolve read address and read size, record memory dependencies
            if address is not None and size is not None:
                for i in range(size):
                    if address + i in memory:
                        instr.dependence.update(memory[address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address or read size, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
            stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'MSTORE':
            address = operands[0].value
            # Resolve write address, label memory
            if address is not None:
                for i in range(32):
                    if address + i not in memory:
                        memory[address + i] = set()
                    instr.overwrite.update(memory[address + i])
                    memory[address + i].add(pc)
            # Can not resolve write address, label all possible addresses
            else:
                if 'all' not in memory:
                    memory['all'] = set()
                for addr in memory:
                    instr.overwrite.update(memory[addr])
                memory['all'].add(pc)
        elif name == 'MSTORE8':
            address = operands[0].value
            # Resolve write address, label memory
            if address is not None:
                if address not in memory:
                    memory[address] = set()
                instr.overwrite.update(memory[address])
                memory[address].add(pc)
            # Can not resolve write address, label all possible addresses
            else:
                if 'all' not in memory:
                    memory['all'] = set()
                for addr in memory:
                    instr.overwrite.update(memory[addr])
                memory['all'].add(pc)
        elif name == 'CALLDATACOPY' or name == 'RETURNDATACOPY':
            address = operands[0].value
            size = operands[2].value
            # Resolve write address and write size, label memory
            if address is not None and size is not None:
                for i in range(size):
                    if address + i not in memory:
                        memory[address + i] = set()
                    instr.overwrite.update(memory[address + i])
                    memory[address + i].add(pc)
            # Can not resolve write address or write size, label all possible addresses
            else:
                if 'all' not in memory:
                    memory['all'] = set()
                for addr in memory:
                    instr.overwrite.update(memory[addr])
                memory['all'].add(pc)
        elif name == 'CODECOPY':
            address = operands[0].value
            size = operands[2].value
            src_pc = operands[1].source
            dst_pc = operands[1].value
            if src_pc is None or dst_pc is None:
                raise ValueError('Error resolving CODECOPY address. pc: {:#x}, source: {:#x}'
                                 .format(pc, operands[1].pc))
            # Construct relocation table
            relocate.sources[src_pc] = None
            relocate.destinations[dst_pc] = None
            # Resolve write address and write size, label memory
            if address is not None and size is not None:
                for i in range(size):
                    if address + i not in memory:
                        memory[address + i] = set()
                    instr.overwrite.update(memory[address + i])
                    memory[address + i].add(pc)
            # Can not resolve write address or write size, label all possible addresses
            else:
                if 'all' not in memory:
                    memory['all'] = set()
                for addr in memory:
                    instr.overwrite.update(memory[addr])
                memory['all'].add(pc)
        elif name == 'EXTCODECOPY':
            address = operands[1].value
            size = operands[3].value
            # Resolve write address and write size, label memory
            if address is not None and size is not None:
                for i in range(size):
                    if address + i not in memory:
                        memory[address + i] = set()
                    instr.overwrite.update(memory[address + i])
                    memory[address + i].add(pc)
            # Can not resolve write address or write size, label all possible addresses
            else:
                if 'all' not in memory:
                    memory['all'] = set()
                for addr in memory:
                    instr.overwrite.update(memory[addr])
                memory['all'].add(pc)
        elif name == 'CALL':
            # Start tracing executed instructions from CALL to SSTORE
            if pc not in sequence:
                sequence[pc] = set()
            read_address = operands[3].value
            read_size = operands[4].value
            # Resolve read address and read size, record memory dependencies
            if read_address is not None and read_size is not None:
                for i in range(read_size):
                    if read_address + i in memory:
                        instr.dependence.update(memory[read_address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address or read size, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
            write_address = operands[5].value
            write_size = operands[6].value
            # Resolve write address and write size, label memory
            if write_address is not None and write_size is not None:
                for i in range(write_size):
                    if write_address + i not in memory:
                        memory[write_address + i] = set()
                    instr.overwrite.update(memory[write_address + i])
                    memory[write_address + i].add(pc)
            # Can not resolve write address or write size, label all possible addresses
            else:
                if 'all' not in memory:
                    memory['all'] = set()
                for addr in memory:
                    instr.overwrite.update(memory[addr])
                memory['all'].add(pc)
            stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'CALLCODE':
            read_address = operands[3].value
            read_size = operands[4].value
            # Resolve read address and read size, record memory dependencies
            if read_address is not None and read_size is not None:
                for i in range(read_size):
                    if read_address + i in memory:
                        instr.dependence.update(memory[read_address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address or read size, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
            write_address = operands[5].value
            write_size = operands[6].value
            # Resolve write address and write size, label memory
            if write_address is not None and write_size is not None:
                for i in range(write_size):
                    if write_address + i not in memory:
                        memory[write_address + i] = set()
                    instr.overwrite.update(memory[write_address + i])
                    memory[write_address + i].add(pc)
            # Can not resolve write address or write size, label all possible addresses
            else:
                if 'all' not in memory:
                    memory['all'] = set()
                for addr in memory:
                    instr.overwrite.update(memory[addr])
                memory['all'].add(pc)
            stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'DELEGATECALL' or name == 'STATICCALL':
            read_address = operands[2].value
            read_size = operands[3].value
            # Resolve read address and read size, record memory dependencies
            if read_address is not None and read_size is not None:
                for i in range(read_size):
                    if read_address + i in memory:
                        instr.dependence.update(memory[read_address + i])
                    if 'all' in memory:
                        instr.dependence.update(memory['all'])
            # Can not resolve read address or read size, record all possible memory dependencies
            else:
                for addr in memory:
                    instr.dependence.update(memory[addr])
            write_address = operands[4].value
            write_size = operands[5].value
            # Resolve write address and write size, label memory
            if write_address is not None and write_size is not None:
                for i in range(write_size):
                    if write_address + i not in memory:
                        memory[write_address + i] = set()
                    instr.overwrite.update(memory[write_address + i])
                    memory[write_address + i].add(pc)
            # Can not resolve write address or write size, label all possible addresses
            else:
                if 'all' not in memory:
                    memory['all'] = set()
                for addr in memory:
                    instr.overwrite.update(memory[addr])
                memory['all'].add(pc)
            stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'SLOAD':
            address = operands[0].value
            # Resolve read address, record storage dependencies
            if address is not None:
                if address in storage:
                    instr.dependence.update(storage[address])
                if 'all' in storage:
                    instr.dependence.update(storage['all'])
            # Can not resolve read address, record all possible storage dependencies
            else:
                for addr in storage:
                    instr.dependence.update(storage[addr])
            stack.insert(0, OperandStackElement(pc, instr))
        elif name == 'SSTORE':
            # End tracing executed instructions from CALL to SSTORE
            for off in sequence:
                if (off, pc) not in trace:
                    trace[(off, pc)] = set()
                trace[(off, pc)].update(sequence[off])
            address = operands[0].value
            # Resolve write address, label storage
            if address is not None:
                if address not in storage:
                    storage[address] = set()
                instr.overwrite.update(storage[address])
                storage[address].add(pc)
            # Can not resolve write address, label all possible addresses
            else:
                if 'all' not in storage:
                    storage['all'] = set()
                for addr in storage:
                    instr.overwrite.update(storage[addr])
                storage['all'].add(pc)
        else:
            outs = opcodes.listing[op][2]
            for i in range(outs):
                stack.insert(0, OperandStackElement(pc, instr))

        if len(stack) > MAX_DEPTH:
            raise RuntimeError('Stack overflow. pc: {:#x}'.format(pc))

        size = opcodes.operand_size(op)
        pc += size + 1

    if blk.next is not None:
        # Add CFG edges, representing control flow dependencies between basic blocks
        cfg.graph.add_edge(blk.offset, blk.next.offset, type='SEQUENTIAL')
        # Update number of return values to wait
        elm.num += 1
        return [State(stat.next_block.next, stack, memory, storage, sequence)]
    else:
        # Current block is NOT revert block
        return False


def execute(_contr, _dfg, _cfg, _trace, _relocate):
    """
    Abstract execute contract, acquire instruction dependencies, construct DFG and CFG, trace execution
    """
    global contr
    global dfg
    global cfg
    global trace
    global relocate
    contr = _contr
    dfg = _dfg
    cfg = _cfg
    trace = _trace
    relocate = _relocate

    init_stat = State(contr.blocks[0], [], {}, {}, {})
    exec_stack = [ExecutionStackElement(init_stat)]
    ret_stack = []
    vis_stats = {init_stat}

    while len(exec_stack) > 0:
        cur_elm = exec_stack[0]
        # Current state has been executed, waiting for return values
        if cur_elm.executed:
            # Check return values, update basic block attributes
            if cur_elm.num == 0:
                pass
            elif cur_elm.num == 1:
                cur_elm.state.next_block.revert = ret_stack[0]
            elif cur_elm.num == 2:
                ret = ret_stack.pop(0) and ret_stack.pop(0)
                cur_elm.state.next_block.revert = ret
                ret_stack.insert(0, ret)
            else:
                raise ValueError('Error resolving return values. pc: {:#x}'.format(cur_elm.state.next_block.offset))
            exec_stack.pop(0)
        # Current state has NOT been executed, execute it
        else:
            ret = advance(cur_elm)
            # Saving subsequent states for future execution
            if isinstance(ret, list):
                for stat in ret:
                    if stat not in vis_stats:
                        vis_stats.add(stat)
                        exec_stack.insert(0, ExecutionStackElement(stat))
                    else:
                        ret_stack.insert(0, stat.next_block.revert)
            # There exists NO subsequent states, saving return values
            else:
                cur_elm.state.next_block.revert = ret
                ret_stack.insert(0, ret)
