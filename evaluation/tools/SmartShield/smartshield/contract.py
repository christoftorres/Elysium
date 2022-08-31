import logging
from digraph import DiGraph
import opcodes
import abstract
import hierarchy

log = logging.getLogger(__name__)


class Contract:
    """
    Storage class, storing a structured contract
    """
    def __init__(self):
        self.blocks = []
        self.instructions = {}
        self.jump_destination = {}


class BasicBlock:
    """
    Storage class, storing a structured basic block
    """
    def __init__(self, offset):
        self.offset = offset
        self.instructions = []
        self.next = None
        self.revert = False
        self.layer = None


class Instruction:
    """
    Storage class, storing a structured instruction
    """
    def __init__(self, op, name, arg):
        self.op = op
        self.name = name
        self.arg = arg
        self.reserved = False
        self.layer = None
        self.dependence = set()
        self.overwrite = set()
        self.discarded = False


class RelocationTable:
    """
    Storage class, storing a structured relocation table
    """
    def __init__(self):
        self.sources = {}
        self.destinations = {}


def initialize(evm):
    """
    Initialize contract analysis, disassemble EVM bytecode, construct basic blocks, create DFG and CFG
    """
    contr = Contract()
    dfg = DiGraph()  # Data Flow Graph
    cfg = DiGraph()  # Control Flow Graph

    cur_blk = BasicBlock(0)
    pc = 0
    while pc < len(evm):
        op = evm[pc]
        if op not in opcodes.listing:
            raise KeyError('Invalid op. op: {:#x}, offset: {:#x}'.format(op, pc))

        name = opcodes.listing[op][0]
        size = opcodes.operand_size(op)
        if size != 0:
            arg = int.from_bytes(evm[pc + 1:pc + 1 + size], byteorder='big')
        else:
            arg = None

        instr = Instruction(op, name, arg)
        if name == 'JUMPDEST':
            if len(cur_blk.instructions) > 0:
                contr.blocks.append(cur_blk)
                # Add CFG nodes, representing basic blocks
                cfg.graph.add_node(cur_blk.offset, blk=cur_blk)
                new_blk = BasicBlock(pc)
                cur_blk.next = new_blk
                cur_blk = new_blk
            cur_blk.offset += 1
            contr.jump_destination[pc] = cur_blk
            contr.instructions[pc] = instr
        else:
            cur_blk.instructions.append(instr)
            contr.instructions[pc] = instr

            if opcodes.is_swap(op) or opcodes.is_dup(op):
                # Omit SWAP and DUP from IDG
                pass
            elif (name == 'JUMP' or name == 'JUMPI' or name == 'STOP' or name == 'RETURN' or
                  name == 'REVERT' or name == 'INVALID' or name == 'SUICIDE'):
                contr.blocks.append(cur_blk)
                # Add CFG nodes, representing basic blocks
                cfg.graph.add_node(cur_blk.offset, blk=cur_blk)
                new_blk = BasicBlock(pc + 1)
                cur_blk.next = new_blk
                cur_blk = new_blk
                # Add DFG nodes, representing instructions
                dfg.graph.add_node(pc, instr=instr)
            else:
                # Add DFG nodes, representing instructions
                dfg.graph.add_node(pc, instr=instr)

        pc += size + 1

    if len(cur_blk.instructions) > 0 or cur_blk.offset - 1 in contr.jump_destination:
        contr.blocks.append(cur_blk)
        # Add CFG nodes, representing basic blocks
        cfg.graph.add_node(cur_blk.offset, blk=cur_blk)
    else:
        contr.blocks[-1].next = None

    return contr, dfg, cfg


def analyze(contr, dfg, cfg):
    """
    Analyze contract, construct DFG and CFG
    """
    # Abstract execute contract, construct DFG and CFG, trace execution
    trace = {}
    relocate = RelocationTable()
    abstract.execute(contr, dfg, cfg, trace, relocate)

    # Traverse CFG, create layers for basic blocks and instructions
    hierarchy.layering(contr, cfg)

    return trace, relocate
