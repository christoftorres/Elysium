import logging
import opcodes

log = logging.getLogger(__name__)


def instruction_to_bytecode(instr):
    """
    Convert instruction to bytecode
    """
    op = instr.op
    evm = bytearray(op.to_bytes(1, byteorder='big'))
    if opcodes.is_push(op):
        arg = instr.arg
        size = opcodes.operand_size(op)
        evm += bytearray(arg.to_bytes(size, byteorder='big'))
    return evm


def convert(contr, dfg, relocate, patches, bytecode, miscellany, updated_miscellany):
    """
    Convert patched contract to bytecode
    """
    instrs = contr.instructions
    sources = relocate.sources
    destinations = relocate.destinations

    for pc, instr in instrs.items():
        # Add patching instructions
        if pc in patches:
            for _, slices in sorted(patches[pc].items()):
                for off in slices:
                    # Update miscellany
                    if off in miscellany:
                        updated_miscellany[len(bytecode)] = miscellany[off]
                    bytecode += instruction_to_bytecode(instrs[off])

        # Remove discarded instructions
        if instr.discarded:
            for pre in dfg.graph.predecessors(pc):
                # Replace discarded instructions with POPs
                if not instrs[pre].discarded:
                    bytecode += bytearray(0x50.to_bytes(1, byteorder='big'))
        else:
            # Construct relocation table
            if pc in sources:
                sources[pc] = len(bytecode)
            if pc in destinations:
                destinations[pc] = len(bytecode)
            # Update miscellany
            if pc in miscellany:
                updated_miscellany[len(bytecode)] = miscellany[pc]
            bytecode += instruction_to_bytecode(instr)


def relocating(contr, relocate, bytecode):
    """
    Relocate target addresses
    """
    instrs = contr.instructions
    sources = relocate.sources
    destinations = relocate.destinations

    for pc, off in sources.items():
        instr = instrs[pc]
        op = instr.op
        arg = instr.arg

        # Update PUSH's opcode
        addr = destinations[arg]
        size = opcodes.operand_size(op)
        if addr is None:
            raise ValueError('Invalid target address. addr: {:#x}, source: {:#x}'.format(arg, pc))
        if addr > 0xff and size == 1:
            instr.op = 0x61
            instr.name = 'PUSH2'
            return False

        # Update PUSH's operand and bytecode
        instr.arg = addr
        bytecode[off + 1: off + size + 1] = bytearray(addr.to_bytes(size, byteorder='big'))

    return True


def execute(contr, dfg, relocate, patches, miscellany):
    """
    Restore patched contract to bytecode
    """
    while True:
        # Traverse DFG, convert patched contract to bytecode
        bytecode = bytearray()
        updated_miscellany = {}
        convert(contr, dfg, relocate, patches, bytecode, miscellany, updated_miscellany)

        # Relocate target addresses
        if relocating(contr, relocate, bytecode):
            break

    return bytecode, updated_miscellany
