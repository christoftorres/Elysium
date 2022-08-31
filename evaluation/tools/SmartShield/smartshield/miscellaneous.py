import logging
import opcodes

log = logging.getLogger(__name__)


class JumpPush:
    def __init__(self, pc, arg, size):
        self.pc = pc
        self.arg = arg
        self.size = size


class Block:
    def __init__(self, bytes_):
        self.isExist = False
        self.pos = -1
        self.content = bytearray.fromhex(bytes_)


add_block = Block('5b8282810180911115909157600080fd')
sub_block = Block('5b828210159057600080fd')
mul_block = Block('5b828202928015825780840483148257600080fd')
div_block = Block('5b8215159057600080fd')
mod_block = Block('5b8215159057600080fd')
ue_block = Block('5b8115159057600080fd')


def init_relocation_table(contr, relocate):
    """
    Initialize relocation table
    """
    instrs = contr.instructions
    sources = relocate.sources
    reloc_tbl = set()

    for pc, off in sources.items():
        instr = instrs[pc]
        op = instr.op
        arg = instr.arg
        size = opcodes.operand_size(op)
        reloc_tbl.add(JumpPush(off, arg, size))

    return reloc_tbl


def set_report(report, vul_pos, vul_type, msg):
    """
    Set patching report file
    """
    if vul_type == 'ue':
        report['UnhandledExceptions'].append(
            {
                'offset': vul_pos,
                'result': msg
            }
        )
    else:
        report['IntegerBugs'].append(
            {
                'offset': vul_pos,
                'category': vul_type,
                'result': msg
            }
        )


def patch_add(reloc, vul_pos, bytecode):
    global add_block
    global sub_block
    global mul_block
    global div_block
    global mod_block
    global ue_block
    added_length = 0xa
    last_pos = len(bytecode)
    if not add_block.isExist:
        end_block = add_block.content
        bytecode.extend(end_block)

        add_block.isExist = True
        add_block.pos = last_pos + added_length
    else:
        add_block.pos += added_length
    
    if sub_block.isExist:
        sub_block.pos += added_length
    if mul_block.isExist:
        mul_block.pos += added_length
    if div_block.isExist:
        div_block.pos += added_length
    if mod_block.isExist:
        mod_block.pos += added_length
    if ue_block.isExist:
        ue_block.pos += added_length

    pos1 = vul_pos + 7
    pos1_bytes = bytearray(pos1.to_bytes(2, 'big'))

    pos2 = add_block.pos
    pos2_bytes = bytearray(pos2.to_bytes(2, 'big'))

    patch_ins = bytearray.fromhex('61{}61{}565b915050'.format(pos1_bytes.hex(), pos2_bytes.hex()))
    bytecode.pop(vul_pos)
    bytecode[vul_pos: vul_pos] = patch_ins

    for push in reloc:
        if push.pc > vul_pos:
            push.pc += added_length
        if push.arg > vul_pos:
            push.arg += added_length

    reloc.add(JumpPush(vul_pos, pos1, 2))
    reloc.add(JumpPush(vul_pos + 3, pos2, 2))


def patch_sub(reloc, vul_pos, bytecode):
    global add_block
    global sub_block
    global mul_block
    global div_block
    global mod_block
    global ue_block
    added_length = 0x8
    last_pos = len(bytecode)
    if not sub_block.isExist:
        end_block = sub_block.content
        bytecode.extend(end_block)

        sub_block.isExist = True
        sub_block.pos = last_pos + added_length
    else:
        sub_block.pos += added_length

    if add_block.isExist:
        add_block.pos += added_length
    if mul_block.isExist:
        mul_block.pos += added_length
    if div_block.isExist:
        div_block.pos += added_length
    if mod_block.isExist:
        mod_block.pos += added_length
    if ue_block.isExist:
        ue_block.pos += added_length

    pos1 = vul_pos + 7
    pos1_bytes = bytearray(pos1.to_bytes(2, 'big'))

    pos2 = sub_block.pos
    pos2_bytes = bytearray(pos2.to_bytes(2, 'big'))

    patch_ins = bytearray.fromhex('61{}61{}565b03'.format(pos1_bytes.hex(), pos2_bytes.hex()))

    bytecode.pop(vul_pos)
    bytecode[vul_pos: vul_pos] = patch_ins

    for push in reloc:
        if push.pc > vul_pos:
            push.pc += added_length
        if push.arg > vul_pos:
            push.arg += added_length

    reloc.add(JumpPush(vul_pos, pos1, 2))
    reloc.add(JumpPush(vul_pos + 3, pos2, 2))


def patch_mul(reloc, vul_pos, bytecode):
    global add_block
    global sub_block
    global mul_block
    global div_block
    global mod_block
    global ue_block
    added_length = 0xa
    last_pos = len(bytecode)
    if not mul_block.isExist:
        end_block = mul_block.content
        bytecode.extend(end_block)

        mul_block.isExist = True
        mul_block.pos = last_pos + added_length
    else:
        mul_block.pos += added_length

    if add_block.isExist:
        add_block.pos += added_length
    if sub_block.isExist:
        sub_block.pos += added_length
    if div_block.isExist:
        div_block.pos += added_length
    if mod_block.isExist:
        mod_block.pos += added_length
    if ue_block.isExist:
        ue_block.pos += added_length

    pos1 = vul_pos + 7
    pos1_bytes = bytearray(pos1.to_bytes(2, 'big'))

    pos2 = mul_block.pos
    pos2_bytes = bytearray(pos2.to_bytes(2, 'big'))

    patch_ins = bytearray.fromhex('61{}61{}565b505050'.format(pos1_bytes.hex(), pos2_bytes.hex()))

    bytecode.pop(vul_pos)
    bytecode[vul_pos: vul_pos] = patch_ins

    for push in reloc:
        if push.pc > vul_pos:
            push.pc += added_length
        if push.arg > vul_pos:
            push.arg += added_length

    reloc.add(JumpPush(vul_pos, pos1, 2))
    reloc.add(JumpPush(vul_pos + 3, pos2, 2))


def patch_div(reloc, vul_pos, bytecode):
    global add_block
    global sub_block
    global mul_block
    global div_block
    global mod_block
    global ue_block
    added_length = 0x8
    last_pos = len(bytecode)
    if not div_block.isExist:
        end_block = div_block.content
        bytecode.extend(end_block)

        div_block.isExist = True
        div_block.pos = last_pos + added_length
    else:
        div_block.pos += added_length

    if add_block.isExist:
        add_block.pos += added_length
    if sub_block.isExist:
        sub_block.pos += added_length
    if mul_block.isExist:
        mul_block.pos += added_length
    if mod_block.isExist:
        mod_block.pos += added_length
    if ue_block.isExist:
        ue_block.pos += added_length

    pos1 = vul_pos + 7
    pos1_bytes = bytearray(pos1.to_bytes(2, 'big'))

    pos2 = div_block.pos
    pos2_bytes = bytearray(pos2.to_bytes(2, 'big'))

    patch_ins = bytearray.fromhex('61{}61{}565b04'.format(pos1_bytes.hex(), pos2_bytes.hex()))

    bytecode.pop(vul_pos)
    bytecode[vul_pos: vul_pos] = patch_ins

    for push in reloc:
        if push.pc > vul_pos:
            push.pc += added_length
        if push.arg > vul_pos:
            push.arg += added_length

    reloc.add(JumpPush(vul_pos, pos1, 2))
    reloc.add(JumpPush(vul_pos + 3, pos2, 2))


def patch_mod(reloc, vul_pos, bytecode):
    global add_block
    global sub_block
    global mul_block
    global div_block
    global mod_block
    global ue_block
    added_length = 0x8
    last_pos = len(bytecode)
    if not mod_block.isExist:
        end_block = mod_block.content
        bytecode.extend(end_block)

        mod_block.isExist = True
        mod_block.pos = last_pos + added_length
    else:
        mod_block.pos += added_length

    if add_block.isExist:
        add_block.pos += added_length
    if sub_block.isExist:
        sub_block.pos += added_length
    if mul_block.isExist:
        mul_block.pos += added_length
    if div_block.isExist:
        div_block.pos += added_length
    if ue_block.isExist:
        ue_block.pos += added_length

    pos1 = vul_pos + 7
    pos1_bytes = bytearray(pos1.to_bytes(2, 'big'))

    pos2 = mod_block.pos
    pos2_bytes = bytearray(pos2.to_bytes(2, 'big'))

    patch_ins = bytearray.fromhex('61{}61{}565b06'.format(pos1_bytes.hex(), pos2_bytes.hex()))

    bytecode.pop(vul_pos)
    bytecode[vul_pos: vul_pos] = patch_ins

    for push in reloc:
        if push.pc > vul_pos:
            push.pc += added_length
        if push.arg > vul_pos:
            push.arg += added_length

    reloc.add(JumpPush(vul_pos, pos1, 2))
    reloc.add(JumpPush(vul_pos + 3, pos2, 2))


def patch_ue(reloc, vul_pos, bytecode):
    global add_block
    global sub_block
    global mul_block
    global div_block
    global mod_block
    global ue_block
    added_length = 0x8
    last_pos = len(bytecode)
    if not ue_block.isExist:
        end_block = ue_block.content
        bytecode.extend(end_block)

        ue_block.isExist = True
        ue_block.pos = last_pos + added_length
    else:
        ue_block.pos += added_length

    if add_block.isExist:
        add_block.pos += added_length
    if sub_block.isExist:
        sub_block.pos += added_length
    if mul_block.isExist:
        mul_block.pos += added_length
    if div_block.isExist:
        div_block.pos += added_length
    if mod_block.isExist:
        mod_block.pos += added_length

    pos1 = vul_pos + 8
    pos1_bytes = bytearray(pos1.to_bytes(2, 'big'))

    pos2 = ue_block.pos
    pos2_bytes = bytearray(pos2.to_bytes(2, 'big'))

    patch_ins = bytearray.fromhex('f161{}61{}565b'.format(pos1_bytes.hex(), pos2_bytes.hex()))

    bytecode.pop(vul_pos)
    bytecode[vul_pos: vul_pos] = patch_ins

    for push in reloc:
        if push.pc > vul_pos:
            push.pc += added_length
        if push.arg > vul_pos:
            push.arg += added_length

    reloc.add(JumpPush(vul_pos + 1, pos1, 2))
    reloc.add(JumpPush(vul_pos + 4, pos2, 2))


def execute(contr, relocate, bytecode, miscellany, report):
    """
    Patch integer bugs and unhandled exceptions
    """
    reloc_tbl = init_relocation_table(contr, relocate)
    key_list = list(miscellany)
    key_list.sort(reverse=True)
    for vul_pos in key_list:
        vul_type = miscellany[vul_pos]
        old_reloc_tbl = reloc_tbl.copy()
        old_bytecode = bytecode.copy()
        try:
            if vul_type == 'add':
                patch_add(reloc_tbl, vul_pos, bytecode)
            elif vul_type == 'sub':
                patch_sub(reloc_tbl, vul_pos, bytecode)
            elif vul_type == 'mul':
                patch_mul(reloc_tbl, vul_pos, bytecode)
            elif vul_type == 'div':
                patch_div(reloc_tbl, vul_pos, bytecode)
            elif vul_type == 'mod':
                patch_mod(reloc_tbl, vul_pos, bytecode)
            elif vul_type == 'ue':
                patch_ue(reloc_tbl, vul_pos, bytecode)
        except Exception as e:
            if str(e).strip('\'') == 'Timeout.':
                raise e
            else:
                reloc_tbl = old_reloc_tbl
                bytecode = old_bytecode
                set_report(report, vul_pos, vul_type, str(e).strip('\''))
        else:
            set_report(report, vul_pos, vul_type, 'Done.')

    for push in reloc_tbl:
        if push.arg > 0xff and push.size == 1:
            bytecode[push.pc: push.pc + 1] = bytearray.fromhex('61')
            push.size += 1
            for push_ in reloc_tbl:
                if push_.pc > push.pc:
                    push_.pc += 1
                if push_.arg > push.pc:
                    push_.arg += 1

    for push in reloc_tbl:
        bytecode[push.pc + 1: push.pc + 1 + push.size] = bytearray(push.arg.to_bytes(push.size, 'big'))
