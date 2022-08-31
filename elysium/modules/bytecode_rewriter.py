#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pyevmasm import assemble_one

def inject_patch_at_address(cfg, patch, address):
    if patch["insert_mode"] == "after":
        after = True
    elif patch["insert_mode"] == "before":
        after = False
    else:
        print("Error: Unknown insert mode:", patch["insert_mode"], "in patch:", patch)
        return cfg

    offset = 0
    for basic_block in cfg.basic_blocks:
        # Search for basic block that contains the bug
        if address >= basic_block.start.pc[1] and address <= basic_block.end.pc[1]:
            j = 0
            delete_location = None, None
            successfully_deleted = False
            patched_instruction_sequence = list()
            deleted_instruction_sequence = list()
            # Delete faulty instructions from basic block
            for i in range(len(basic_block.instructions)):
                if str(basic_block.instructions[i]) == patch["delete"].split(" ")[j].replace("_", " "):
                    if j == 0:
                        delete_location = i, basic_block.instructions[i].pc[0]
                    deleted_instruction_sequence.append(basic_block.instructions[i])
                    offset -= basic_block.instructions[i].size
                    if j < len(patch["delete"].split(" ")) - 1:
                        j += 1
                    else:
                        successfully_deleted = True
                else:
                    if not successfully_deleted and j > 0:
                        patched_instruction_sequence += deleted_instruction_sequence
                        deleted_instruction_sequence = list()
                        j = 0
                        if str(basic_block.instructions[i]) == patch["delete"].split(" ")[j].replace("_", " "):
                            if j == 0:
                                delete_location = i, basic_block.instructions[i].pc[0]
                            deleted_instruction_sequence.append(basic_block.instructions[i])
                            offset -= basic_block.instructions[i].size
                            if j < len(patch["delete"].split(" ")) - 1:
                                j += 1
                            else:
                                successfully_deleted = True
                                delete_location = i - len(patch["delete"].split(" ")) + 1
                        else:
                            patched_instruction_sequence.append(basic_block.instructions[i])
                    else:
                        patched_instruction_sequence.append(basic_block.instructions[i])
            if patch["delete"] == "":
                for i in range(len(basic_block.instructions)):
                    if basic_block.instructions[i].pc[1] == address:
                        delete_location = i, basic_block.instructions[i].pc[0]
                        successfully_deleted = True
                        break

            # Insert correct instructions into basic block
            i, pc = delete_location
            if i and pc:
                push_locations = {}
                j = 0
                while j < len(patch["insert"].split(" ")):
                    code = patch["insert"].split(" ")[j]
                    if after:
                        index = i + j + 1
                    else:
                        index = i + j

                    if code.startswith("PUSH_jump_loc"):
                        location = code.replace("PUSH_", "")
                        if not location in push_locations:
                            push_locations[location] = list()
                        push_locations[location].append(index)
                        address_width = len(hex(pc).replace("0x", ""))
                        if address_width % 2 != 0:
                            address_width += 1
                        address_width = int(address_width / 2)
                        patched_instruction_sequence.insert(index, assemble_one("PUSH"+str(address_width)+" "+hex(pc)))
                        patched_instruction_sequence[index].pc = pc, 0

                    elif code.startswith("PUSH"):
                        patched_instruction_sequence.insert(index, assemble_one(code.split("_")[0]+" "+code.split("_")[1]))
                        patched_instruction_sequence[index].pc = pc, 0

                    elif code.startswith("JUMPDEST_jump_loc"):
                        location = code.replace("JUMPDEST_", "")
                        address_width = len(hex(pc).replace("0x", ""))
                        if address_width % 2 != 0:
                            address_width += 1
                        address_width = int(address_width / 2)
                        if after:
                            for k in push_locations[location]:
                                original_pc = patched_instruction_sequence[k].pc
                                patched_instruction_sequence[k] = assemble_one("PUSH"+str(address_width)+" "+hex(pc + 1))
                                patched_instruction_sequence[k].pc = original_pc
                        else:
                            for k in push_locations[location]:
                                original_pc = patched_instruction_sequence[k].pc
                                patched_instruction_sequence[k] = assemble_one("PUSH"+str(address_width)+" "+hex(pc))
                                patched_instruction_sequence[k].pc = original_pc
                        patched_instruction_sequence.insert(index, assemble_one("JUMPDEST"))
                        patched_instruction_sequence[index].pc = pc, 0

                    else:
                        patched_instruction_sequence.insert(index, assemble_one(code))
                        patched_instruction_sequence[index].pc = pc, 0

                    pc += patched_instruction_sequence[index].size
                    offset += patched_instruction_sequence[index].size
                    j += 1

                delta = 0
                for k in range(len(patched_instruction_sequence)):
                    if delta == 0 and k > 0 and patched_instruction_sequence[k].pc[0] < patched_instruction_sequence[k - 1].pc[0]:
                        delta = patched_instruction_sequence[k - 1].pc[0] - patched_instruction_sequence[k].pc[0] + patched_instruction_sequence[k - 1].size
                    patched_instruction_sequence[k].pc = patched_instruction_sequence[k].pc[0] + delta, patched_instruction_sequence[k].pc[1]

            # Update basic block if faulty instructions were successfully detected and deleted
            if successfully_deleted:
                basic_block._instructions = patched_instruction_sequence
                for instruction in basic_block.instructions:
                    if isinstance(instruction.pc, int):
                        instruction.pc = instruction.pc, instruction.pc

    for basic_block in cfg.basic_blocks:
        if basic_block.start.pc[1] > address:
            for instruction in basic_block.instructions:
                instruction.pc = instruction.pc[0] + offset, instruction.pc[1]

    return cfg
