import Helper
import Scanner


def rebuild(blist, addr):
    print("Rebuilding...")
    buffer = []
    pos = addr
    print("Writing blocks with padding")
    for block in blist:
        block["new_offsets"] = []
        block["new_sizes"] = []
        for opc in block["opcodes"]:
            asm = str(opc.mnemonic) + " " + str(opc.op_str)
            bytecode, _ = Helper.global_data["ass"].asm(asm, pos)
            buffer.extend(bytecode)
            block["new_offsets"].append(pos)
            block["new_sizes"].append(len(bytecode))
            pos = pos + len(bytecode)
        for i in range(0, 16):
            buffer.append(0x90)
            pos = pos + 1
    print("Inserting jumps")
    for block in blist:
        if len(block["exits"]) == 1:
            child = Scanner.find_block(block["exits"][0], blist)
            Helper.assert_true(child is not None, "Child not found", None)
            asm = "jmp " + hex(child["new_offsets"][0])
            last = len(block["opcodes"]) - 1
            new_addr = block["new_offsets"][last] + block["new_sizes"][last]
            bytecode, _ = Helper.global_data["ass"].asm(asm, new_addr)
            for i in range(0, len(bytecode)):
                buffer[new_addr - addr + i] = bytecode[i]
        elif len(block["exits"]) == 2:
            child_true = Scanner.find_block(block["exits"][0], blist)
            child_false = Scanner.find_block(block["exits"][1], blist)
            Helper.assert_true(child_true is not None, "Child_true not found", None)
            Helper.assert_true(child_false is not None, "Child_false not found", None)
            last = len(block["opcodes"]) - 1
            asm = str(block["opcodes"][last].mnemonic) + " " + hex(child_true["new_offsets"][0])
            new_addr = block["new_offsets"][last]
            bytecode, _ = Helper.global_data["ass"].asm(asm, new_addr)
            block["new_sizes"][last] = len(bytecode)
            for i in range(0, len(bytecode)):
                buffer[new_addr - addr + i] = bytecode[i]
            asm = "jmp " + hex(child_false["new_offsets"][0])
            new_addr = block["new_offsets"][last] + block["new_sizes"][last]
            bytecode, _ = Helper.global_data["ass"].asm(asm, new_addr)
            for i in range(0, len(bytecode)):
                buffer[new_addr - addr + i] = bytecode[i]
    Helper.assert_true(True, "", "Rebuilding done")
    return bytes(buffer)
