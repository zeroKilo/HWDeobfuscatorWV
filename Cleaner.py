import Helper
import Scanner


def clean_graph(blist):
    print("Start cleaning graph")
    fix_counter = 0
    found_fix = True
    while found_fix:
        found_fix = clean_simple_jumps(blist)
        if found_fix:
            fix_counter = fix_counter + 1
    found_fix = True
    while found_fix:
        found_fix = clean_consecutive_blocks(blist)
        if found_fix:
            fix_counter = fix_counter + 1
    found_fix = True
    while found_fix:
        found_fix = clean_direct_jumps(blist)
        if found_fix:
            fix_counter = fix_counter + 1
    found_fix = True
    while found_fix:
        found_fix = clean_obfuscated_jumps_method1(blist)
        if found_fix:
            fix_counter = fix_counter + 1
    found_fix = True
    while found_fix:
        found_fix = clean_obfuscated_jumps_method2(blist)
        if found_fix:
            fix_counter = fix_counter + 1
    found_fix = True
    while found_fix:
        found_fix = clean_obfuscated_jumps_method3(blist)
        if found_fix:
            fix_counter = fix_counter + 1
    print("Finished cleaning, applied", str(fix_counter), "Fixes")


def clean_simple_jumps(blist):
    fixed_list = []
    clean_entries(blist)
    found_fix = remove_simple_jumps(blist[0], blist, fixed_list)
    return found_fix


def clean_consecutive_blocks(blist):
    fixed_list = []
    clean_entries(blist)
    found_fix = combine_consecutive_blocks(blist[0], blist, fixed_list)
    return found_fix


def clean_direct_jumps(blist):
    fixed_list = []
    clean_entries(blist)
    found_fix = remove_direct_jumps(blist[0], blist, fixed_list)
    return found_fix


def clean_obfuscated_jumps_method1(blist):
    fixed_list = []
    clean_entries(blist)
    found_fix = replace_obfuscated_jumps_method1(blist[0], blist, fixed_list)
    return found_fix


def clean_obfuscated_jumps_method2(blist):
    patterns = Helper.get_jmp14_patterns()
    found_fix = False
    for pattern in patterns:
        fixed_list = []
        clean_entries(blist)
        found_fix = replace_obfuscated_jumps_method2(blist[0], blist, fixed_list, pattern)
        if found_fix:
            break
    return found_fix


def clean_obfuscated_jumps_method3(blist):
    fixed_list = []
    clean_entries(blist)
    found_fix = replace_obfuscated_jumps_method3(blist[0], blist, fixed_list)
    return found_fix


def clean_entries(blist):
    for i in range(0, len(blist)):
        blist[i]["entries"] = []
        for b in blist:
            if blist[i]["start"] in b["exits"]:
                blist[i]["entries"].append(b["start"])


def link_parents_to_child(block, blist):
    child = Scanner.find_block(block["exits"][0], blist)
    Helper.assert_true(child is not None, "Child not found", None)
    print("Linking parents of block at", hex(block["start"]), "with child block at", hex(child["start"]))
    for entry in block["entries"]:
        parent = Scanner.find_block(entry, blist)
        if parent is not None:
            found = False
            print("- Fixing parent block at", hex(parent["start"]))
            for i in range(0, len(parent["exits"])):
                if parent["exits"][i] == block["start"]:
                    parent["exits"][i] = child["start"]
                    found = True
                    break
            Helper.assert_true(found, "Failed to fix parent", None)
            found = False
            for i in range(0, len(child["entries"])):
                entry = child["entries"][i]
                if entry == block["start"]:
                    child["entries"][i] = parent["start"]
                    found = True
                    break
            if not found:
                child["entries"].append(parent["start"])


def remove_simple_jumps(block, blist, fixed_list):
    found_fix = False
    fixed_list.append(block["start"])
    if len(block["opcodes"]) == 1 and len(block["exits"]) == 1:
        if str(block["opcodes"][0].mnemonic) == "jmp" and str(block["opcodes"][0].op_str).startswith("0x"):
            found_fix = True
            link_parents_to_child(block, blist)
            print("- Removed simple jump block at", hex(block["start"]))
            blist.remove(block)
    if not found_fix:
        for ex in block["exits"]:
            if ex not in fixed_list:
                child = Scanner.find_block(ex, blist)
                if child is not None and remove_simple_jumps(child, blist, fixed_list):
                    found_fix = True
                    break
    return found_fix


def combine_consecutive_blocks(block, blist, fixed_list):
    found_fix = False
    fixed_list.append(block["start"])
    if len(block["opcodes"]) > 1 and len(block["exits"]) == 1:
        child = Scanner.find_block(block["exits"][0], blist)
        Helper.assert_true(child is not None, "Child not found", None)
        if len(child["entries"]) == 1:
            found_fix = True
            if str(block["opcodes"][-1].mnemonic) == "jmp" and str(block["opcodes"][-1].op_str).startswith("0x"):
                block["opcodes"] = block["opcodes"][:-1]
            for opc in child["opcodes"]:
                block["opcodes"].append(opc)
            block["exits"] = []
            for ex in child["exits"]:
                block["exits"].append(ex)
            print("Removed consecutive block at", hex(child["start"]))
            blist.remove(child)
    if not found_fix:
        for ex in block["exits"]:
            if ex not in fixed_list:
                child = Scanner.find_block(ex, blist)
                if child is not None and combine_consecutive_blocks(child, blist, fixed_list):
                    found_fix = True
                    break
    return found_fix


def remove_direct_jumps(block, blist, fixed_list):
    found_fix = False
    fixed_list.append(block["start"])
    if len(block["opcodes"]) > 0:
        if str(block["opcodes"][-1].mnemonic) == "jmp" and str(block["opcodes"][-1].op_str).startswith("0x"):
            found_fix = True
            block["opcodes"] = block["opcodes"][:-1]
            print("Removed simple jump in block", hex(block["start"]))
    if not found_fix and len(block["opcodes"]) > 1:
        if str(block["opcodes"][-2].mnemonic) == "push" and str(block["opcodes"][-2].op_str).startswith("0x"):
            if str(block["opcodes"][-1].mnemonic) == "ret":
                found_fix = True
                block["opcodes"] = block["opcodes"][:-2]
                print("Removed push jump in block", hex(block["start"]))
                if len(block["opcodes"]) == 0:
                    link_parents_to_child(block, blist)
                    print("- Removed empty block", hex(block["start"]))
                    blist.remove(block)
    if not found_fix:
        for ex in block["exits"]:
            if ex not in fixed_list:
                child = Scanner.find_block(ex, blist)
                if child is not None and remove_direct_jumps(child, blist, fixed_list):
                    found_fix = True
                    break
    return found_fix


def replace_obfuscated_jumps_method1(block, blist, fixed_list):
    found_fix = False
    fixed_list.append(block["start"])
    pattern = [
        "ret",
        "pop",
        "pop",
        "mov",
        "cmov",
        "mov",
        "mov",
        "push",
        "push",
        "push",
    ]
    if len(block["opcodes"]) >= 10:
        found = True
        for i in range(0, 10):
            if not str(block["opcodes"][(-i - 1)].mnemonic).startswith(pattern[i]):
                found = False
                break
        if found:
            replace_addr = block["opcodes"][-10].address
            asm = "j" + str(block["opcodes"][-5].mnemonic)[4:] + " 0x0"
            print("Found obfuscated jump in", hex(block["start"]), "replacing with", asm, "at", hex(replace_addr))
            new_bytecode, _ = Helper.global_data["ass"].asm(asm)
            new_bytecode = bytes(new_bytecode)
            new_opcs = Helper.global_data["dis"].disasm(new_bytecode, replace_addr)
            new_opc = None
            for opc in new_opcs:
                new_opc = opc
                break
            block["opcodes"] = block["opcodes"][:-10]
            block["opcodes"].append(new_opc)
            found_fix = True
    if not found_fix:
        for ex in block["exits"]:
            if ex not in fixed_list:
                child = Scanner.find_block(ex, blist)
                if child is not None and replace_obfuscated_jumps_method1(child, blist, fixed_list):
                    found_fix = True
                    break
    return found_fix


def replace_obfuscated_jumps_method2(block, blist, fixed_list, pattern):
    found_fix = False
    fixed_list.append(block["start"])
    if len(block["opcodes"]) >= 14:
        found = True
        for i in range(0, 14):
            if not str(block["opcodes"][(-i - 2)].mnemonic).startswith(pattern[i]):
                found = False
                break
        if found:
            replace_addr = block["opcodes"][-14].address
            asm = "j" + str(block["opcodes"][-8].mnemonic)[4:] + " 0x0"
            print("Found obfuscated jump in", hex(block["start"]), "replacing with", asm, "at", hex(replace_addr))
            new_bytecode, _ = Helper.global_data["ass"].asm(asm)
            new_bytecode = bytes(new_bytecode)
            new_opcs = Helper.global_data["dis"].disasm(new_bytecode, replace_addr)
            new_opc = None
            for opc in new_opcs:
                new_opc = opc
                break
            block["opcodes"] = block["opcodes"][:-15]
            block["opcodes"].append(new_opc)
            found_fix = True
    if not found_fix:
        for ex in block["exits"]:
            if ex not in fixed_list:
                child = Scanner.find_block(ex, blist)
                if child is not None and replace_obfuscated_jumps_method2(child, blist, fixed_list, pattern):
                    found_fix = True
                    break
    return found_fix


def replace_obfuscated_jumps_method3(block, blist, fixed_list):
    found_fix = False
    fixed_list.append(block["start"])
    if len(block["opcodes"]) >= 4:
        opcs = block["opcodes"]
        if len(opcs) >= 4:
            start = len(opcs) - 4
            if str(opcs[start].mnemonic) == "push" and str(opcs[start].op_str).startswith("0x"):
                if str(opcs[start + 1].mnemonic) == "push" and str(opcs[start + 1].op_str).startswith("dword ptr"):
                    addr = int(str(opcs[start + 1].op_str)[13:-1], 16)
                    if 0x003F2A34 < addr < 0x003F2EB0:
                        if str(opcs[start + 2].mnemonic) == "lea" and str(opcs[start + 2].op_str) == "esp, [esp + 4]":
                            if str(opcs[start + 3].mnemonic) == "jmp" and str(
                                    opcs[start + 3].op_str) == "dword ptr [esp - 4]":
                                replace_addr = opcs[start].address
                                asm = "call dword ptr [" + hex(addr) + "]"
                                print("Found obfuscated jump in", hex(block["start"]), "replacing with", asm, "at",
                                      hex(replace_addr))
                                new_bytecode, _ = Helper.global_data["ass"].asm(asm)
                                new_bytecode = bytes(new_bytecode)
                                new_opcs = Helper.global_data["dis"].disasm(new_bytecode, replace_addr)
                                new_opc = None
                                for opc in new_opcs:
                                    new_opc = opc
                                    break
                                block["opcodes"] = opcs[:-4]
                                block["opcodes"].append(new_opc)
                                found_fix = True
    if not found_fix:
        for ex in block["exits"]:
            if ex not in fixed_list:
                child = Scanner.find_block(ex, blist)
                if child is not None and replace_obfuscated_jumps_method3(child, blist, fixed_list):
                    found_fix = True
                    break
    return found_fix
