import Helper


def get_asm_block(handle, addr, seen_addr, blist, used_hint, hints):
    block = {
        "start": addr,
        "end": addr,
        "opcodes": [],
        "entries": [],
        "exits": [],
    }
    blist.append(block)
    for b in blist:
        for ex in b["exits"]:
            if ex == addr:
                block["entries"].append(b["start"])
    dis = Helper.global_data["dis"]
    print("###################################")
    print("Starting a new block at", hex(addr))
    pos = addr
    while True:
        seen_addr.append(pos)
        buff = handle.read_bytes(pos, 16)
        opcodes = dis.disasm(buff, pos)
        opc = None
        for o in opcodes:
            opc = o
            break
        Helper.assert_true(opc is not None, "BAD OPCODE", None)
        cmd = str(opc.mnemonic)
        oper = str(opc.op_str)
        print("0x%x:\t%s\t%s" % (opc.address, cmd, oper))
        block["opcodes"].append(opc)
        block["end"] = block["end"] + opc.size
        if cmd.startswith("j"):
            block["exits"] = find_exits_jmp_method1(oper)
            if len(block["exits"]) == 0:
                block["exits"] = find_exits_jmp_method2(block)
            if len(block["exits"]) == 0:
                block["exits"] = find_exits_jmp_method3(block)
            if len(block["exits"]) == 0:
                block["exits"] = find_exits_jmp_method4(block)
            if len(block["exits"]) == 0:
                block["exits"] = find_exits_jmp_method5(block, blist)
            if not cmd == "jmp":
                block["exits"].append(block["end"])
            if len(block["exits"]) == 0:
                for hint in hints:
                    if int(hint["address"], 16) == opc.address:
                        block["exits"] = []
                        for ex in hint["exits"]:
                            block["exits"].append(int(ex, 16))
                        used_hint.append(opc.address)
                        Helper.assert_true(True, "", "Used hint, this prevents rebuilding!")
            break
        elif cmd == "ret":
            block["exits"] = find_exits_ret_method1(block, blist)
            if len(block["exits"]) == 0:
                block["exits"] = find_exits_ret_method2(block["opcodes"])
            break
        pos += opc.size
        if pos in seen_addr:
            block["exits"].append(pos)
            break
    print("Stopping block at", hex(block["end"]))
    print("Found Exits:")
    for ex in block["exits"]:
        print(" -", hex(ex), "(Seen :", str(ex in seen_addr) + ")")
    for ex in block["exits"]:
        if ex not in seen_addr:
            get_asm_block(handle, ex, seen_addr, blist, used_hint, hints)
    return block


def find_block(addr, blist):
    for b in blist:
        if b["start"] == addr:
            return b
    return None


def find_exits_jmp_method1(oper):
    exits = []
    passed = False
    if oper.startswith("0x"):
        try:
            exits.append(int(oper[2:], 16))
            passed = True
        except:
            pass
    Helper.print_method_result(passed, "find_exits_jmp_method1")
    return exits


def find_exits_jmp_method2(block):
    exits = []
    passed = False
    opcs = block["opcodes"]
    start = len(opcs) - 2
    if str(opcs[start].mnemonic) == "push" and str(opcs[start + 1].mnemonic) == "jmp":
        addr = int(str(opcs[start].op_str)[2:], 16)
        test = str(opcs[start + 1].op_str)
        if test.startswith("dword ptr [0x"):
            test2 = int(test[13:-1], 16)
            if 0x003F2A34 < test2 < 0x003F2EB0:
                exits.append(addr)
                passed = True
        elif len(test) == 3 and test[0] == 'e' and test[2] == 'x' and addr > 0x3F0000:
            exits.append(addr)
            passed = True
    Helper.print_method_result(passed, "find_exits_jmp_method2")
    return exits


def find_exits_jmp_method3(block):
    exits = []
    passed = False
    opcs = block["opcodes"]
    if len(opcs) >= 3:
        start = len(opcs) - 3
        if str(opcs[start].mnemonic) == "push" and str(opcs[start].op_str).startswith("0x"):
            addr = int(str(opcs[start].op_str)[2:], 16)
            if str(opcs[start + 1].mnemonic) == "lea" and str(opcs[start + 1].op_str) == "esp, [esp + 4]":
                if str(opcs[start + 2].mnemonic) == "jmp" and str(opcs[start + 2].op_str) == "dword ptr [esp - 4]":
                    exits.append(addr)
                    offset = opcs[start].address
                    asm = "jmp " + hex(addr)
                    new_bytecode, _ = Helper.global_data["ass"].asm(asm)
                    new_bytecode = bytes(new_bytecode)
                    new_opcs = Helper.global_data["dis"].disasm(new_bytecode, offset)
                    new_opc = None
                    for opc in new_opcs:
                        new_opc = opc
                        break
                    block["opcodes"] = opcs[:-3]
                    block["opcodes"].append(new_opc)
                    passed = True
    Helper.print_method_result(passed, "find_exits_jmp_method3")
    return exits


def find_exits_jmp_method4(block):
    exits = []
    passed = False
    opcs = block["opcodes"]
    if len(opcs) >= 4:
        start = len(opcs) - 4
        if str(opcs[start].mnemonic) == "push" and str(opcs[start].op_str).startswith("0x"):
            addr = int(str(opcs[start].op_str)[2:], 16)
            if str(opcs[start + 1].mnemonic) == "push" and str(opcs[start + 1].op_str).startswith("dword ptr"):
                test = int(str(opcs[start + 1].op_str)[13:-1], 16)
                if 0x003F2A34 < test < 0x003F2EB0:
                    if str(opcs[start + 2].mnemonic) == "lea" and str(opcs[start + 2].op_str) == "esp, [esp + 4]":
                        if str(opcs[start + 3].mnemonic) == "jmp" and str(opcs[start + 3].op_str) == "dword ptr [esp - 4]":
                            exits.append(addr)
                            passed = True
    Helper.print_method_result(passed, "find_exits_jmp_method4")
    return exits


def find_exits_jmp_method5(block, blist):
    exits = []
    patterns = Helper.get_jmp14_patterns()
    for pattern in patterns:
        exits = find_exits_jmp14(block, blist, pattern, 7, 13)
        if len(exits) > 0:
            break
    Helper.print_method_result(len(exits) > 0, "find_exits_jmp_method5")
    return exits


def find_exits_jmp14(block, blist, pattern, exitpos1, exitpos2):
    exits = []
    currBlock = block
    collOpcs = []
    while len(collOpcs) < 14:
        count = len(currBlock["opcodes"])
        for i in range(0, count):
            opc = currBlock["opcodes"][count - i - 1]
            cmd = str(opc.mnemonic)
            if not cmd == "jmp":
                collOpcs.append(opc)
        if len(currBlock["entries"]) == 1:
            fblock = find_block(currBlock["entries"][0], blist)
            if fblock is not None:
                currBlock = fblock
            else:
                break
        else:
            break
    passed = False
    if len(collOpcs) >= 14:
        passed = True
        for i in range(0, 14):
            if not str(collOpcs[i].mnemonic).startswith(pattern[i]):
                passed = False
                break
    if passed:
        tmp = str(collOpcs[exitpos1].op_str).split(",")[1].strip()
        exit1 = int(tmp[2:], 16)
        tmp = str(collOpcs[exitpos2].op_str)
        exit2 = int(tmp[2:], 16)
        exits.append(exit1)
        exits.append(exit2)
    Helper.print_method_result(passed, "find_exits_jmp_method5")
    return exits


def find_exits_ret_method1(block, blist):
    exits = []
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
    currBlock = block
    collOpcs = []
    while len(collOpcs) < 10:
        count = len(currBlock["opcodes"])
        for i in range(0, count):
            opc = currBlock["opcodes"][count - i - 1]
            cmd = str(opc.mnemonic)
            if not cmd == "jmp":
                collOpcs.append(opc)
            if len(collOpcs) == 10:
                break
        if len(currBlock["entries"]) == 1:
            fblock = find_block(currBlock["entries"][0], blist)
            if fblock is not None:
                currBlock = fblock
            else:
                break
        else:
            break
    passed = False
    if len(collOpcs) >= 10:
        passed = True
        for i in range(0, 10):
            if not str(collOpcs[i].mnemonic).startswith(pattern[i]):
                passed = False
                break
    if passed:
        tmp = str(collOpcs[5].op_str).split(",")[1].strip()
        exit1 = int(tmp[2:], 16)
        tmp = str(collOpcs[9].op_str)
        exit2 = int(tmp[2:], 16)
        exits.append(exit1)
        exits.append(exit2)
    Helper.print_method_result(passed, "find_exits_ret_method1")
    return exits


def find_exits_ret_method2(opcs):
    exits = []
    passed = False
    if len(opcs) > 1:
        start = len(opcs) - 2
        if str(opcs[start].mnemonic) == "push":
            if str(opcs[start].op_str).startswith("0x"):
                if str(opcs[start + 1].mnemonic) == "ret":
                    exits.append(int(str(opcs[start].op_str)[2:], 16))
                    passed = True
    Helper.print_method_result(passed, "find_exits_ret_method2")
    return exits
