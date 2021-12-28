import subprocess
import Helper


def make_block_text(block):
    result = ""
    for opc in block["opcodes"]:
        result = result + hex(opc.address) + " " + opc.mnemonic + " " + opc.op_str + "\\l"
    return result


def make_block(block):
    result = "\tBlock" + str(block["id"]) + " [shape=box,fontname=\"Lucida Console\""
    result = result + ",fontsize=8,fillcolor=azure2,style=filled,label=\"" + make_block_text(block) + "\"];\n"
    return result


def fix_block_splits(block_list):
    for i in range(0, len(block_list)):
        b = block_list[i]
        for ex in b["exits"]:
            for j in range(0, len(block_list)):
                if block_list[j]["start"] < ex < block_list[j]["end"]:
                    print('Found block split at ' + hex(ex))
                    old_block = block_list[j]
                    new_block = {
                        "start": ex,
                        "end": old_block["end"],
                        "opcodes": [],
                        "entries": [],
                        "exits": old_block["exits"],
                    }
                    new_block["entries"].append(old_block["start"])
                    opcs = old_block["opcodes"]
                    old_block["opcodes"] = []
                    old_block["exits"] = []
                    old_block["exits"].append(ex)
                    old_block["end"] = ex
                    for opc in opcs:
                        if opc.address >= ex:
                            new_block["opcodes"].append(opc)
                        else:
                            old_block["opcodes"].append(opc)
                    block_list[j] = old_block
                    block_list.append(new_block)
                    return True
    return False


def make_graph(block_list, filename):
    while fix_block_splits(block_list):
        pass
    result = "digraph G {\n"
    block_id = 0
    for b in block_list:
        b["id"] = block_id
        result = result + make_block(b)
        block_id = block_id + 1
    for i in range(0, len(block_list)):
        b = block_list[i]
        for ex in b["exits"]:
            found = False
            for j in range(0, len(block_list)):
                if ex == block_list[j]["start"]:
                    result = result + "\tBlock" + str(i) + "->Block" + str(j) + ";\n"
                    found = True
                    break
            if not found:
                Helper.assert_true(found, "Failed to link exit for Block at " + hex(b["start"]), None)
    result = result + "}"
    with open(filename, "w") as output:
        output.write(result)


def make_image(file_graph, file_image):
    cmd = 'dot -Tpng ' + file_graph + ' -o ' + file_image
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    process.communicate()