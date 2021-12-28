import sys
import Helper
import Scanner
import GraphHelper
import Cleaner
import Rebuilder
import Injector


graph_name = "graph.txt"
image_name = "graph.png"
graph_name_cleaned = "graph_clean.txt"
image_name_cleaned = "graph_clean.png"
result_binary_name = "result.bin"


Helper.init_helper()
Helper.file_delete(graph_name)
Helper.file_delete(image_name)
Helper.file_delete(graph_name_cleaned)
Helper.file_delete(image_name_cleaned)
Helper.file_delete(result_binary_name)
config = Helper.load_config()
pid = Helper.get_process_id()
Helper.assert_true(pid is not None, "Happy Wars process not found", "Found Happy Wars proces id = " + str(pid))
handle = Helper.get_process_handle()
Helper.assert_true(handle is not None, "could not get a process handle", "Got handle to process")
base_addr = Helper.get_base_addr(handle)
Helper.assert_true(base_addr is not None, "could not get a base address", "Got base address = " + hex(base_addr))
Helper.assert_true(base_addr == 0x3F0000, "base address should be 0x3F0000, remove ASLR first!", "Base address correct")
test = Helper.mem_read_int(handle, base_addr)
Helper.assert_true(test == 0x905A4D, "EXE header not found!", "EXE header found")
start_addr = int(config["startaddress"], 16)
Helper.assert_true(start_addr > base_addr, "start address is lower than base address", "Start address OK")
seen_addr = []
blist = []
used_hint = []
block = Scanner.get_asm_block(handle, start_addr, seen_addr, blist, used_hint, config["hints"])
Helper.assert_true(True, "", "Scanning done")
seen_addr = []
Helper.print_block(block, 0, blist, seen_addr)
Helper.assert_true(True, "", "Tree printing done")
GraphHelper.make_graph(blist, graph_name)
Helper.assert_true(Helper.file_exists(graph_name), "Graph file was not created", "Graph file was created")
GraphHelper.make_image(graph_name, image_name)
Helper.assert_true(Helper.file_exists(image_name), "Image file was not created", "Image file was created")
Cleaner.clean_graph(blist)
GraphHelper.make_graph(blist, graph_name_cleaned)
Helper.assert_true(Helper.file_exists(graph_name_cleaned), "Graph file was not created", "Graph file was created")
GraphHelper.make_image(graph_name_cleaned, image_name_cleaned)
Helper.assert_true(Helper.file_exists(image_name_cleaned), "Image file was not created", "Image file was created")
if config["rebuild"] == 1 and len(used_hint) == 0:
    byte_code = Rebuilder.rebuild(blist, start_addr)
    print("New binary size =", hex(len(byte_code)))
    rebuild_addr = Injector.alloc_mem(handle.process_handle, len(byte_code))
    print("Allocated new memory at", hex(rebuild_addr))
    byte_code = Rebuilder.rebuild(blist, rebuild_addr)
    Helper.save_binary(byte_code, result_binary_name)
    if config["inject"] == 1:
        Helper.assert_true(Helper.file_exists(result_binary_name), "Result binary was not created", "Result binary was created")
        Injector.inject(handle, start_addr, rebuild_addr, byte_code)
Helper.assert_true(True, "", "Done!")
