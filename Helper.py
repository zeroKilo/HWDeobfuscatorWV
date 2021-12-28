import os
import json
import pymem
import psutil
from os.path import exists
from colorama import init, Back, Fore, Style
import Scanner
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

global_data = {}


def init_helper():
    init()
    global_data["dis"] = Cs(CS_ARCH_X86, CS_MODE_32)
    global_data["ass"] = Ks(KS_ARCH_X86, KS_MODE_32)


def file_delete(filename):
    if file_exists(filename):
        os.remove(filename)


def file_exists(filename):
    return exists(filename)


def save_binary(blob, filename):
    f = open(filename, 'wb')
    f.write(blob)
    f.close()


def load_config():
    with open('config.json') as json_file:
        return json.load(json_file)


def print_method_result(result, method):
    if result:
        print(Fore.LIGHTGREEN_EX + "METHOD", method, "PASSED" + Style.RESET_ALL)
    else:
        print(Fore.LIGHTRED_EX + "METHOD", method, "FAILED" + Style.RESET_ALL)


def assert_true(cond, error, passed):
    if not cond:
        print(Back.LIGHTRED_EX + Fore.BLACK + "ERROR : " + error + Style.RESET_ALL)
        print("Usage:")
        print(" python HWDeobfuscatorWV [address]")
        print("Example:")
        print(" python HWDeobfuscatorWV 11904B0")
        quit()
    elif passed is not None:
        print(Back.LIGHTGREEN_EX + Fore.BLACK + "PASS  : " + passed + Style.RESET_ALL)


def get_process_id():
    process_name = "HappyWars"
    pid = None
    for proc in psutil.process_iter():
        if process_name in proc.name():
            pid = proc.pid
    return pid


def get_process_handle():
    return pymem.Pymem("HappyWars.exe")


def get_base_addr(handle):
    return pymem.process.module_from_name(handle.process_handle, "HappyWars.exe").lpBaseOfDll


def mem_read_int(handle, addr):
    return handle.read_int(addr)


def print_block(block, tabs, blist, seen_addr):
    seen_addr.append(block["start"])
    s = ""
    for i in range(0, tabs):
        s = s + "+"
    s = s + "Block at " + hex(block["start"])
    print(s)
    for ex in block["exits"]:
        if not ex in seen_addr:
            b = Scanner.find_block(ex, blist)
            if b is not None:
                print_block(b, tabs + 1, blist, seen_addr)


def get_jmp14_patterns():
    return [
                ["lea", "mov", "lea", "lea", "mov", "mov", "cmov",
                 "mov", "mov", "lea", "mov", "mov", "lea", "push"],
                ["lea", "mov", "lea", "mov", "lea", "mov", "cmov",
                 "mov", "mov", "lea", "mov", "lea", "mov", "push"],
                ["lea", "lea", "mov", "mov", "lea", "mov", "cmov",
                 "mov", "mov", "lea", "mov", "lea", "mov", "push"],
                ["lea", "lea", "mov", "lea", "mov", "mov", "cmov",
                 "mov", "mov", "mov", "lea", "lea", "mov", "push"],
                ["lea", "lea", "mov", "mov", "lea", "mov", "cmov",
                 "mov", "mov", "lea", "mov", "mov", "lea", "push"],
                ["lea", "lea", "mov", "lea", "mov", "mov", "cmov",
                 "mov", "mov", "lea", "mov", "mov", "lea", "push"],
                ["lea", "mov", "lea", "mov", "lea", "mov", "cmov",
                 "mov", "mov", "mov", "lea", "lea", "mov", "push"]
           ]
