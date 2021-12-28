import Helper
from ctypes import *


def alloc_mem(handle, size):
    page_rwx_value = 0x40
    mem_commit = 0x00001000
    return windll.kernel32.VirtualAllocEx(handle, 0, size, mem_commit, page_rwx_value)


def inject(handle, old_addr, new_addr, byte_code):
    print("Injecting new byte code")
    handle.write_bytes(new_addr, byte_code, len(byte_code))
    asm = "jmp " + hex(new_addr)
    byte_code, _ = Helper.global_data["ass"].asm(asm, old_addr)
    print("Hooking original function")
    handle.write_bytes(old_addr, bytes(byte_code), len(byte_code))