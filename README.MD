# Happy Wars deobfuscator by Warranty Voider

this tool helps to revert the obfuscation applied to functions in the game Happy Wars

about the obfuscation:

- asm blocks are split up and inbetween single jmps are inserted
- asm blocks are scattered randomly throughout binary
- ends of asm blocks have their control flow obfuscated
- maybe more

this tool does (in this order, depending on config.json):

- find process ID by name
- gets handle to it
- starts scanning asm blocks at start address
- reconstructs the control flow graph
- cleans it, replaces obfuscations
- rebuilds asm blocks to one binary blob
- injects it to new memory in process
- replaces original function with jmp to new function

after this, you can dump it from memory, insert in IDA Pro or Ghidra and let it decompile

NOTICE: this script was only a first attempt, its far from done!!! its just a codebase for other projects like this :)