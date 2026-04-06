# Ghidra: disassemble the real ssl_log_secret (FUN_007cdff8) to find client_random access

program = currentProgram
listing = program.getListing()
funcMgr = program.getFunctionManager()
baseAddr = program.getImageBase()

# FUN_007cdff8 = real ssl_log_secret at offset 0x6cdff8
addr = baseAddr.add(0x6cdff8)
func = funcMgr.getFunctionAt(addr)
if not func:
    print("[!] No function at 0x6cdff8")
else:
    print("Function: %s at %s (size %d bytes)" % (func.getName(), addr, func.getBody().getNumAddresses()))
    print()

    inst = listing.getInstructionAt(addr)
    while inst and func.getBody().contains(inst.getAddress()):
        iaddr = inst.getAddress()
        offset = iaddr.subtract(baseAddr)
        mnem = inst.getMnemonicString()

        # Get references
        refs = inst.getReferencesFrom()
        refStr = ""
        for ref in refs:
            targetFunc = funcMgr.getFunctionAt(ref.getToAddress())
            if targetFunc:
                refStr = " -> %s" % targetFunc.getName()
            elif ref.getReferenceType().isCall():
                refStr = " -> CALL 0x%x" % ref.getToAddress().subtract(baseAddr)

        print("  0x%06x: %-50s%s" % (offset, str(inst), refStr))
        inst = inst.getNext()

# Also decompile it if possible
print("\n=== Decompiled ===")
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(program)
results = decomp.decompileFunction(func, 60, monitor)
if results.decompileCompleted():
    print(results.getDecompiledFunction().getC())
else:
    print("[!] Decompilation failed: %s" % results.getErrorMessage())
decomp.dispose()
