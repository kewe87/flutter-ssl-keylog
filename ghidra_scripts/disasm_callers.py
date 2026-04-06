# Ghidra: disassemble the TLS keylog caller functions to find ssl_log_secret

program = currentProgram
listing = program.getListing()
funcMgr = program.getFunctionManager()
refMgr = program.getReferenceManager()
baseAddr = program.getImageBase()

# Functions that reference keylog label strings
targets = {
    "tls12_client_random": 0x6c3514,  # CLIENT_RANDOM
    "tls13_handshake":     0x6d3cc0,  # CLIENT/SERVER_HANDSHAKE_TRAFFIC_SECRET
    "tls13_appdata":       0x6d3d5c,  # CLIENT/SERVER_TRAFFIC_SECRET_0, EXPORTER_SECRET
}

all_called = {}

for name, offset in sorted(targets.items(), key=lambda x: x[1]):
    addr = baseAddr.add(offset)
    func = funcMgr.getFunctionAt(addr)
    if not func:
        print("[!] No function at 0x%x for %s" % (offset, name))
        continue

    print("\n" + "=" * 60)
    print("Function: %s at %s (offset 0x%x)" % (name, addr, offset))
    body = func.getBody()
    print("Size: %d bytes" % body.getNumAddresses())

    # Print all instructions
    inst = listing.getInstructionAt(addr)
    call_targets = []
    while inst and body.contains(inst.getAddress()):
        instStr = str(inst)
        instAddr = inst.getAddress()
        instOffset = instAddr.subtract(baseAddr)

        # Highlight calls (BL, BLR)
        mnemonic = inst.getMnemonicString()
        if mnemonic in ["bl", "blr", "b"]:
            # Get the call target
            refs = inst.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType().isCall() or ref.getReferenceType().isJump():
                    targetAddr = ref.getToAddress()
                    targetOffset = targetAddr.subtract(baseAddr)
                    targetFunc = funcMgr.getFunctionAt(targetAddr)
                    targetName = targetFunc.getName() if targetFunc else "unknown"
                    print("  0x%06x: %-40s -> %s at 0x%x (%s)" % (
                        instOffset, instStr, targetName, targetOffset,
                        "CALL" if ref.getReferenceType().isCall() else "JUMP"))
                    call_targets.append((targetAddr, targetOffset, targetName))
                    if targetName not in all_called:
                        all_called[targetName] = []
                    all_called[targetName].append(name)
        else:
            print("  0x%06x: %s" % (instOffset, instStr))

        inst = inst.getNext()

    print("\nCalls from %s:" % name)
    for t_addr, t_off, t_name in call_targets:
        print("  -> %s at 0x%x" % (t_name, t_off))

# Find common called function = ssl_log_secret
print("\n" + "=" * 60)
print("COMMON CALLED FUNCTIONS (candidates for ssl_log_secret):")
print("=" * 60)

for fname, callers in sorted(all_called.items()):
    if len(callers) >= 2:
        print("  %s called by: %s" % (fname, ", ".join(callers)))
        # Get function details
        for func in funcMgr.getFunctions(True):
            if func.getName() == fname:
                faddr = func.getEntryPoint()
                foff = faddr.subtract(baseAddr)
                print("    Address: %s (offset 0x%x)" % (faddr, foff))
                print("    Size: %d bytes" % func.getBody().getNumAddresses())
                # Print params
                params = func.getParameters()
                print("    Params: %d" % len(params))
                for p in params:
                    print("      %s %s" % (p.getDataType(), p.getName()))
                break
