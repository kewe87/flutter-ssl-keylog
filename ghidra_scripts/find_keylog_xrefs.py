# Ghidra headless script: find xrefs to TLS keylog label strings
# and ssl_log_secret function in libflutter.so
#
# Run with:
# analyzeHeadless D:\romo\ghidra_proj flutter2 -process libflutter.so \
#   -postScript find_keylog_xrefs.py -noanalysis

from ghidra.program.util import DefinedDataIterator
from ghidra.program.model.symbol import RefType
import ghidra.program.model.address as addr

# Strings we want to find xrefs for
TARGET_STRINGS = [
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
    "CLIENT_RANDOM",
    "CERTIFICATE_VERIFY_FAILED",
    "SecureSocket_RegisterKeyLogPort",
    "SSL_write",
    "SSL_read",
]

program = currentProgram
listing = program.getListing()
refMgr = program.getReferenceManager()
funcMgr = program.getFunctionManager()
mem = program.getMemory()
baseAddr = program.getImageBase()

print("=" * 60)
print("TLS KeyLog Xref Finder for libflutter.so")
print("Base address: %s" % baseAddr)
print("=" * 60)

# Step 1: Find string addresses
def findStrings(target):
    """Search memory for a null-terminated string."""
    results = []
    target_bytes = bytearray(target.encode('ascii') + b'\x00')
    blocks = mem.getBlocks()
    for block in blocks:
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        searchAddr = start
        while searchAddr is not None and searchAddr.compareTo(end) < 0:
            searchAddr = mem.findBytes(searchAddr, end, target_bytes, None, True, monitor)
            if searchAddr is not None:
                results.append(searchAddr)
                searchAddr = searchAddr.add(1)
    return results

# Step 2: For each target string, find its address and all xrefs
found_functions = set()

for target in TARGET_STRINGS:
    addrs = findStrings(target)
    if not addrs:
        print("\n[MISS] '%s' not found in memory" % target)
        continue

    for strAddr in addrs:
        offset = strAddr.subtract(baseAddr)
        print("\n[STR] '%s' at %s (offset 0x%x)" % (target, strAddr, offset))

        # Get all references TO this address
        refs = refMgr.getReferencesTo(strAddr)
        refList = []
        while refs.hasNext():
            refList.append(refs.next())

        if not refList:
            # Try nearby addresses (sometimes the ref points to start of string data)
            for delta in range(-8, 9):
                nearAddr = strAddr.add(delta)
                refs2 = refMgr.getReferencesTo(nearAddr)
                while refs2.hasNext():
                    refList.append(refs2.next())

        if not refList:
            print("  [!] No xrefs found")
            continue

        for ref in refList:
            fromAddr = ref.getFromAddress()
            fromOffset = fromAddr.subtract(baseAddr)
            func = funcMgr.getFunctionContaining(fromAddr)
            funcName = func.getName() if func else "unknown"
            funcAddr = func.getEntryPoint() if func else None
            funcOffset = funcAddr.subtract(baseAddr) if funcAddr else 0

            print("  [XREF] from %s (offset 0x%x) in function %s at %s (offset 0x%x)" % (
                fromAddr, fromOffset, funcName,
                funcAddr if funcAddr else "?", funcOffset))

            if func:
                found_functions.add((funcName, funcAddr, funcOffset, target))

# Step 3: For interesting functions, get their full details
print("\n" + "=" * 60)
print("SUMMARY: Functions referencing TLS/SSL strings")
print("=" * 60)

for funcName, funcAddr, funcOffset, target in sorted(found_functions, key=lambda x: x[2]):
    func = funcMgr.getFunctionAt(funcAddr)
    if func:
        body = func.getBody()
        size = body.getNumAddresses()
        print("\n  Function: %s" % funcName)
        print("  Address:  %s (offset 0x%x from base)" % (funcAddr, funcOffset))
        print("  Size:     %d bytes" % size)
        print("  Refs string: '%s'" % target)

        # Check if this function could be ssl_log_secret
        # ssl_log_secret takes (SSL*, label, secret, secret_len)
        # and calls the keylog_callback
        params = func.getParameterCount()
        print("  Params:   %d" % params)

# Step 4: Look for the keylog callback setter
print("\n" + "=" * 60)
print("Looking for SSL_CTX_set_keylog_callback pattern...")
print("=" * 60)

# This function is small: it takes (SSL_CTX*, callback) and stores callback in ctx
# Look for functions that reference "keylog" strings
keylog_addrs = findStrings("keylog")
for ka in keylog_addrs:
    offset = ka.subtract(baseAddr)
    print("[STR] 'keylog' at %s (offset 0x%x)" % (ka, offset))
    refs = refMgr.getReferencesTo(ka)
    while refs.hasNext():
        ref = refs.next()
        fromAddr = ref.getFromAddress()
        func = funcMgr.getFunctionContaining(fromAddr)
        if func:
            print("  [XREF] from %s in %s (offset 0x%x)" % (
                fromAddr, func.getName(), func.getEntryPoint().subtract(baseAddr)))

print("\n[DONE]")
