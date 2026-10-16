#!/usr/bin/env python3
"""Disassemble vnetlib.dll exports by name, annotating strings and calls."""
import pefile, capstone, sys

BASE = os.environ.get("VMWARE_DIR")   # local VMware Workstation install dir
if not BASE: sys.exit("set VMWARE_DIR to your local 'VMware Workstation' install dir")
pe = pefile.PE(BASE + "/vnetlib.dll")
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
exports = {}
for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if e.name:
        exports[e.name.decode()] = base + e.address

def cstr(va, n=80):
    try:
        d = pe.get_data(pe.get_offset_from_rva(va - base), n).split(b"\x00")[0]
        if d and all(32 <= b < 127 for b in d):
            return d.decode()
    except Exception:
        pass
    return None

for name in sys.argv[1:]:
    va = exports.get(name)
    print(f"=== {name} @ {va:x} ===")
    if not va:
        continue
    data = pe.get_data(pe.get_offset_from_rva(va - base), 1200)
    calls = 0
    for i in md.disasm(data, va):
        note = ""
        if i.mnemonic == "lea" and "[rip +" in i.op_str:
            tt = i.address + i.size + int(i.op_str.split("[rip + 0x")[1].split("]")[0], 16)
            s = cstr(tt)
            if s:
                note = f"  ; {s!r}"
        elif i.mnemonic == "call":
            try:
                t = int(i.op_str, 16)
                for en, ev in exports.items():
                    if ev == t:
                        note = f"  ; -> {en}"
                if not note and t in range(base, base + pe.OPTIONAL_HEADER.SizeOfImage):
                    note = "  ; -> local"
            except ValueError:
                pass
        print(f"  {i.address:x}: {i.mnemonic} {i.op_str}{note}")
        if i.mnemonic == "ret":
            calls += 1
            if calls >= 2:
                break
