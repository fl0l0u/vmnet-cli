#!/usr/bin/env python3
"""Map VNL_* log tag strings to their functions; extract format strings per function."""
import pefile, capstone, re, sys

BASE = os.environ.get("VMWARE_DIR")   # local VMware Workstation install dir
if not BASE: sys.exit("set VMWARE_DIR to your local 'VMware Workstation' install dir")
pe = pefile.PE(BASE + "/vnetlib.dll")
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text')
tva = base + text.VirtualAddress
tdata = text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def read_cstr(va):
    try:
        off = pe.get_offset_from_rva(va - base)
    except Exception:
        return None
    d = pe.__data__
    end = d.find(b'\x00', off, off + 400)
    raw = d[off:end]
    return raw.decode() if raw and all(32 <= b < 127 for b in raw) else None

# pass 1: all lea rip -> string
lea_map = {}   # code address -> resolved string
insns = list(md.disasm(tdata, tva))
for i in insns:
    if i.mnemonic == 'lea' and '[rip +' in i.op_str:
        tgt = i.address + i.size + int(i.op_str.split('[rip + 0x')[1].split(']')[0], 16)
        s = read_cstr(tgt)
        if s:
            lea_map[i.address] = s
    if i.mnemonic == 'lea' and '[rip -' in i.op_str:
        tgt = i.address + i.size - int(i.op_str.split('[rip - 0x')[1].split(']')[0], 16)
        s = read_cstr(tgt)
        if s:
            lea_map[i.address] = s

# index instructions by address
addr2idx = {i.address: k for k, i in enumerate(insns)}

# pass 2: for each target, find the lea of "FN: " tag, then walk forward to ret
TARGETS = sys.argv[1:]
exports = {e.name.decode(): base + e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
def resolve_thunk(va):
    for _ in range(6):
        off = pe.get_offset_from_rva(va - base)
        ins = list(md.disasm(pe.get_data(off, 16), va))
        if ins and ins[0].mnemonic == 'jmp' and ins[0].op_str.startswith('0x'):
            va = int(ins[0].op_str, 16)
        else:
            return va
    return va

for fn in TARGETS:
    tag = fn + ": "
    entry = None
    for a, s in lea_map.items():
        if s == tag:
            entry = a
            break
    if entry is None and fn in exports:
        # fall back: disassemble from resolved export, collect strings until ret
        va = resolve_thunk(exports[fn])
        fmts = []
        for i in md.disasm(pe.get_data(pe.get_offset_from_rva(va - base), 1200), va):
            s = None
            if i.mnemonic == 'lea' and '[rip +' in i.op_str:
                s = read_cstr(i.address + i.size + int(i.op_str.split('[rip + 0x')[1].split(']')[0], 16))
            if s and s != tag and '%' in s:
                fmts.append(s)
            if i.mnemonic == 'ret':
                break
        print(f"=== {fn} @ {hex(va)} (from export) ===")
        for s in fmts[:12]:
            print(f"   {s!r}")
        continue
    if entry is None:
        print(f"=== {fn}: tag not found ===")
        continue
    k = addr2idx[entry]
    fmts = []
    for i in insns[k:k+400]:
        s = lea_map.get(i.address)
        if s and s != tag and ('%' in s or (s[:1].isalpha() and ' ' in s)):
            fmts.append(s)
        if i.mnemonic in ('ret', 'jmp') and i.address > entry:
            if i.mnemonic == 'ret':
                break
    print(f"=== {fn} @ {hex(entry)} ===")
    for s in fmts[:14]:
        print(f"   {s!r}")
