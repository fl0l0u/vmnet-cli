#!/usr/bin/env python3
"""Byte-scan .text for lea reg,[rip+d] pointing at given strings; disassemble referencing funcs."""
import os, sys
import pefile, capstone, re, sys, struct

BASE = os.environ.get("VMWARE_DIR")   # local VMware Workstation install dir
if not BASE: sys.exit("set VMWARE_DIR to your local 'VMware Workstation' install dir")
pe = pefile.PE(BASE + "/vnetlib.dll")
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text')
tva, tdata = base + text.VirtualAddress, text.get_data()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def str_va(s):
    pat = s.encode() + b'\x00'
    hits, i = [], 0
    while True:
        j = pe.__data__.find(pat, i)
        if j == -1: break
        # need start-of-string: preceding byte is 0 or section boundary
        if j == 0 or pe.__data__[j-1] == 0:
            sec = next((x for x in pe.sections if x.PointerToRawData <= j < x.PointerToRawData + x.SizeOfRawData), None)
            if sec: hits.append(base + j - sec.PointerToRawData + sec.VirtualAddress)
        i = j + 1
    return hits

def find_lea_refs(targets):
    """scan 48 8D 05/0D/15/1D/25/2D/35/3D disp32 (lea r64,[rip+disp])"""
    refs = {}
    for m in re.finditer(rb'\x48\x8D[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', tdata):
        disp = struct.unpack('<i', tdata[m.end():m.end()+4])[0]
        tgt = tva + m.start() + 7 + disp
        if tgt in targets:
            refs.setdefault(tgt, []).append(tva + m.start())
    return refs

def containing_func_start(code_va):
    """walk back up to 0x400 for int3 padding / ret end boundary"""
    off = code_va - tva
    d = tdata
    for back in range(1, 0x400):
        if off-back < 0: break
        if d[off-back] == 0xCC and d[off-back-1] in (0xC3, 0x90, 0x00) or (d[off-back:off-back+4] == b'\xCC\xCC\xCC\xCC'):
            return tva + off - back + 1
    return tva + off - 0x40

for s in sys.argv[1:]:
    hits = str_va(s)
    print(f"=== string {s!r} at {[hex(h) for h in hits]} ===")
    refs = find_lea_refs(set(hits))
    for t, codes in refs.items():
        for c in codes:
            fs = containing_func_start(c)
            print(f"  referenced at {hex(c)} in func starting ~{hex(fs)}")
            for i in md.disasm(pe.get_data(pe.get_offset_from_rva(fs - base), 200), fs):
                note = ""
                if i.mnemonic == 'lea' and '[rip +' in i.op_str:
                    tt = i.address + i.size + int(i.op_str.split('[rip + 0x')[1].split(']')[0], 16)
                    ds = pe.get_data(pe.get_offset_from_rva(tt - base), 60).split(b'\x00')[0]
                    if ds and all(32 <= b < 127 for b in ds): note = f"  ; {ds.decode()!r}"
                print(f"    {i.address:x}: {i.mnemonic} {i.op_str}{note}")
                if i.mnemonic == 'ret': break
