#!/usr/bin/env python3
"""Disassemble target functions, resolving every rip-relative reference to its string."""
import os, sys
import pefile, capstone, struct

BASE = os.environ.get("VMWARE_DIR")   # local VMware Workstation install dir
if not BASE: sys.exit("set VMWARE_DIR to your local 'VMware Workstation' install dir")
PATH = BASE + "/vnetlib.dll"
pe = pefile.PE(PATH)
base = pe.OPTIONAL_HEADER.ImageBase
exports = {e.name.decode(): base + e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def va_to_off(va):
    try:
        return pe.get_offset_from_rva(va - base)
    except Exception:
        return None

def read_cstr(va, wide=False):
    off = va_to_off(va)
    if off is None or not (0 <= off < len(pe.__data__)):
        return None
    if wide:
        end = pe.__data__.find(b'\x00\x00', off, off + 512)
        raw = pe.__data__[off:end if end != -1 else off + 256]
        try: return raw.decode('utf-16-le', errors='ignore')
        except Exception: return None
    end = pe.__data__.find(b'\x00', off, off + 512)
    raw = pe.__data__[off:end if end != -1 else off + 256]
    if raw and all(32 <= b < 127 for b in raw):
        return raw.decode('ascii')
    return None

def deref_ptr_string(va):
    """treat va as an 8-byte pointer slot holding a string VA (data xref)."""
    off = va_to_off(va)
    if off is None or not (0 <= off < len(pe.__data__) - 8):
        return None
    ptr = struct.unpack('<Q', pe.__data__[off:off+8])[0]
    if base <= ptr < base + len(pe.__data__):
        return read_cstr(ptr) or read_cstr(ptr, wide=True) or f"0x{ptr:x}"
    return None

TARGETS = ["VNL_GetVnetDisplayName", "VNL_GetVnetSubnetAddr", "VNL_GetVnetUseDHCP",
           "VNL_GetDHCPParam", "VNL_SetDHCPParam", "VNL_AssignSubnetAddressToVnet",
           "VNL_ExportDatabaseToFile", "VNL_GetNATPortForward", "VNL_SetNATPortForward",
           "VNL_EnumNATPortForward", "VNL_GetBridgeState", "VNL_SetVnetSubnetAddr"]

for t in TARGETS:
    if t not in exports:
        continue
    va = exports[t]
    print(f"=== {t} @ 0x{va:x} ===")
    for i in md.disasm(pe.get_data(va - base, 600), va):
        note = ""
        if '[rip' in i.op_str:
            tgt = i.address + i.size + int(i.op_str.split('[rip + 0x')[1].split(']')[0], 16) if '+ 0x' in i.op_str else \
                  i.address + i.size - int(i.op_str.split('[rip - 0x')[1].split(']')[0], 16)
            s = read_cstr(tgt) or read_cstr(tgt, wide=True) or deref_ptr_string(tgt)
            note = f"   ; -> {s!r}" if s else f"   ; -> 0x{tgt:x}"
        if i.mnemonic == 'call' and '0x' in i.op_str and '*' not in i.op_str:
            note = f"   ; -> {i.op_str}"
        print(f"  {i.address:x}: {i.mnemonic} {i.op_str}{note}")
        if i.mnemonic == 'ret':
            break
    print()
