#!/usr/bin/env python3
"""PE recon: version info, sections, exports, imports for the network binaries."""
import pefile, sys, os

BASE = os.environ.get("VMWARE_DIR")   # local VMware Workstation install dir
if not BASE: sys.exit("set VMWARE_DIR to your local 'VMware Workstation' install dir")
TARGETS = ["vmnetcfg.exe", "vnetlib.exe", "vnetlib.dll", "vmnetcfgLib.dll",
           "vmnat.exe", "VMnetDHCP.exe", "vmnetBridge.dll", "vnetsniffer.exe", "vnetstats.exe"]

def version_info(pe, path):
    out = {}
    try:
        vi = pe.VS_FIXEDFILEINFO[0]
        out["filever"] = "%d.%d.%d.%d" % (vi.FileVersionMS >> 16, vi.FileVersionMS & 0xffff,
                                          vi.FileVersionLS >> 16, vi.FileVersionLS & 0xffff)
        out["prodver"] = "%d.%d.%d.%d" % (vi.ProductVersionMS >> 16, vi.ProductVersionMS & 0xffff,
                                          vi.ProductVersionLS >> 16, vi.ProductVersionLS & 0xffff)
    except Exception:
        pass
    try:
        for f in pe.FileInfo:
            for entry in f:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            out[k.decode(errors='replace')] = v.decode(errors='replace')
    except Exception:
        pass
    return out

for name in TARGETS:
    path = os.path.join(BASE, name)
    if not os.path.exists(path):
        print(f"=== {name}: NOT PRESENT ===")
        continue
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
    ])
    print(f"=== {name} ===")
    machine = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
    print(f"  arch={machine}  imagebase=0x{pe.OPTIONAL_HEADER.ImageBase:x}")
    vi = version_info(pe, path)
    for k in ("ProductVersion", "FileVersion", "ProductName", "FileDescription"):
        if k in vi:
            print(f"  {k}: {vi[k]}")
    # exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        syms = [e.name.decode() if e.name else f"ord{e.ordinal}" for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        print(f"  EXPORTS ({len(syms)}):")
        for s in sorted(syms):
            print(f"    {s}")
    # imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        dlls = [(e.dll.decode(), len(e.imports)) for e in pe.DIRECTORY_ENTRY_IMPORT]
        print(f"  IMPORTS: " + ", ".join(f"{d}({n})" for d, n in dlls))
    pe.close()
    print()
