#!/usr/bin/env python3
"""Which VNL_* functions does vmnetcfg.exe import? Full import-name dump per DLL."""
import os, sys
import pefile

BASE = os.environ.get("VMWARE_DIR")   # local VMware Workstation install dir
if not BASE: sys.exit("set VMWARE_DIR to your local 'VMware Workstation' install dir")
for name in ("vmnetcfg.exe", "vnetlib.exe"):
    pe = pefile.PE(f"{BASE}/{name}", fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    print(f"=== {name} imports ===")
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        dll = e.dll.decode()
        if dll.lower() in ("vnetlib.dll",) or "vmware" in dll.lower():
            print(f"  {dll}:")
            for imp in e.imports:
                print(f"    {imp.name.decode() if imp.name else 'ord' + str(imp.ordinal)}")
        else:
            interesting = [i.name.decode() for i in e.imports if i.name and any(
                k in i.name.decode() for k in (
                    "Pipe", "DeviceIo", "CreateFile", "RegOpen", "RegCreate", "RegSetValue",
                    "RegQuery", "RegEnum", "OpenService", "StartService", "ControlService",
                    "QueryService", "EnumServices", "StartDoc", "WsaStartup"))]
            if interesting:
                print(f"  {dll}: {', '.join(sorted(set(interesting)))}")
    pe.close()
    print()
