import os, sys
import pefile, capstone
BASE = os.environ.get("VMWARE_DIR")   # local VMware Workstation install dir
if not BASE: sys.exit("set VMWARE_DIR to your local 'VMware Workstation' install dir")
pe = pefile.PE(BASE + "/vnetlib.dll")
base = pe.OPTIONAL_HEADER.ImageBase
exports = {}
for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if e.name:
        exports[e.name.decode()] = base + e.address
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
TARGETS = ["VNL_GetVnetDisplayName","VNL_GetVnetSubnetAddr","VNL_GetVnetSubnetMask",
           "VNL_GetVnetUseDHCP","VNL_GetVnetUseNAT","VNL_GetDHCPParam","VNL_GetNATParam",
           "VNL_SetDHCPParam","VNL_SetNATParam","VNL_AssignSubnetAddressToVnet",
           "VNL_GetNATPortForward","VNL_SetNATPortForward","VNL_EnumNATPortForward",
           "VNL_GetBridgeState","VNL_SetVnetSubnetAddr","VNL_ExportDatabaseToFile"]
for t in TARGETS:
    if t not in exports: print(f"--- {t}: NOT EXPORTED"); continue
    data = pe.get_data(exports[t]-base, 240)
    print(f"--- {t} @ 0x{exports[t]:x}")
    for i in md.disasm(data, exports[t]):
        print(f"    {i.mnemonic} {i.op_str}")
        
        if i.mnemonic == "ret": break
