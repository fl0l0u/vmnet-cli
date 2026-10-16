# vmnetcfg / vnetlib Reverse-Engineering Recon

Target: **VMware Workstation Pro 26.0.1 build 25688693** (win-x64 binaries, from `VMware Workstation.zip`).
Phase A (static analysis) — performed 2026-10-14 on Linux, no execution of the binaries.

---

## 1. Architecture map (confirmed from import tables + strings)

```
vmnetcfg.exe  (MFC/ATL GUI, "Virtual Network Editor Application")
   └─ imports 38 functions from VNETLIB.dll  ← the GUI is a thin shell over vnetlib
vnetlib.exe   ("VMware network install library executable") — CLI wrapper, same dispatcher
vnetlib.dll   ("VMware network install library") — ALL logic, 148 exported VNL_* functions
     │
     ├─ Registry (the authoritative "network database"):
     │     HKLM\SOFTWARE\VMware, Inc.\VMnetLib                    ← params, IPv4 keys
     │     HKLM\SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig        ← per-vmnet entries
     │     HKLM\SOFTWARE\VMware, Inc.\VMnetLib\VMnetBridge
     │     HKLM\SOFTWARE\VMware, Inc.\VMnetAdapter / \VMnetBridge
     │     HKLM\SOFTWARE\VMware, Inc.\Driver Database
     │     HKLM\SYSTEM\CurrentControlSet\Services\VMnetBridge\Parameters
     │     HKLM\SYSTEM\CurrentControlSet\Services\VMnetDHCP\Parameters
     │     HKLM\SYSTEM\CurrentControlSet\Services\VMware NAT Service\Parameters
     │     (Wow6432Node mirrors exist; VMnetLibSaved = backup copy)
     │
     ├─ Config files (consumed by the services at start):
     │     C:\ProgramData\VMware\VMware Workstation\vmnetnat.conf
     │     C:\ProgramData\VMware\VMware Workstation\vmnetdhcp.conf
     │     vmnetdhcp.leases ; %temp%\vnetlib.config / vnetlib.tmp
     │
     ├─ Services controlled via SCM (OpenService/StartService/ControlService):
     │     "VMware NAT Service"   → vmnat.exe
     │     "VMware DHCP Service"  → VMnetDHCP.exe
     │     "VMware Authorization Service" (authd) — checked during operations
     │
     └─ Kernel drivers / device interface:
           \\.\Global\VMnetUserif  ← control device (vmnetuserif.sys): live apply of
           vmnetbridge.sys (VMnetBridge svc, auto-start, netbridge.inf)   bridge/subnet
           vmnetadapter.sys, vmnet.sys, vmx86.sys, hcmon.sys              changes w/o reboot
```

No named-pipe RPC protocol to reverse: **vnetlib talks to the kernel via the
`\\.\Global\VMnetUserif` DeviceIoControl interface and to services via the SCM,
and persists state in the registry + conf files.** The GUI does nothing beyond
calling VNL_* functions.

## 2. vnetlib.dll export surface (148 functions, grouped)

- **Topology**: VNL_GetNumberOfVnets, VNL_FindVNetWithFeatures, VNL_GetVnetDisplayName / Set...,
  VNL_GetVnetSubnetAddr / Mask (Set...), VNL_GetVnetUseDHCP / UseNAT (Set...),
  VNL_AssignSubnetAddressToVnet, VNL_DeleteVnetFromDatabase, VNL_GetVNetFeatures
- **Bridge**: VNL_Get/SetBridgeState, VNL_Get/SetBridgeHints, VNL_QueryTeaming(State),
  VNL_Start/StopBridge, VNL_Install/UninstallNetworkBridge, VNL_SafeToStopBridge
- **NAT**: VNL_Get/SetNATParam, VNL_Get/SetNATPortForward, VNL_EnumNATPortForward,
  VNL_Get/SetNATPrivPort, VNL_EnumNATPrivPort, VNL_GetNATStatus, VNL_Start/Stop/Install/UninstallNAT,
  VNL_UpdateNATFromConfig, VNL_GetNATConfigFilePath
- **DHCP**: VNL_Get/SetDHCPParam, VNL_Set/GetDHCPIPToMAC, VNL_EnumDHCPIPToMAC,
  VNL_GetDHCPStatus, VNL_Start/Stop/Install/UninstallDHCP, VNL_UpdateDHCPFromConfig,
  VNL_GetDHCPConfigFilePath, VNL_GetDHCPLeaseFilePath
- **Adapter**: VNL_Install/UninstallNetworkAdapter, VNL_Get/SetVnetAdapterAddr,
  VNL_Get/SetVnetAdapterUserSpecifiedName, VNL_GetVnetAdapterConfigured/Status,
  VNL_Connect/DisconnectVnetAdapter, VNL_Enable/DisableNetworkAdapter, VNL_UpdateAdapterFromConfig
- **Services/drivers install**: VNL_Install/Uninstall{HostDrivers, UserIf, VMX86, VMCI, USB, Hcmon, ...},
  VNL_Start/Stop{Bridge, DHCP, NAT, UserIf, VMX86, VMCI, Hcmon},
  VNL_Install/Reinstall/UninstallNetworkComponents, VNL_SafeToInstallNetworkComponents
- **Database backup/restore**: VNL_BackupDatabase, VNL_BackupDatabaseInRegistry,
  VNL_Import/ExportDatabaseToFile, VNL_ParseBackupDatabase, VNL_RestoreDatabase(FromRegistry),
  VNL_DeleteNetLibDatabase
- **Packet filter / misc**: VNL_*HostPacketFilter*, VNL_Get/SetCurrentLogLevel, VNL_Version

**The GUI (vmnetcfg.exe) imports exactly these 38**: GetNumberOfVnets, Get/SetVnetDisplayName,
Get/SetVnetSubnetAddr, Get/SetVnetSubnetMask, Get/SetVnetUseDHCP, Get/SetVnetUseNAT,
AssignSubnetAddressToVnet, Get/SetBridgeState, Get/SetDHCPParam, Get/SetNATParam,
Get/SetNATPortForward, EnumNATPortForward, Install{NAT,DHCP,UserIf,NetworkBridge,NetworkAdapter},
ReinstallNetworkComponents, UninstallNetworkComponents, UninstallNetworkAdapter,
Export/ImportDatabaseToFile, Start/Stop{DHCP,NAT}, Update{Adapter,DHCP,NAT}FromConfig.
→ That set is the complete behavioral footprint of "click OK in the Network Editor".

## 3. vnetlib.exe CLI grammar (from command-handler + token table in vnetlib.dll)

Dispatchers found: allStatusFunct, backupFunct, bridge{Install,Uninstall,Start,Stop,Status,Set,
Garp,Ungarp,Team,Unteam,CheckHints}Funct, dhcp{Add,Rem,Install,Uninstall,Start,Stop,Status,Update,
SetUnset}Funct, nat{Add,Rem,Install,Uninstall,Start,Stop,Status,Update}Funct, installSetFunct,
teamUpdateFunct.

Grammar: `vnetlib.exe -- <object> <action> [args]` with objects
`bridge | nat | dhcp | adapter | hostonly | userif | team | database | status | all` and actions
`install | uninstall | start | stop | status | add | rem | set | unset | update | backup | restore |
export | import | delete | garp | ungarp | team | unteam | checkhints | connect | disconnect | enable | disable`.

Known parameter tokens (DHCP/NAT): `leasebegin leaseend leasedefault leasemaximum dnsserver1..3
dnstimeout dnsautodetect dnspolicy dnsretries natip6enable natip6prefix forward noforward privport
unprivport configport udptimeout tcptimeout nbnstimeout nbdstimeout allowanyoui`.

Registry value names confirmed: DHCPDefaultLeaseDuration, DHCPLeaseBeginIP, DHCPLeaseEndIP,
DHCPMaxLeaseDuration, natIp6Enable, natIp6Prefix. NAT port-forward format: `ip:port`.

Note: vnetlib.exe prints "this utility is not intended to be run as a standalone application" —
it is the installer's helper, but the dispatcher is fully present; needs elevation.

## 4. Interface strategy (recommendation)

**Primary: link against / P/Invoke `vnetlib.dll`'s VNL_* exports** — same contract vmnetcfg.exe
uses, stable ABI, handles service+driver ordering internally. A C# or C++ CLI calling
VNL_SetVnetSubnetAddr(...) etc. IS the Network Editor.

**Secondary: XML database round-trip** — VNL_ExportDatabaseToFile → edit → VNL_ImportDatabaseFromFile
gives scripted bulk changes (this is the GUI's "Save/Restore Settings" buttons).

**Fallback: script `vnetlib.exe -- <obj> <action>`** for start/stop/status/install verbs.

Change sequence implied by the API (what OK does): stop affected services → write registry →
VNL_Update{NAT,DHCP}FromConfig (rewrite conf files) → VNL_AssignSubnetAddressToVnet via
VMnetUserif device (live bridge update) → restart services.

## 5. PHASE B RESULTS — verified live on Windows 11 (<test-box>), 2026-10-14

**Confirmed true API signatures** (x64 Microsoft convention, first param is the
vnet NAME STRING `"vmnetN"`, not an index — proven by live ctypes calls + log
format strings in .rdata):

```c
int VNL_Version(void);                         // 0x10000 = API 1.0
int VNL_GetNumberOfVnets(void);                // 20
int VNL_GetVnetDisplayName (const char* v, char* out, int* lenInOut);   // key: DisplayName
int VNL_GetVnetSubnetAddr  (const char* v, char* out, int* lenInOut);   // key: IPSubnetAddress
int VNL_GetVnetSubnetMask  (const char* v, char* out, int* lenInOut);   // key: IPSubnetMask
int VNL_SetVnetSubnetAddr  (const char* v, const char* addr);           // rc=1 on success
int VNL_SetVnetSubnetMask  (const char* v, const char* mask);
int VNL_SetVnetDisplayName (const char* v, const char* name);
int VNL_GetVnetUseDHCP     (const char* v);    // 0/1
int VNL_GetVnetUseNAT      (const char* v);    // 0/1
int VNL_SetVnetUseDHCP     (const char* v, int on);
int VNL_SetVnetUseNAT      (const char* v, int on);
int VNL_AssignSubnetAddressToVnet(const char* v, int overwrite);        // probes 192.168/172.16
int VNL_GetDHCPParam(const char* v, int paramId, int unk0, char* out, int* lenInOut);
int VNL_SetDHCPParam(const char* v, int paramId, const char* value, int len);
int VNL_UpdateDHCPFromConfig(const char* vnet);   // per-vnet! rewrites vmnetdhcp.conf
int VNL_UpdateNATFromConfig(const char* vnet);    // per-vnet! rewrites vmnetnat.conf
int VNL_UpdateAdapterFromConfig(void);            // no args
int VNL_StartDHCP/StopDHCP/StartNAT/StopNAT(void);// rc=1 success
int VNL_InstallNetworkAdapter  (const char* vnet);// creates Adapter\UseAdapter=1
int VNL_UninstallNetworkAdapter(const char* vnet);
int VNL_ConnectVnetAdapter(const char* vnet);     // rc=1
int VNL_DeleteVnetFromDatabase(const char* vnet); // rc=1
int VNL_ExportDatabaseToFile(const wchar_t* file);// SAVES REGISTRY HIVE (regf magic), not XML!
int VNL_ImportDatabaseFromFile(const wchar_t* file);
int VNL_GetVnetAdapterStatus(const char* v, char* out, int* len, int* status); // 4 params
```
rc semantics: most bool/status functions return **1 = success** (VNLIB_STATUS_...),
Install/UninstallAdapter return 0 = success. Check per-function; don't assume.

**Registry database confirmed** — `HKLM\SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig\vmnetN`:
```
IPSubnetAddress  REG_SZ      DisplayName  REG_SZ      JumboPacket (in hive)
IPSubnetMask     REG_SZ
    \Adapter     UseAdapter  REG_DWORD
    \DHCP        UseDHCP     REG_DWORD
    \NAT         UseNAT      REG_DWORD
```

**Config files**: `C:\ProgramData\VMware\vmnetdhcp.conf` + `vmnetnat.conf`
(NOT under \VMware Workstation\ — service Parameters point here:
`VMnetDHCP\Parameters\ConfFile`, `VMware NAT Service\Parameters\ConfigPath`).
ISC-dhcpd format, per-vnet block generated by UpdateDHCPFromConfig:
subnet/32 range = .128-.254, host MAC = **00:50:56:C0:00:0N**, host addr = .1,
DNS = .1 (host-only) / .2 (NAT gateway), lease 1800/7200 defaults.

**Full lifecycle proven via vnetlib.dll + ctypes (no GUI, no vnetlib.exe):**
create vmnet5 (Set addr/mask/usedhcp/displayname) → InstallNetworkAdapter →
UpdateDHCPFromConfig (conf block appeared) → Stop/StartDHCP → delete
(UninstallAdapter → DeleteVnetFromDatabase → StopDHCP → UpdateDHCPFromConfig →
StartDHCP) → machine restored to baseline. Verified by registry + conf diffs.

**vnetlib.exe CLI**: parses `-- obj action` and exits (status all → rc 1) but
prints NOTHING to stdout/stderr in a session-0/non-console context — output goes
through vmwarebase logging. Treat the exe as installer-internal; use the DLL.

**Open items (minor)**: DHCP/NAT paramId enum values (sweep 0-11 returned empty
on fresh install — enum likely maps to conf keys like leasebegin/leaseend;
confirm via SetDHCPParam + conf diff), InstallNetworkAdapter's extra params (RESOLVED
— see §7: 5-arg signature, garbage-arg AV was the real bug), packet filter API.

## 7. BRIDGED networks — mechanism fully reverse engineered + proven live (2026-10-14)

Goal: custom vnet "LAN" bridged on interface "Ethernet" (+ "WLAN"/"Wi-Fi").
The test VM has ONE physical NIC (VirtIO, GUID {<virtio-nic-guid>},
MAC <virtio-nic-mac>); no Wi-Fi exists → WLAN reported as unsupported interface.

### Binding mechanism (the actual GUI mechanism)
`vmnetbridge.sys` is an NDIS filter (netbridge.inf, Class=NetService, hwid
`vmware_bridge`, notify object vmnetbridge.dll). Adapter→segment binding:

    HKLM\SYSTEM\CurrentControlSet\Services\VMnetBridge\Parameters\Adapters\{adapter-guid}\
        VMnet  REG_DWORD = N          ; pin physical adapter to vmnetN (0 = default)

+ a VMnetBridge driver cycle (`sc stop/start VMnetBridge`) applies it. Verified:
after pinning Ethernet→2, `VNL_GetVNetFeatures("vmnet2")` = **0x1** and vmnet0's
0x1 cleared. NDIS binding itself (`vmware_bridge` component) must be Enabled on
the adapter (it is by default; `Get-NetAdapterBinding -ComponentID vmware_bridge`).

### VNL_GetVNetFeatures bits (proven)
0x1 = bridged (follows live driver bindings), 0x100 = host adapter exists,
0x10000 = NAT, 0x1000000 = DHCP. vmnet1=0x01000100, vmnet8=0x01010100.

### Bridge-state struct API (undocumented signatures, cracked from disasm)
```
VNL_GetBridgeState(VNetLib_BridgeState* buf, int size)   size MUST be 0x855c (34140)
VNL_SetBridgeState(VNetLib_BridgeState* buf, int size)   same; rc=1 ok, but driver
                                       recomputes adapter vnet fields from bindings
struct: +0x00 version=1, +0x08 numVnets?, +0x60 adapter entries[64] ×0x208:
  entry+0x04 id(5 seen), +0x08 name (utf16 "\DEVICE\{guid}"), +0x108 name2 (utf16
  description), +0x208 mac[6], +0x210 vnet (READ-ONLY view of binding)
VNL_GetBridgeHints(HintSet*, int vnetNo)              rc=0 when no hints stored
VNL_SetBridgeHints(HintSet*, int vnetNo, int sendIoctl)  rc=1 wrote registry+ioctl 0x81022088
HintSet: +0x00 version=1, +0x18 Hint* ; Hint: next, +0x08 type 0xABCE=require/
  0xABCF=prohibit/0xABD0=?, +0x0c flags(0 unless 0xABD0), +0x10 Criterion* ;
  Criterion: next, +0x08 type 0xDCBB=score/0xDCBC=netflags/0xDCBD=substr(≤50 wchar),
  +0x10 wchar*
Storage: HKLM\SYSTEM\CCS\Services\VMnetBridge\Parameters\Hints%02d\Hint%02d\Criterion%02d
  {version,type,score,length,data}  — hints are the auto-bridge (vmnet0) selection
  language; per-vnet manual pin = the VMnet value above.
Ioctls on \\.\Global\VMnetUserif: 0x8102203c=query bridge state, 0x81022040=update,
0x81022088=push hints.
```

### GUI-equivalent recipe for "LAN bridged on Ethernet"
1. `VMnetBridge\Parameters\Adapters\{guid}\VMnet = 2`  (pin)
2. `VNL_SetVnetDisplayName("vmnet2", "LAN")`
3. `VNL_SetVnetUseDHCP/UseNAT("vmnet2", 0)`
4. `sc stop VMnetBridge && sc start VMnetBridge`
VMs select it via `ethernet0.networkName = "LAN"` (or connectionType custom).

### Full network removal (proven live 2026-10-14, tool `remove --vnet N`)
1. delete bridge pin: `VMnetBridge\Parameters\Adapters\{guid}` subkey where VMnet=N
2. `VNL_UninstallNetworkAdapter("vmnetN")` — removes the VMnetN host adapter PnP
   device (rc=0 = success; device gone within seconds)
3. delete `VMnetConfig\vmnetN` recursively (RegDeleteKey on a key with subkeys
   returns ACCESS_DENIED — recurse children first; embedded-python winreg may
   lack DeleteTree)
4. `VNL_UpdateDHCPFromConfig("vmnetN")` (+ `VNL_UpdateNATFromConfig` for NAT) —
   rewrites the conf WITHOUT the subnet stanza (must run after step 3)
5. restart VMnetDHCP (+ VMware NAT Service) and cycle VMnetBridge if it was pinned
Verify: features → 0x0, conf stanza gone, device gone.
NOTE: VNL_UpdateAdapterFromConfig dereferences arg1 — call with a vnet string or
explicit NULL; ctypes no-arg call crashes when a register holds a stale value.
Feature bits reflect live services; read DHCP/NAT/adapter config from the
registry (VMnetConfig\vmnetN\{DHCP,NAT,Adapter}\Use*), not features, before deleting.

### Host adapter PnP device — headless recipe (cracked 2026-10-14, corrected same day)
**Real signatures (disassembly-proven):**
`VNL_InstallNetworkAdapter(vnet, HWND hW, flags, p4, int* p5)` — 5 params, p5
dereferenced unless NULL; `VNL_UninstallNetworkAdapter(vnet, HWND hW, int* nR)` —
nR dereferenced unless NULL. ctypes calling them with only `vnet` leaves garbage in
r8/stack → intermittent `access violation reading 0x2` (crashed explorer once via
the PnP event storm it triggers mid-call). Always pass explicit 0s / byref(c_int()).
With correct args BOTH work headless (setupapi: install SUCCESS at ROOT\NET\xxxx,
uninstall = Delete Device SUCCESS) — the earlier "Invalid window handle 0x578"
failure was the garbage-hW bug, not a window-station limitation. Fallbacks that also
work (used before the fix): `"...\drvInst64.exe" installRootDriver 0 *VMnetAdapterN
"...\netadapter.inf" 1` and `pnputil.exe /remove-device ROOT\NET\xxxx`
(Remove-PnpDevice PS cmdlet may be absent). Install completes async — poll ~18 s.
Device gets generic connection name ("Ethernet N") — rename via Rename-NetAdapter
keyed on InterfaceDescription 'VMnetN$' (both VNL and drvInst64 paths need this
headless). Feature bit semantics (test-suite-proven 2026-10-14): 0x100/0x1000000
need the DEVICE present + service bounce; the dhcp bit reflects dhcpd's live BINDING
to the host adapter interface (stays set while the adapter holds an IP, even with
UseDHCP=0 — registry+conf are config truth, bit clears only when the device goes).
SetVnetUseNAT(vnet,1) does NOT create the NAT subkey on a fresh
vnet — write VMnetConfig\vmnetN\NAT\UseNAT=1 directly.
vmnetnat.conf has ONE [host] section (gateway/device of the last-regenerated NAT vnet);
after any NAT change run UpdateNATFromConfig for ALL UseNAT vnets ascending.
VNL_UpdateAdapterFromConfig dereferences arg1 — pass vnet string or NULL explicitly.
Applying an adapter IP change: VNL_SetVnetAdapterAddr only writes config; the LIVE
adapter IP updates only after VNL_UpdateAdapterFromConfig(vnet) (test-suite-proven).
Ghost config keys: VNL probes/getters (AssignSubnetAddressToVnet collision scan et
al.) lazily create VMnetConfig\vmnetN keys holding only DisplayName="VMnetN" on
untouched vnets — features stay 0 so `list` hides them, but any config-key existence
check sees them. No VNL_SetVnetUseAdapter export exists — cmd_add writes
Adapter\UseAdapter=1 itself after InstallNetworkAdapter.
VNL_Export/ImportDatabaseToFile = registry hive round-trip, works (rc=1).

### vmnet0 — NOT removable (proven live 2026-10-14)
Segment 0 is instantiated by the VMnetBridge DRIVER at load; VMnetConfig\vmnet0 only
holds the display name. Stripping everything (config key, adapter, conf, dhcp bounce)
leaves features(vmnet0)=0x1 — the bridged segment survives total config removal.
"Converting" it to host-only is cosmetic: add-on bits appear (UseAdapter registry)
but InstallNetworkAdapter never creates a VMnetAdapter0 device for segment 0, and the
bridge bit never leaves. The only real off-switch is the service:
`sc stop/config VMnetBridge start=disabled`. The tool now refuses `add --vnet 0`
and `add` onto any in-use segment; `remove --vnet 0` stays refused even with --force.

## 8. vmnetcfg.exe PARITY — GUI binary reverse engineered (2026-10-14)
vmnetcfg.exe imports exactly 38 VNL_* functions = the authoritative API surface.
Its call sites carry the literal constants; combined with live registry/conf diffs:

**DHCP dialog (dhcpDlg) → VNL_SetDHCPParam(vnet, paramId, char* value, int len)**:
paramIds are NOT 0..N — GUI constants: 0x3426=range begin (DHCPLeaseBeginIP),
0x3427=range end (DHCPLeaseEndIP), 0x342a=default lease (DHCPLeaseDuration),
0x342b=max lease (DHCPMaxLeaseDuration). Apply path clears params by calling with
value=NULL — pass None, NEVER integer 0 (garbage-pointer AV, cf. §7 crash story).

**Port forwarding (mapPortDlg) → VNL_SetNATPortForward(vnet, int proto, WORD hostPort,
char* vmIP, [stack] WORD vmPort, wchar_t* desc, int)** — proto: 1=TCP 0=UDP (arg2,
NOT the trailing int). Writes VMnetConfig\vmnetN\NAT\{TCP,UDP}Forward\<hostPort> =
"vmIP:vmPort" REG_SZ (+ <port>Description sibling). Delete = same call with
vmIP=NULL. UpdateNATFromConfig renders them into [incomingtcp]/[incomingudp].
EnumNATPortForward out-arg layout unresolved — read the registry instead.

**NAT advanced (natDlg/dnsDlg/netbiosDlg) → registry NAT subkey values rendered by
UpdateNATFromConfig into vmnetnat.conf**: ip→[host] ip (gateway, /mask auto),
hostIp, ConfigPort→configport, natIp6Enable, activeFTP, allowAnyOUI, udpTimeout→[udp],
DNSAutodetect/DNSNameServer1-3/DNSPolicy/DNSRetries/DNSTimeout→[dns],
NBNSTimeout→[netbios] nbnsTimeout. VNL_SetNATParam crashes all arg guesses —
not needed, registry+regen is the proven path.

**Conf regen semantics (critical!)**: UpdateNATFromConfig(vnet) rewrites the ENTIRE
vmnetnat.conf from that vnet's config (single [host]); UpdateDHCPFromConfig(vnet)
edits only that segment's block in vmnetdhcp.conf IN PLACE — stale blocks for
segments removed out-of-band are purged only by regenerating for that vnet.
restore-defaults therefore regens DHCP conf for ALL vnets.

**Restore Defaults** (GUI: UninstallNetworkComponents + Install{Bridge,UserIf,DHCP,NAT}
+ recreate vmnet1 host-only 192.168.14.0 + vmnet8 NAT 192.168.251.0, both adapter+dhcp).
Tool implements the config-level equivalent (no driver reinstall). Service bounce via
VNL_Stop/StartDHCP/NAT (GUI-proven, no sc.exe). **No IP Pools dialog exists in this
build** (zero 'Pool' strings) — do not invent one.

**autobridge (tool extension, not a GUI feature)**: one bridge segment per PHYSICAL
NIC — Ethernet→LAN<n>, Wi-Fi→WLAN<n> (per-class index in ifIndex order), convergent
and idempotent, vmnet0 (driver auto-bridge default) untouched. Physical-vs-VPN
classification on this box's OS: `Get-NetAdapter` exposes NO ifType/PnPId, but
`Get-CimInstance root/StandardCimv2 MSFT_NetAdapter` carries **PnPDeviceID** — the
reliable discriminator: real NICs sit on PCI\… (test box: VirtIO `PCI\VEN_1AF4`),
while TAP/Wintun/ZeroTier/VMware VMnet are `ROOT\…`/`SWD\…`-enumerated regardless
of what medium their driver claims (note `Get-NetAdapter -Physical` INCLUDES the
vmnet8 adapter on this OS — do not trust it alone). Wi-Fi = *IfType or
*PhysicalMediaType 71 in the adapter's registry Class\{4d36e972-…}\NNNN key
(matched by NetCfgInstanceId); ifType 24/131/… (ppp/tunnels) excluded.

### CLI built: `vmnet-cli.py` (repo root) + native port `vmnet-cli.c` → `vmnet-cli.exe`
Full vmnetcfg.exe Network Editor parity (this build has no IP Pools dialog — §8).
Validated by `test_vmnet_cli.py` — 89 remote end-to-end checks (registry, conf,
PnP device, feature bits, live adapter IP, guards, export/import round-trip,
port-forwarding, DHCP settings, type conversion, restore-defaults, autobridge,
clear/flush), self-restoring baseline. Run: `.venv/bin/python tests/test_vmnet_cli.py`
(exit = fail count); against the exe: `VMNET_TOOL=exe` (build via `build_exe.py`).
Commands: `adapters` / `list` / `add hostonly|nat --name X [--subnet A [--mask M]] [--vnet N] [--dhcp on|off]`
/ `bridged --name LAN --adapter Ethernet [--vnet N]` / `edit --vnet N [--name|--subnet|--mask|--dhcp|--nat]`
`[--type bridged|hostonly|nat] [--adapter on|off] [--dhcp-begin A --dhcp-end A --lease S --max-lease S]`
/ `set-ip --vnet N --addr A` / `natfw list|add|remove --vnet N [--proto tcp|udp --hport P [--vm-ip A --vm-port P --desc D]]`
/ `natcfg show|set --vnet N [--gateway-ip|--host-ip|--configport|--ipv6|--active-ftp|--allow-any-oui|--udp-timeout|--dns-auto|--dns1..3|--dns-policy|--dns-retries|--dns-timeout|--nbns-timeout]`
/ `remove --vnet N [--force]` / `unpin --vnet N` / `restore-defaults --force` / `clear|flush --force` (remove EVERY network incl. stock, vmnet0 stays) / `export|import --file F`
/ `autobridge [--dry-run]` (bridge every physical NIC: Ethernet→LAN<n>, Wi-Fi→WLAN<n>; §8 for the
physical-vs-VPN classification heuristic).
Full CRUD proven live: created DEVLAB (hostonly+dhcp, auto-subnet 192.168.192.0, device,
conf, features 0x01000100) and NETLAB (NAT+dhcp 192.168.38.0, features 0x01010100),
edited, set-ip, exported/imported hive, removed both — machine back at stock baseline.

## 6. Original unknowns list (kept for reference)
1. Exact argument grammar per vnetlib.exe subcommand (which verbs take vmnetN vs ip/mask).
2. Whether VNL_Set* writes the registry immediately and Update*FromConfig alone suffices,
   or a service restart is mandatory for each change class.
3. Full XML schema of ExportDatabaseToFile (file layout only, no need to invent it).
4. VMnetConfig registry value names for subnetAddr/subnetMask/useDhcp/useNat/displayName
   (value names likely constructed; verify with `reg query`).
5. Signatures/calling convention of the VNL_* exports (stdcall vs cdecl; params are ints + char*).

Capture recipe for a Windows box (Procmon + 20 min):
- `reg save "HKLM\SOFTWARE\VMware, Inc.\VMnetLib" vmnetlib.hiv` before/after one GUI change
- Procmon filter: process name vmnetcfg.exe OR vnetlib.exe, operation RegSetValueFile/WriteFile/DeviceIoControl
- Run `vnetlib.exe -- status all`, `-- help`, one `-- add dhcp vmnet1` and record output + exit codes
- VNL_Version() + one export via `dumpbin /exports` (already have names; need decorations → x64 = undecorated, good)

## 9. Native C port (`vmnet-cli.c`) — findings (2026-10-14)

Single-file Win32 C port of vmnet-cli.py; zero deps beyond advapi32/iphlpapi/setupapi.
Built on the VM with portable MinGW-w64 at `C:\Temp\mingw64` (winget source on the box
is broken: 0x8a15000f). `build_exe.py` uploads the source over SMB and compiles to
`C:\ludus\vmnet-cli.exe`. Test suite runs against it with `VMNET_TOOL=exe`.

### vnetlib treats string args as FIXED-WIDTH fields (CRITICAL)
VNL_* functions read and normalize (zero-pad) their string arguments ~260 bytes
in place — far past the terminating NUL. Passing a tight stack buffer or an
argv pointer corrupts the CALLER'S STACK: loop counters were zeroed
(`for (k=2;k<20;k++) features(v)` printed `vmnet0` forever), autobridge saw every
segment "in use", getters leaked previous values. A buffer padded with 0xAA past
the NUL even flips rc 1→0 on GetVNetFeatures (it scans past the NUL). Python
ctypes never showed this because str/bytes args are marshalled into fresh heap
temporaries. RULE: every string passed to VNL_* must go through a >= 512-byte
zero-initialized scratch buffer (`vlstr()` in vmnet-cli.c), and getter OUT
buffers must be zeroed before each call (vnetlib may not write at all).

### VNL_Export/ImportDatabaseToFile are no-ops from native processes
From a native x64 exe (LoadLibrary + direct call) `VNL_ExportDatabaseToFile`
returns rc=1 but never creates the file (stack/static/heap/exact-size args all
tested; rc even flips after unrelated VNL calls); from a ctypes-style caller in
the same OS/token it writes a proper hive. Not root-caused — irrelevant: the
export file is byte-comparable to `reg save HKLM\...\VMnetLib\VMnetConfig`
(plain regf hive), so vmnet-cli.c implements export/import NATIVELY:
RegSaveKeyExW(REG_LITE) with SE_BACKUP_NAME, and RegLoadKeyW → tree-replace →
RegUnLoadKeyW with SE_RESTORE_NAME. Same file format, no vnetlib quirk.

### vnetlib is not safe against concurrent hammering
Two stuck processes calling `VNL_GetVNetFeatures` in a tight loop starved/blocked a
user's `remove` mid-flight (config deleted, conf regen never ran) — vnetlib appears
to serialize on an internal lock. Never leave a looping vnetlib process running;
treat "tool hangs" as a symptom of another live instance first (`Get-Process`).

### This box has no `vmnet` service
`sc query vmnet` → 1060 is NORMAL here: the drivers are registered as services
`VMnetUserif` + `VMnetAdapter` (+ `VMnetBridge`); `vmnet.sys` has no service key on
this install. Don't "restore" one.

### Export hygiene
`VNL_Start/StopDHCP/NAT` DO exist (rc=1, §1). Still: never call a possibly-missing
export blind — `v0()` returns 2 when GetProcAddress yields NULL and callers fall
back to SCM stop/start. A `die()` on a missing export during cleanup paths is a
self-inflicted hang risk (partial operation left half-done).

### Batched multi-network operations (stage/apply split)
PnP adapter install/uninstall via vnetlib is ASYNC: the VNL call returns
immediately and the device appears/disappears seconds later. Multi-network
commands therefore run in two phases: STAGE (pins, VNL adapter kicks, registry
deletes, per-block conf edits — all cheap, all first) then APPLY (ONE settle
wait over all kicked PnP ops, ONE vmnetnat.conf regen, ONE service restart per
service, ONE bridge cycle). flush/clear/restore-defaults and multi-`--vnet`
remove all share this; single remove is just a one-element batch. Guards are
validated for every vnet BEFORE any staging so a refused batch leaves no
half-removed networks. Adapter presence for the batch wait uses ONE enumeration
per poll round (Get-NetAdapter / GetAdaptersAddresses scan of "VMnetN" desc
suffix) instead of one query per vnet per round.

### vmnetcfg.exe applies in PHASES, not per network (§8 confirmation)
vmnetcfg.exe's own progress strings show the Apply/Remove machinery runs one
scan + one adapter phase + one bridge phase + one service start each, for ALL
networks at once: "Pre-scan for disabling existing NAT network." →
"Installing network adapters." / "Updating host virtual adapters." →
"Checking bridge configuration." → "Start DHCP service." / "Start NAT
service.". The tool's batch stage/apply split mirrors this. Also confirmed:
vmnetcfg.exe never opens VMnetConfig paths itself (only registry string is
Software\VMware, Inc.\Running VM List) — its list is purely VNL features, so
the tool's registry-truth fallback in `list`/`vnet_in_use` can only be MORE
correct than the GUI, never divergent in steady state.

### Out-of-range segment names: vnetlib CLAMPS reads, VALIDATES writes (live-proven 2026-10-14)
`VNL_GetVNetFeatures("vmnet99")` returns rc=1 with ANOTHER segment's features
(the index is clamped/wrapped into range) — so a guard that only checks
"features != 0" silently sees vmnet0's bit for vmnet99. Setters
(`VNL_SetVnetSubnetAddr` etc.) DO validate: `edit --vnet 99 --subnet ...`
left every real segment untouched. Consequences baked into both tools:
`require_vnet()` range-checks every user-supplied --vnet before any use, and
every auto-pick scan iterates `2..vnet_count()`, never the literal 2..19.

### The fixed-width in-place padding hazard applies to WCHAR* args too (§9 extension)
`VNL_SetNATPortForward`'s `desc` parameter is a `WCHAR*` — same treatment
required as the char* args: a >=512-byte zeroed scratch, not a tight
`u82w()`/`create_unicode_buffer(len+1)` heap string (vnetlib may normalize
~260 bytes past the terminator). C uses `vlwide()` (vnl.c); Python `_c`
already pads str args to >=512 bytes.

### VNL_Stop/Start* rc: fallback on rc != 1, not rc > 1
1 = success, 0 = failure ("could not stop"), 2 (native v0 sentinel) = export
absent. An earlier version treated 0 as success, so the documented SCM
fallback never fired for genuine failures — dhcpd kept serving stale config
after edit/remove while the tool printed success. Both tools now fall
through to the SCM whenever the VNL call returns anything but 1.
