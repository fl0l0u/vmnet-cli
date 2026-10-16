#!/usr/bin/env python3
"""
vmnet-cli — command-line interface to the VMware Workstation Virtual Network
Editor, built on the reverse-engineered vnetlib.dll VNL_* API (Workstation 26H1,
build 25688693; API v1.0). Run elevated on the Windows host running Workstation.

Usage (full vmnetcfg.exe Network Editor parity):
  vmnet-cli.py adapters                          list physical interfaces
  vmnet-cli.py list                              list vmnet segments + features
  vmnet-cli.py add hostonly --name X [--subnet A [--mask M]] [--vnet N] [--dhcp on|off]
  vmnet-cli.py add nat     --name X [--subnet A [--mask M]] [--vnet N]
  vmnet-cli.py bridged --name LAN  --adapter Ethernet [--vnet N]
  vmnet-cli.py edit --vnet N [--name X] [--subnet A] [--mask M] [--dhcp on|off] [--nat on|off]
                   [--type bridged|hostonly|nat] [--adapter on|off]
                   [--dhcp-begin A --dhcp-end A] [--lease S --max-lease S]
  vmnet-cli.py set-ip --vnet N --addr A          host adapter IP
  vmnet-cli.py natfw list  --vnet N --proto tcp|udp --hport P
  vmnet-cli.py natfw add   --vnet N --proto tcp|udp --hport P --vm-ip A --vm-port P [--desc D]
  vmnet-cli.py natfw remove --vnet N --proto tcp|udp --hport P
  vmnet-cli.py natcfg show|set --vnet N [--gateway-ip A] [--host-ip A] [--configport P]
                   [--ipv6 on|off] [--active-ftp on|off] [--allow-any-oui on|off]
                   [--udp-timeout S] [--dns-auto on|off] [--dns1 A --dns2 A --dns3 A]
                   [--dns-policy order|rotate|burst] [--dns-retries N] [--dns-timeout S]
                   [--nbns-timeout S]
  vmnet-cli.py remove --vnet N [--force]         delete a vmnet network entirely
  vmnet-cli.py unpin --vnet N                    drop bridge binding(s), keep network
  vmnet-cli.py autobridge [--dry-run]            bridge each physical NIC:
                                                 Ethernet->LAN<n>, Wi-Fi->WLAN<n>
  vmnet-cli.py restore-defaults --force          wipe custom nets, recreate vmnet1+vmnet8
  vmnet-cli.py clear|flush --force               remove EVERY network (vmnet0 stays)
  vmnet-cli.py export --file F                   save config (registry hive)
  vmnet-cli.py import --file F                   restore config
"""
import argparse, ctypes, sys, time, winreg
from ctypes import wintypes, byref, create_string_buffer, create_unicode_buffer, c_int

VL = r"C:\Program Files\VMware\VMware Workstation\vnetlib.dll"
BRIDGE_TABLE = r"SYSTEM\CurrentControlSet\Services\VMnetBridge\Parameters\Adapters"
CFG = r"SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig"

FEATURE_BITS = {0x1: "bridged", 0x100: "hostonly-adapter", 0x10000: "nat", 0x1000000: "dhcp"}
# Binding model (reverse engineered, verified live):
#   HKLM\SYSTEM\CurrentControlSet\Services\VMnetBridge\Parameters\Adapters\{adapter-guid}\VMnet = N
#   pins that physical adapter to vmnet segment N; reload with a VMnetBridge driver cycle.
#   VNL_GetVNetFeatures then reports bit 0x1 (bridged) on vmnetN.

# ---- physical interface enumeration (PowerShell Get-NetAdapter) --------------
def physical_interfaces():
    """Return {friendly name: adapter GUID} for physical (non-VMware) interfaces."""
    import subprocess
    ps = ("Get-NetAdapter | Where-Object { $_.InterfaceDescription -notlike 'VMware*' }"
          " | Sort-Object ifIndex | ConvertTo-Csv -NoTypeInformation")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True, check=True, timeout=60).stdout
    import csv, io
    result = {}
    for row in csv.DictReader(io.StringIO(out)):
        guid = (row.get("InterfaceGuid") or "").strip().upper()
        name = (row.get("Name") or "").strip('"')
        if guid and name:
            result[name] = guid
    return result

# Real-hardware PnP bus prefixes. Software adapters (TAP, Wintun/WireGuard,
# ZeroTier, VMware VMnet…) are ROOT\- or SWD\-enumerated and never appear here,
# even when their driver masquerades as an 802.3 medium.
PHYSICAL_BUSES = ("PCI", "VPCI", "USB", "PCMCIA", "SDIO", "SDCC", "SD", "IEEE1394",
                  "MDIO", "ACPI")
NET_CLASS = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

def _adapter_medium(guid):
    """(*IfType, *PhysicalMediaType) from the adapter's registry class key.
    71 = IEEE 802.11 in both fields; 6/14 = 802.3 Ethernet. (0, 0) = unknown
    (some drivers omit the REV values; the bus gate already proved physical)."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NET_CLASS) as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                try:
                    with winreg.OpenKey(k, winreg.EnumKey(k, i)) as sk:
                        if winreg.QueryValueEx(sk, "NetCfgInstanceId")[0].upper() != guid:
                            continue
                        out = []
                        for rev, plain in (("*IfType", "IfType"),
                                           ("*PhysicalMediaType", "PhysicalMediaType")):
                            for name in (rev, plain):
                                try:
                                    out.append(winreg.QueryValueEx(sk, name)[0])
                                    break
                                except OSError:
                                    continue
                            else:
                                out.append(0)
                        return tuple(out)
                except OSError:
                    continue
    except OSError:
        pass
    return (0, 0)

def classify_interfaces():
    """Physical NICs only, in ifIndex order: [(guid, name, kind, desc)].
    kind is 'wifi' for IEEE 802.11 (ifType/PhysicalMediaType 71) else 'ethernet'.
    VPN/virtual adapters are filtered by requiring the adapter's PnP device to
    sit on a real hardware bus: ROOT\\-enumerated drivers (TAP, WireGuard,
    ZeroTier, VMware VMnet) and SWD\\ devices never qualify, whatever medium
    their driver claims."""
    import subprocess, csv, io
    ps = ("Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter"
          " | Sort-Object ifIndex | Select-Object Name,InterfaceGuid,PnPDeviceID,"
          "InterfaceDescription | ConvertTo-Csv -NoTypeInformation")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True, check=True, timeout=60).stdout
    result = []
    for row in csv.DictReader(io.StringIO(out)):
        guid = (row.get("InterfaceGuid") or "").strip().upper()
        name = (row.get("Name") or "").strip('"')
        desc = (row.get("InterfaceDescription") or "").strip('"')
        pnp = (row.get("PnPDeviceID") or "").strip('"').upper()
        if not guid or "VMware" in desc or not pnp:
            continue
        if not pnp.split("\\")[0].startswith(PHYSICAL_BUSES):
            continue                       # ROOT\/SWD\… = software driver
        iftype, pmt = _adapter_medium(guid)
        if iftype in (24, 131, 135, 136, 148, 154, 166, 181, 209):
            continue                       # ppp / tunnel / virtual ifTypes
        kind = "wifi" if 71 in (iftype, pmt) else "ethernet"
        result.append((guid, name, kind, desc))
    return result

# ---- vnetlib wrapper ---------------------------------------------------------
def _vlbuf(a):
    """vnetlib treats string args as fixed-width fields and zero-pads them IN
    PLACE (~260 bytes; RECON §9). ctypes hands bytes/str as pointers into
    exact-size temporaries, so give every string arg a roomy buffer instead."""
    if isinstance(a, bytes):
        b = create_string_buffer(max(len(a) + 448, 512))
        b.value = a
        return b
    if isinstance(a, str):
        b = create_unicode_buffer(max(len(a) + 224, 256))
        b.value = a
        return b
    return a

class VNetLib:
    def __init__(self):
        self.d = ctypes.WinDLL(VL)
    def _c(self, name, *args):
        try:
            f = getattr(self.d, name)
        except AttributeError:
            return 2        # missing export: let callers fall back (RECON §9 hygiene)
        f.restype = c_int
        return f(*[_vlbuf(a) for a in args])
    def count(self): return self._c("VNL_GetNumberOfVnets")
    def features(self, vnet):
        feat = c_int(0)
        rc = self._c("VNL_GetVNetFeatures", vnet.encode(), byref(feat))
        return feat.value if rc == 1 else None
    def get_str(self, fn, vnet):
        buf = create_string_buffer(512); ln = c_int(512)
        rc = self._c(fn, vnet.encode(), buf, byref(ln))
        return buf.value.decode(errors="replace") if rc in (0, 1) and buf.value else ""
    def set_str(self, fn, vnet, val):
        return self._c(fn, vnet.encode(), val.encode() if isinstance(val, str) else val)
    def set_use_dhcp(self, vnet, on): return self._c("VNL_SetVnetUseDHCP", vnet.encode(), on)
    def set_use_nat(self, vnet, on): return self._c("VNL_SetVnetUseNAT", vnet.encode(), on)
    def update_adapter(self, vnet=None):
        # dereferences arg1; pass NULL (rebuild all) or the vnet string explicitly
        return self._c("VNL_UpdateAdapterFromConfig", vnet.encode() if vnet else None)
    def update_dhcp(self, vnet): return self._c("VNL_UpdateDHCPFromConfig", vnet.encode())
    def stop_bridge(self): return self._c("VNL_StopBridge")
    def start_bridge(self): return self._c("VNL_StartBridge")

def reg_bridge_bindings():
    """{adapter-guid: vnet-number} from the driver's Adapters subkeys (VMnet value)."""
    out = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, BRIDGE_TABLE) as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                sub = winreg.EnumKey(k, i)
                try:
                    with winreg.OpenKey(k, sub) as sk:
                        v, _ = winreg.QueryValueEx(sk, "VMnet")
                        out[sub.upper()] = v
                except OSError:
                    pass
    except FileNotFoundError:
        pass
    return out

def reg_bridge_set(guid, vnet):
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, BRIDGE_TABLE + "\\" + guid) as sk:
        winreg.SetValueEx(sk, "VMnet", 0, winreg.REG_DWORD, vnet)

def reg_bridge_del(guid):
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, BRIDGE_TABLE + "\\" + guid)
    except FileNotFoundError:
        pass

def cycle_bridge():
    """Reload the bridge driver so it re-reads Parameters\\Adapters bindings."""
    import subprocess, time
    for exe in ("sc.exe", "sc"):
        try:
            subprocess.run([exe, "stop", "VMnetBridge"], capture_output=True, timeout=30)
            time.sleep(2)
            subprocess.run([exe, "start", "VMnetBridge"], capture_output=True, timeout=30)
            time.sleep(3)
            return
        except FileNotFoundError:
            continue
    raise SystemExit("could not reload VMnetBridge driver (sc.exe not found)")

def vnet_in_use(vl, n):
    f = vl.features(f"vmnet{n}")
    # config key is ground truth too: features can transiently read 0
    return ((f or 0) != 0 or reg_exists(CFG + f"\\vmnet{n}")
            or n in (0, 1, 8))

def cmd_adapters(vl):
    iface = physical_interfaces()
    bound = reg_bridge_bindings()
    for name, guid in sorted(iface.items(), key=lambda kv: kv[1]):
        v = bound.get(guid)
        print(f"{name:30} {guid}  -> {'vmnet'+str(v) if v is not None else 'vmnet0 (auto)'}")

def reg_exists(path):
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path).Close()
        return True
    except OSError:
        return False

def cmd_list(vl):
    bindings = reg_bridge_bindings()
    for n in range(0, vl.count()):
        f = vl.features(f"vmnet{n}") or 0
        if not f:
            # VNL_GetVNetFeatures can transiently return 0 while PnP or the
            # services settle; fall back to registry truth so a configured
            # network never vanishes from the list mid-flight.
            vnet = f"vmnet{n}"
            if reg_exists(CFG + "\\" + vnet):
                if reg_flag(vnet, "DHCP"): f |= 0x1000000
                if reg_flag(vnet, "NAT"):  f |= 0x10000
                if reg_flag(vnet, "Adapter"): f |= 0x100
                if not f: f = 1
            if any(v == n for v in bindings.values()): f |= 1
            if not f: continue
        bits = ", ".join(v for b, v in FEATURE_BITS.items() if f & b)
        name = vl.get_str("VNL_GetVnetDisplayName", f"vmnet{n}")
        addr = vl.get_str("VNL_GetVnetSubnetAddr", f"vmnet{n}")
        pins = [g for g, v in bindings.items() if v == n]
        extra = f" pinned={','.join(pins)}" if pins else ""
        print(f"vmnet{n:<2} {bits:40} name={name!r} subnet={addr}{extra}")

def install_adapter_start(vnet):
    """Kick the VNL adapter install; wait via install_adapter_finish."""
    vl = VNetLib()
    # 5-arg signature: (vnet, hwnd, flags, p4, p5*) — p5 is dereferenced if not NULL,
    # so every trailing arg MUST be passed explicitly (stale-register AV otherwise).
    vl._c("VNL_InstallNetworkAdapter", vnet.encode(), 0, 0, 0, 0)

def install_adapter_finish(vnet, rounds=10):
    """Wait for the PnP install; fall back to drvInst64 installRootDriver
    (works headless, verified)."""
    import subprocess, time
    for _ in range(rounds):      # PnP completes asynchronously; give it room
        time.sleep(3)
        if _adapter_present(vnet):
            _name_adapter(vnet)  # headless VNL path also leaves generic names
            return True
    exe = VL.rsplit("\\", 1)[0] + "\\drvInst64.exe"
    inf = VL.rsplit("\\", 1)[0] + "\\netadapter.inf"
    subprocess.run([exe, "installRootDriver", "0", f"*{vnet.replace('vmnet', 'VMnetAdapter')}", inf, "1"],
                   capture_output=True, timeout=120)
    for _ in range(4):
        time.sleep(3)
        if _adapter_present(vnet):
            _name_adapter(vnet)
            return True
    return False

def install_adapter(vnet, verbose=True):
    install_adapter_start(vnet)
    return install_adapter_finish(vnet)

def _adapter_present(vnet):
    return int(vnet[5:]) in _adapters_present_set()

def _name_adapter(vnet):
    """drvInst installs with generic connection names; give it the VMnetN name."""
    import subprocess
    want = f"VMware Network Adapter {vnet.replace('vmnet', 'VMnet')}"
    subprocess.run(["powershell", "-NoProfile", "-Command",
        f"$a = Get-NetAdapter | Where-Object {{ $_.InterfaceDescription -match 'VMnet{vnet[5:]}$' -and $_.Name -ne '{want}' }};"
        f" if ($a) {{ Rename-NetAdapter -InputObject $a -NewName '{want}' -Confirm:$false }}"],
        capture_output=True, text=True, timeout=60)

def _adapters_present_set():
    """VMnet segments that currently have an adapter device (one PS call)."""
    import subprocess
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
        "(Get-NetAdapter | ForEach-Object { if ($_.InterfaceDescription -match 'VMnet(\\d+)$') { $Matches[1] } }) -join ' '"],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("Get-NetAdapter failed: " + (r.stderr or "").strip()[:200])
    return {int(x) for x in r.stdout.split()}

def uninstall_adapter_start(vnet, n):
    """Kick the VNL adapter removal; clear the config flag. Wait via finish."""
    vl = VNetLib()
    try:
        vl._c("VNL_UninstallNetworkAdapter", vnet.encode(), 0, ctypes.byref(ctypes.c_int(0)))
    except OSError:
        pass
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\Adapter") as k:
        winreg.SetValueEx(k, "UseAdapter", 0, winreg.REG_DWORD, 0)

def uninstall_adapter_finish(n, present=None):
    """Wait for device removal; pnputil fallback. present = live segment set."""
    import subprocess
    if present is None:
        time.sleep(3)
        present = _adapters_present_set()
    if n in present:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
            "Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |"
            f" Where-Object {{ $_.FriendlyName -match 'VMnet{n}$' }} | Select-Object -Expand InstanceId"],
            capture_output=True, text=True, timeout=60)
        for iid in r.stdout.split():
            subprocess.run(["pnputil.exe", "/remove-device", iid], capture_output=True, timeout=120)
        time.sleep(3)
        present = _adapters_present_set()
    return n not in present

def uninstall_adapter(vnet, n):
    uninstall_adapter_start(vnet, n)
    return uninstall_adapter_finish(n)

def regen_nat_conf(vl):
    """vmnetnat.conf has ONE [host] section; regenerate for every NAT vnet,
    ascending, so the file stays consistent with config."""
    for n in range(2, vl.count()):
        v = f"vmnet{n}"
        if reg_flag(v, "NAT") or (vl.features(v) or 0) & 0x10000:
            vl._c("VNL_UpdateNATFromConfig", v.encode())

def ensure_nat(vnet, on):
    vl = VNetLib()
    vl._c("VNL_SetVnetUseNAT", vnet.encode(), 1 if on else 0)
    if on and not reg_flag(vnet, "NAT"):
        # VNL_SetVnetUseNAT does not create the NAT subkey for a fresh vnet
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\NAT") as k:
            winreg.SetValueEx(k, "UseNAT", 0, winreg.REG_DWORD, 1)

DHCP_PARAM = {"begin": 0x3426, "end": 0x3427, "default_lease": 0x342a, "max_lease": 0x342b}
# vmnetcfg.exe call sites proved these paramIds (0x342a/0x342b in its dhcpDlg) +
# live registry sweep mapped each to its DHCP subkey value name.

def set_dhcp_param(vl, vnet, key, value):
    v = str(value).encode()
    return vl._c("VNL_SetDHCPParam", vnet.encode(), DHCP_PARAM[key], v, len(v))

def restart_services(dhcp=True, nat=False):
    """VNL_Stop/Start* like vmnetcfg.exe does; sc.exe fallback."""
    import subprocess, time
    for key, svc in (("dhcp", "VMnetDHCP"), ("nat", "VMware NAT Service")):
        if not (dhcp if key == "dhcp" else nat):
            continue
        vl = VNetLib()
        stop, start = "VNL_Stop" + key.upper(), "VNL_Start" + key.upper()
        if vl._c(stop) not in (0, 1):
            subprocess.run(["sc.exe", "stop", svc], capture_output=True, timeout=30)
        time.sleep(2)
        if vl._c(start) not in (0, 1):
            subprocess.run(["sc.exe", "start", svc], capture_output=True, timeout=30)
        time.sleep(3)

def pick_vnet(vl, n=None):
    if n is not None:
        return n
    taken = set(reg_bridge_bindings().values())
    for k in range(2, 20):
        if k not in taken and not vnet_in_use(vl, k):
            return k
    raise SystemExit("no free vmnet segment (2..19)")

def cmd_add(vl, args):
    if args.vnet == 0:
        sys.exit("vmnet0 is the built-in bridge segment; it cannot be re-typed "
                 "(segment 0 lives in the VMnetBridge driver, not in config)")
    if args.vnet is not None and vnet_in_use(vl, args.vnet):
        sys.exit(f"vmnet{args.vnet} is already in use; pick another --vnet or remove it first")
    n = pick_vnet(vl, args.vnet)
    vnet = f"vmnet{n}"
    is_nat = args.kind == "nat"
    if args.subnet:
        vl.set_str("VNL_SetVnetSubnetAddr", vnet, args.subnet)
        vl.set_str("VNL_SetVnetSubnetMask", vnet, args.mask or "255.255.255.0")
    else:
        if vl._c("VNL_AssignSubnetAddressToVnet", vnet.encode(), 0) != 1:
            sys.exit("could not auto-assign a free subnet; pass --subnet")
    subnet = vl.get_str("VNL_GetVnetSubnetAddr", vnet)
    dhcp = True if is_nat else args.dhcp != "off"
    print(f"* add {args.kind}: {vnet} name={args.name!r} subnet={subnet}"
          f" dhcp={'on' if dhcp else 'off'} nat={'on' if is_nat else 'off'}")
    vl.set_str("VNL_SetVnetDisplayName", vnet, args.name)
    ensure_nat(vnet, is_nat)
    vl.set_use_dhcp(vnet, 1 if dhcp else 0)
    ok = install_adapter(vnet)
    print(f"  - host adapter device: {'ok' if ok else 'pending/failed (PnP is async)'}")
    # write adapter config regardless: the device may still arrive after this call
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\Adapter") as k:
        winreg.SetValueEx(k, "UseAdapter", 0, winreg.REG_DWORD, 1)  # no VNL setter exists
    hostip = subnet.rsplit(".", 1)[0] + ".1" if subnet else "0.0.0.1"
    vl._c("VNL_SetVnetAdapterAddr", vnet.encode(), hostip.encode())
    if is_nat:
        regen_nat_conf(vl)
    vl.update_dhcp(vnet)
    vl.update_adapter()
    restart_services(dhcp=dhcp, nat=is_nat)
    want = 0x100 | (0x10000 if is_nat else 0) | (0x1000000 if dhcp else 0)
    f = 0
    for _ in range(10):        # adapter/NAT bits settle asynchronously (RECON §7)
        f = vl.features(vnet) or 0
        if f & want == want:
            break
        time.sleep(2)
    print(f"  {'OK' if f & want == want else 'WARNING'}: features=0x{f:08x}")

def cmd_edit(vl, args):
    vnet = f"vmnet{args.vnet}"
    n = args.vnet
    if n == 0 and args.type:
        sys.exit("vmnet0 is the built-in bridge segment; it cannot be re-typed")
    if vl.features(vnet) is None:
        sys.exit(f"{vnet} not readable")
    dhcp_changed = nat_changed = subnet_changed = False
    if args.type:
        if args.type == "nat":
            ensure_nat(vnet, True); vl.set_use_dhcp(vnet, 1); dhcp_changed = nat_changed = True
            if not _adapter_present(vnet):
                install_adapter(vnet)
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\Adapter") as k:
                    winreg.SetValueEx(k, "UseAdapter", 0, winreg.REG_DWORD, 1)
        elif args.type == "hostonly":
            ensure_nat(vnet, False); nat_changed = True
            if not _adapter_present(vnet):
                install_adapter(vnet)
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\Adapter") as k:
                    winreg.SetValueEx(k, "UseAdapter", 0, winreg.REG_DWORD, 1)
        else:  # bridged: strip NAT/DHCP/adapter; bind a NIC with the `bridged` command
            ensure_nat(vnet, False); vl.set_use_dhcp(vnet, 0)
            nat_changed = dhcp_changed = True
            if _adapter_present(vnet) or reg_flag(vnet, "Adapter"):
                uninstall_adapter(vnet, n)
        print(f"* {vnet} connection type -> {args.type}")
    if args.adapter:
        if args.adapter == "on":
            install_adapter(vnet)
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\Adapter") as k:
                winreg.SetValueEx(k, "UseAdapter", 0, winreg.REG_DWORD, 1)
            subnet = vl.get_str("VNL_GetVnetSubnetAddr", vnet)
            if subnet:
                vl._c("VNL_SetVnetAdapterAddr", vnet.encode(),
                      (subnet.rsplit(".", 1)[0] + ".1").encode())
        else:
            uninstall_adapter(vnet, n)
        print(f"* {vnet} host adapter {args.adapter}")
    if args.name is not None:
        vl.set_str("VNL_SetVnetDisplayName", vnet, args.name); print(f"* {vnet} DisplayName={args.name!r}")
    if args.subnet or args.mask:
        if args.subnet:
            vl.set_str("VNL_SetVnetSubnetAddr", vnet, args.subnet)
        vl.set_str("VNL_SetVnetSubnetMask", vnet, args.mask or vl.get_str("VNL_GetVnetSubnetMask", vnet))
        subnet_changed = True
        print(f"* {vnet} subnet={vl.get_str('VNL_GetVnetSubnetAddr', vnet)}/{vl.get_str('VNL_GetVnetSubnetMask', vnet)}")
    for key, val in (("begin", args.dhcp_begin), ("end", args.dhcp_end),
                     ("default_lease", args.lease), ("max_lease", args.max_lease)):
        if val is not None:
            rc = set_dhcp_param(vl, vnet, key, val)
            print(f"* {vnet} DHCP {key}={val}: {'ok' if rc == 1 else 'rc=' + str(rc)}")
            dhcp_changed = True
    if args.dhcp:
        vl.set_use_dhcp(vnet, 1 if args.dhcp == "on" else 0)
        dhcp_changed = True; print(f"* {vnet} UseDHCP={args.dhcp}")
    if args.nat:
        ensure_nat(vnet, args.nat == "on")
        nat_changed = True; print(f"* {vnet} UseNAT={args.nat}")
    if subnet_changed or dhcp_changed:
        vl.update_dhcp(vnet)
    if subnet_changed or nat_changed:
        regen_nat_conf(vl)
    if subnet_changed or dhcp_changed or nat_changed:
        restart_services(dhcp=subnet_changed or dhcp_changed, nat=subnet_changed or nat_changed)
    print(f"  features=0x{(vl.features(vnet) or 0):08x}")

NATVAL = {  # cli flag -> (registry value name, type) — UpdateNATFromConfig reads these
    "gateway_ip":   ("ip", winreg.REG_SZ),
    "host_ip":      ("hostIp", winreg.REG_SZ),
    "configport":   ("ConfigPort", winreg.REG_DWORD),
    "ipv6":         ("natIp6Enable", "bool"),
    "active_ftp":   ("activeFTP", "bool"),
    "allow_any_oui": ("allowAnyOUI", "bool"),
    "udp_timeout":  ("udpTimeout", winreg.REG_DWORD),
    "dns_auto":     ("DNSAutodetect", "bool"),
    "dns1":         ("DNSNameServer1", winreg.REG_SZ),
    "dns2":         ("DNSNameServer2", winreg.REG_SZ),
    "dns3":         ("DNSNameServer3", winreg.REG_SZ),
    "dns_policy":   ("DNSPolicy", winreg.REG_SZ),
    "dns_retries":  ("DNSRetries", winreg.REG_DWORD),
    "dns_timeout":  ("DNSTimeout", winreg.REG_DWORD),
    "nbns_timeout": ("NBNSTimeout", winreg.REG_DWORD),
}

def cmd_natfw(vl, args):
    vnet = f"vmnet{args.vnet}"
    if args.action != "list" and not args.proto:
        sys.exit("natfw add/remove need --proto tcp|udp")
    if args.action != "list" and not args.hport:
        sys.exit("natfw add/remove need --hport")
    proto = 1 if args.proto == "tcp" else 0   # VNL_SetNATPortForward arg2: 1=TCP 0=UDP
    if args.action == "list":
        for sub, label in (("TCPForward", "tcp"), ("UDPForward", "udp")):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\NAT\\{sub}") as k:
                    vals = {winreg.EnumValue(k, i)[0]: winreg.EnumValue(k, i)[1]
                            for i in range(winreg.QueryInfoKey(k)[1])}
                for port, target in sorted(vals.items()):
                    if port.endswith("Description"): continue
                    desc = vals.get(port + "Description", "")
                    if isinstance(desc, bytes):
                        desc = desc.decode("utf-16-le", "replace").strip("\x00")
                    print(f"  {vnet} {label} host:{port} -> {target}" + (f"  ({desc})" if desc else ""))
            except OSError:
                pass
        return
    if args.action == "add":
        if not (args.vm_ip and args.vm_port):
            sys.exit("natfw add needs --vm-ip and --vm-port")
        rc = vl._c("VNL_SetNATPortForward", vnet.encode(), proto, args.hport,
                   args.vm_ip.encode(), args.vm_port, args.desc, 0)  # desc: str -> wchar_t*
        print(f"* {vnet} map {args.proto} host:{args.hport} -> {args.vm_ip}:{args.vm_port}: "
              f"{'ok' if rc == 1 else 'rc=' + str(rc)}")
    else:  # remove: same call with vmIP NULL (GUI-proven delete semantics)
        rc = vl._c("VNL_SetNATPortForward", vnet.encode(), proto, args.hport, None, 0, None, 0)
        print(f"* {vnet} unmap {args.proto} host:{args.hport}: {'ok' if rc == 1 else 'rc=' + str(rc)}")
    # UpdateNATFromConfig rewrites the WHOLE conf from the given vnet's config —
    # regen the target last so its forwards/sections are the ones in the file.
    vl._c("VNL_UpdateNATFromConfig", vnet.encode())
    restart_services(dhcp=False, nat=True)

def cmd_natcfg(vl, args):
    vnet = f"vmnet{args.vnet}"
    if not reg_flag(vnet, "NAT") and not (vl.features(vnet) or 0) & 0x10000:
        sys.exit(f"{vnet} is not a NAT network")
    key = f"{CFG}\\{vnet}\\NAT"
    if args.action == "show":
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            for i in range(winreg.QueryInfoKey(k)[1]):
                name, val, _ = winreg.EnumValue(k, i)
                print(f"  {name} = {val}")
        return
    changed = False
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
        for flag, (rname, rtype) in NATVAL.items():
            val = getattr(args, flag, None)
            if val is None: continue
            if rtype == "bool":
                val = 1 if val == "on" else 0
            winreg.SetValueEx(k, rname, 0, rtype if rtype != "bool" else winreg.REG_DWORD, val)
            print(f"  {vnet} NAT {rname} = {val}")
            changed = True
    if changed:
        vl._c("VNL_UpdateNATFromConfig", vnet.encode())
        restart_services(dhcp=False, nat=True)
    else:
        print("nothing to change")

def cmd_restore(vl, args):
    if not args.force:
        sys.exit("restore-defaults removes ALL custom networks; pass --force")
    print("* restoring default networks (vmnet0 auto-bridge, vmnet1 host-only, vmnet8 NAT)")
    ctx = batch_new()
    for n in range(2, vl.count()):
        if n in (1, 8): continue
        if reg_exists(f"{CFG}\\vmnet{n}"):
            remove_stage(vl, n, ctx)
    for n, is_nat, subnet in ((1, False, "192.168.14.0"), (8, True, "192.168.251.0")):
        vnet = f"vmnet{n}"
        if vl.features(vnet):
            continue
        vl.set_str("VNL_SetVnetSubnetAddr", vnet, subnet)
        vl.set_str("VNL_SetVnetSubnetMask", vnet, "255.255.255.0")
        vl.set_use_dhcp(vnet, 1)
        if is_nat:
            ensure_nat(vnet, True)
        install_adapter_start(vnet)       # kicked now, awaited together in apply
        ctx["added"].append(n)
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\Adapter") as k:
            winreg.SetValueEx(k, "UseAdapter", 0, winreg.REG_DWORD, 1)
        vl._c("VNL_SetVnetAdapterAddr", vnet.encode(), (subnet.rsplit(".", 1)[0] + ".1").encode())
        print(f"  - recreated {vnet} ({'nat' if is_nat else 'hostonly'}) {subnet}")
    vl.set_str("VNL_SetVnetDisplayName", "vmnet0", "VMnet0")
    # UpdateDHCPFromConfig edits each segment's block in place — regen EVERY vnet
    # (including 0) so conf blocks for removed/stale segments are purged too.
    for n in range(vl.count()):
        vl.update_dhcp(f"vmnet{n}")
    ctx["dhcp"] = ctx["nat"] = True       # one restart for the whole restore
    batch_apply(vl, ctx)

def cmd_setip(vl, args):
    vnet = f"vmnet{args.vnet}"
    rc = vl._c("VNL_SetVnetAdapterAddr", vnet.encode(), args.addr.encode())
    print(f"* {vnet} adapter IP {args.addr}: {'ok' if rc == 1 else 'rc=' + str(rc)}")
    vl.update_adapter(vnet)   # apply to the live device, not just the config
    cur = vl.get_str("VNL_GetVnetAdapterAddr", vnet)
    print(f"  configured adapter addr: {cur!r}")

def cmd_export(vl, args):
    rc = vl._c("VNL_ExportDatabaseToFile", args.file)
    print(f"export -> {args.file}: {'ok' if rc == 1 else 'rc=' + str(rc)}")

def cmd_import(vl, args):
    rc = vl._c("VNL_ImportDatabaseFromFile", args.file)
    print(f"import <- {args.file}: {'ok' if rc == 1 else 'rc=' + str(rc)}")
    if rc == 1:
        vl.update_dhcp("vmnet1"); regen_nat_conf(vl)
        restart_services(dhcp=True, nat=True)

def cmd_bridged(vl, args):
    iface = physical_interfaces()
    if args.adapter not in iface:
        sys.exit(f"ERROR: no network interface named {args.adapter!r} on this host. "
                 f"Available: {', '.join(sorted(iface))}")
    guid = iface[args.adapter]
    if args.vnet is not None:
        n = args.vnet
    else:
        taken = set(reg_bridge_bindings().values())
        n = next((k for k in range(2, 20) if k not in taken and not vnet_in_use(vl, k)), None)
        if n is None:
            raise SystemExit("no free vmnet segment (2..19)")
    vnet = f"vmnet{n}"
    print(f"* {args.name}: {vnet} bridged to interface {args.adapter!r} ({guid})")
    reg_bridge_set(guid, n)
    vl.set_str("VNL_SetVnetDisplayName", vnet, args.name)
    vl.set_use_dhcp(vnet, 0); vl.set_use_nat(vnet, 0)
    cycle_bridge()
    f = vl.features(vnet)
    ok = f is not None and f & 0x1
    print(f"  {'OK' if ok else 'WARNING: bridged bit not set'}: {vnet} features=0x{(f or 0):08x}")

def cmd_unpin(vl, args):
    removed = False
    for guid, v in reg_bridge_bindings().items():
        if v == args.vnet:
            reg_bridge_del(guid)
            print(f"* removed bridge binding {guid} -> vmnet{v}")
            removed = True
    if not removed:
        print(f"* no bridge binding on vmnet{args.vnet}")
    if removed:
        cycle_bridge()

def cmd_autobridge(vl, args):
    """Bridge every physical NIC to its own segment: Ethernet -> LAN<n>,
    Wi-Fi -> WLAN<n> (n = per-class index in ifIndex order). Convergent and
    idempotent: existing pins are kept and renamed, clean segments are reused.
    vmnet0 (the driver's auto-bridge default) is left untouched."""
    nics = classify_interfaces()
    if not nics:
        print("* no physical NICs found (every adapter looks virtual/VPN)")
        return
    pins = reg_bridge_bindings()
    named = {}    # display name -> vnet, so a segment from an earlier run is
    for k in range(1, vl.count()):   # adopted instead of duplicating the name
        dn = vl.get_str("VNL_GetVnetDisplayName", f"vmnet{k}")
        if dn:
            named.setdefault(dn, k)
    counts = {"ethernet": 0, "wifi": 0}
    planned = set()
    changed = False
    for guid, ifname, kind, desc in nics:
        counts[kind] += 1
        want = ("LAN" if kind == "ethernet" else "WLAN") + str(counts[kind])
        if guid in pins:
            n = pins[guid]
            vnet = f"vmnet{n}"
            if (vl.features(vnet) or 0) & ~0x1:
                print(f"* {ifname} already pinned to {vnet} with host network "
                      "config; left alone (use unpin/remove to reclaim it)")
                continue
            if vl.get_str("VNL_GetVnetDisplayName", vnet) != want:
                vl.set_str("VNL_SetVnetDisplayName", vnet, want)
                changed = True
                print(f"* {vnet} renamed to {want} ({ifname})")
            else:
                print(f"* {vnet} already bridges {ifname} as {want}")
            continue
        n = named.get(want)
        if n is not None and (n in pins.values() or n in planned
                              or (vl.features(f"vmnet{n}") or 0) & ~0x1):
            n = None                       # name taken by a real network elsewhere
        if n is None:
            taken = set(pins.values()) | planned
            n = next((k for k in range(2, 20) if k not in taken
                      and not vnet_in_use(vl, k)), None)
        if n is None:
            print(f"ERROR: no free vmnet segment (2..19) for {ifname}")
            continue
        vnet = f"vmnet{n}"
        print(f"* autobridge {ifname} ({desc}; {kind}) -> {vnet} as {want}"
              + (" [dry-run]" if args.dry_run else ""))
        planned.add(n)
        changed = True
        if not args.dry_run:
            reg_bridge_set(guid, n)
            pins[guid] = n
            vl.set_str("VNL_SetVnetDisplayName", vnet, want)
            vl.set_use_dhcp(vnet, 0)
            vl.set_use_nat(vnet, 0)
            named.setdefault(want, n)
    if args.dry_run:
        print("(dry run: nothing changed)")
        return
    if changed:
        cycle_bridge()
    for guid, n in sorted(pins.items(), key=lambda kv: kv[1]):
        f = vl.features(f"vmnet{n}")
        ok = f is not None and f & 0x1
        print(f"  {'OK' if ok else 'WARNING'}: vmnet{n} pinned to {guid} "
              f"features=0x{(f or 0):08x}")

def reg_flag(vnet, sub):
    """True if VMnetConfig\\vnet\\sub\\Use<sub> == 1 (registry is the config truth)."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\{sub}") as k:
            return winreg.QueryValueEx(k, "Use" + sub)[0] == 1
    except OSError:
        return False

def reg_delete_tree(key_path):
    """Recursively delete an HKLM key and all subkeys (winreg.DeleteTree fallback)."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            subs = [winreg.EnumKey(k, i) for i in range(winreg.QueryInfoKey(k)[0])]
    except FileNotFoundError:
        return
    for s in subs:
        reg_delete_tree(key_path + "\\" + s)
    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)

def cmd_clear(vl, args):
    """Remove EVERY vmnet network — custom AND stock vmnet1/vmnet8. vmnet0 (the
    VMnetBridge driver's auto-bridge segment) is not removable and always stays."""
    if not args.force:
        sys.exit("clear removes ALL networks including stock vmnet1/vmnet8; pass --force")
    print("* clearing all vmnet networks (vmnet0 remains)")
    bindings = reg_bridge_bindings()
    ctx = batch_new()
    for n in range(1, vl.count()):
        vnet = f"vmnet{n}"
        f = vl.features(vnet) or 0
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CFG + "\\" + vnet).Close()
            has = True
        except OSError:
            has = False
        if f == 0 and not has and not any(v == n for v in bindings.values()):
            continue                       # silent segment: nothing to do
        remove_stage(vl, n, ctx)
    batch_apply(vl, ctx)

def cmd_remove(vl, args):
    for n in args.vnet:                    # validate everything before touching anything
        if n == 0:
            sys.exit("vmnet0 is the built-in bridge segment and cannot be removed")
        if n in (1, 8) and not args.force:
            sys.exit(f"vmnet{n} is a stock Workstation network; pass --force to remove it anyway")
    ctx = batch_new()
    for n in args.vnet:
        remove_stage(vl, n, ctx)
    batch_apply(vl, ctx)

def batch_new():
    """Collects multi-network changes so every expensive wait/restart happens
    once for the whole batch instead of once per network."""
    return {"dhcp": False, "nat": False, "bridge": False,
            "gone": [], "added": [], "vnets": []}

def remove_stage(vl, n, ctx):
    """Cheap part of a removal: pins, adapter kick, config key, conf edits."""
    vnet = f"vmnet{n}"
    f = vl.features(vnet) or 0
    pinned = any(v == n for v in reg_bridge_bindings().values())
    had_dhcp = bool(f & 0x1000000) or reg_flag(vnet, "DHCP")
    had_nat = bool(f & 0x10000) or reg_flag(vnet, "NAT")
    had_adapter = bool(f & 0x100) or reg_flag(vnet, "Adapter")
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CFG + "\\" + vnet).Close()
        has_config = True
    except OSError:
        has_config = False
    if f == 0 and not (had_dhcp or had_nat or had_adapter or pinned) and not has_config:
        print(f"* {vnet} is not configured; nothing to remove")
        return False
    parts = [v for b, v in FEATURE_BITS.items() if f & b]
    print(f"* removing {vnet}" + (f" ({', '.join(parts)})" if parts else ""))
    ctx["vnets"].append(n)
    for guid, v in reg_bridge_bindings().items():
        if v == n:
            reg_bridge_del(guid)
            print(f"  - unbound {guid}")
            ctx["bridge"] = True
    if had_adapter:
        uninstall_adapter_start(vnet, n)
        ctx["gone"].append(n)
    reg_delete_tree(CFG + "\\" + vnet)
    print("  - deleted VMnetConfig\\" + vnet)
    if had_dhcp:
        rc = vl.update_dhcp(vnet)
        print(f"  - vmnetdhcp.conf regenerated: {'ok' if rc == 1 else 'rc=' + str(rc)}")
        ctx["dhcp"] = True
    if had_nat:
        ctx["nat"] = True          # conf regen once at apply (whole-file rewrite)
    return True

def remove_vnet(vl, n):
    ctx = batch_new()
    if remove_stage(vl, n, ctx):
        batch_apply(vl, ctx)

def batch_apply(vl, ctx):
    """One wait for all PnP operations, one conf regen, one service restart,
    one bridge cycle — regardless of batch size."""
    if ctx["nat"]:
        regen_nat_conf(vl)
        print("  - vmnetnat.conf regenerated")
    if ctx["gone"]:
        time.sleep(3)
        present = _adapters_present_set()
        for n in ctx["gone"]:
            if n in present:
                uninstall_adapter_finish(n, present=present)
                present = _adapters_present_set()
            print(f"  - host adapter device vmnet{n}: {'STILL PRESENT' if n in present else 'gone'}")
    if ctx["added"]:
        pending = list(ctx["added"])
        for _ in range(10):
            time.sleep(3)
            present = _adapters_present_set()
            pending = [n for n in pending if n not in present]
            if not pending:
                break
        import subprocess
        exe = VL.rsplit("\\", 1)[0] + "\\drvInst64.exe"
        inf = VL.rsplit("\\", 1)[0] + "\\netadapter.inf"
        for n in pending:
            try:
                subprocess.run([exe, "installRootDriver", "0", f"*VMnetAdapter{n}", inf, "1"],
                               capture_output=True, timeout=120)
            except subprocess.TimeoutExpired:
                pass                     # keep waiting; do not abort the batch
        time.sleep(3)
        for _ in range(4):
            if not pending:
                break
            time.sleep(3)
            present = _adapters_present_set()
            pending = [n for n in pending if n not in present]
        present = _adapters_present_set()
        for n in ctx["added"]:
            if n in present:
                _name_adapter(f"vmnet{n}")
            print(f"  - host adapter device vmnet{n}: {'ok' if n in present else 'pending/failed (PnP is async)'}")
    if ctx["dhcp"] or ctx["nat"]:
        restart_services(dhcp=ctx["dhcp"], nat=ctx["nat"])
    if ctx["bridge"]:
        cycle_bridge()
    for n in ctx["vnets"]:
        left = vl.features(f"vmnet{n}") or 0     # absent (None) counts as removed
        print(f"  {'OK' if left == 0 else 'WARNING'}: vmnet{n} features now 0x{left:08x}")

def parse_vnet(s):
    """Accept both '2' and 'vmnet2'."""
    t = str(s).strip().lower()
    if t.startswith("vmnet"):
        t = t[5:]
    try:
        return int(t)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a segment number or name (e.g. 2 or vmnet2), got {s!r}")

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("adapters"); sub.add_parser("list")
    a = sub.add_parser("add")
    a.add_argument("kind", choices=["hostonly", "nat"])
    a.add_argument("--name", required=True); a.add_argument("--subnet")
    a.add_argument("--mask"); a.add_argument("--vnet", type=parse_vnet)
    a.add_argument("--dhcp", choices=["on", "off"], default="on", help="hostonly only")
    b = sub.add_parser("bridged")
    b.add_argument("--name", required=True); b.add_argument("--adapter", required=True)
    b.add_argument("--vnet", type=parse_vnet)
    e = sub.add_parser("edit")
    e.add_argument("--vnet", type=parse_vnet, required=True)
    e.add_argument("--name"); e.add_argument("--subnet"); e.add_argument("--mask")
    e.add_argument("--dhcp", choices=["on", "off"]); e.add_argument("--nat", choices=["on", "off"])
    e.add_argument("--type", choices=["bridged", "hostonly", "nat"])
    e.add_argument("--adapter", choices=["on", "off"], help="host adapter checkbox")
    e.add_argument("--dhcp-begin"); e.add_argument("--dhcp-end")
    e.add_argument("--lease", type=int, help="default lease seconds")
    e.add_argument("--max-lease", type=int)
    fw = sub.add_parser("natfw", help="NAT port forwarding (mapPortDlg)")
    fw.add_argument("action", choices=["list", "add", "remove"])
    fw.add_argument("--vnet", type=parse_vnet, required=True)
    fw.add_argument("--proto", choices=["tcp", "udp"])
    fw.add_argument("--hport", type=int)
    fw.add_argument("--vm-ip"); fw.add_argument("--vm-port", type=int)
    fw.add_argument("--desc")
    nc = sub.add_parser("natcfg", help="NAT/DNS/NetBIOS advanced settings (natDlg)")
    nc.add_argument("action", choices=["show", "set"])
    nc.add_argument("--vnet", type=parse_vnet, required=True)
    for flag, typ in (("gateway-ip", str), ("host-ip", str), ("configport", int),
                      ("udp-timeout", int), ("dns1", str), ("dns2", str), ("dns3", str),
                      ("dns-policy", str), ("dns-retries", int), ("dns-timeout", int),
                      ("nbns-timeout", int)):
        nc.add_argument("--" + flag, type=typ)
    for flag in ("ipv6", "active-ftp", "allow-any-oui", "dns-auto"):
        nc.add_argument("--" + flag, choices=["on", "off"])
    rd = sub.add_parser("restore-defaults", help="wipe custom nets, recreate vmnet1+vmnet8")
    rd.add_argument("--force", action="store_true")
    cl = sub.add_parser("clear", aliases=["flush"],
                        help="remove ALL vmnet networks incl. stock (vmnet0 stays)")
    cl.add_argument("--force", action="store_true")
    i = sub.add_parser("set-ip")
    i.add_argument("--vnet", type=parse_vnet, required=True); i.add_argument("--addr", required=True)
    r = sub.add_parser("remove", help="delete vmnet networks (adapter, config, conf, services) — batched across all --vnet args")
    r.add_argument("--vnet", type=parse_vnet, required=True, action="append")
    r.add_argument("--force", action="store_true", help="allow removing stock vmnet1/vmnet8")
    u = sub.add_parser("unpin", help="only remove bridge binding(s) of a vnet, keep the network")
    u.add_argument("--vnet", type=parse_vnet, required=True)
    ab = sub.add_parser("autobridge",
                        help="bridge every physical NIC: Ethernet->LAN<n>, Wi-Fi->WLAN<n>")
    ab.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    x = sub.add_parser("export"); x.add_argument("--file", required=True)
    m = sub.add_parser("import"); m.add_argument("--file", required=True)
    args = ap.parse_args()
    vl = VNetLib()
    {"adapters": lambda: cmd_adapters(vl), "list": lambda: cmd_list(vl),
     "add": lambda: cmd_add(vl, args),
     "bridged": lambda: cmd_bridged(vl, args), "edit": lambda: cmd_edit(vl, args),
     "set-ip": lambda: cmd_setip(vl, args), "remove": lambda: cmd_remove(vl, args),
     "unpin": lambda: cmd_unpin(vl, args),
     "autobridge": lambda: cmd_autobridge(vl, args),
     "natfw": lambda: cmd_natfw(vl, args), "natcfg": lambda: cmd_natcfg(vl, args),
     "restore-defaults": lambda: cmd_restore(vl, args),
     "clear": lambda: cmd_clear(vl, args), "flush": lambda: cmd_clear(vl, args),
     "export": lambda: cmd_export(vl, args), "import": lambda: cmd_import(vl, args)}[args.cmd]()

if __name__ == "__main__":
    main()
