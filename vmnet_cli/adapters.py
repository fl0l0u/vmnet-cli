# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.adapters - see vmnet_cli.cli for the tool overview."""

import csv
import ctypes
import io
import subprocess
import sys
import time
import winreg

from .registry import CFG
from .vnl import VL, VNetLib


# ---- physical interface enumeration (PowerShell Get-NetAdapter) --------------
def physical_interfaces():
    """Return {friendly name: adapter GUID} for physical (non-VMware) interfaces."""
    ps = (
        "Get-NetAdapter | Where-Object { $_.InterfaceDescription -notlike 'VMware*' }"
        " | Sort-Object ifIndex | ConvertTo-Csv -NoTypeInformation"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        sys.exit(f"adapter enumeration failed: {e}")
    import csv
    import io

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
PHYSICAL_BUSES = ("PCI", "VPCI", "USB", "PCMCIA", "SDIO", "SDCC", "SD", "IEEE1394", "MDIO", "ACPI")
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
                        for rev, plain in (
                            ("*IfType", "IfType"),
                            ("*PhysicalMediaType", "PhysicalMediaType"),
                        ):
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
    ps = (
        "Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter"
        " | Sort-Object ifIndex | Select-Object Name,InterfaceGuid,PnPDeviceID,"
        "InterfaceDescription | ConvertTo-Csv -NoTypeInformation"
    )
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout
    result = []
    for row in csv.DictReader(io.StringIO(out)):
        guid = (row.get("InterfaceGuid") or "").strip().upper()
        name = (row.get("Name") or "").strip('"')
        desc = (row.get("InterfaceDescription") or "").strip('"')
        pnp = (row.get("PnPDeviceID") or "").strip('"').upper()
        if not guid or "VMware" in desc or not pnp:
            continue
        if not pnp.split("\\")[0].startswith(PHYSICAL_BUSES):
            continue  # ROOT\/SWD\… = software driver
        iftype, pmt = _adapter_medium(guid)
        if iftype in (24, 131, 135, 136, 148, 154, 166, 181, 209):
            continue  # ppp / tunnel / virtual ifTypes
        kind = "wifi" if 71 in (iftype, pmt) else "ethernet"
        result.append((guid, name, kind, desc))
    return result


def install_adapter_start(vnet):
    """Kick the VNL adapter install; wait via install_adapter_finish."""
    vl = VNetLib()
    # 5-arg signature: (vnet, hwnd, flags, p4, p5*) — p5 is dereferenced if not NULL,
    # so every trailing arg MUST be passed explicitly (stale-register AV otherwise).
    vl._c("VNL_InstallNetworkAdapter", vnet.encode(), 0, 0, 0, 0)


def install_adapter_finish(vnet, rounds=10):
    """Wait for the PnP install; fall back to drvInst64 installRootDriver
    (works headless, verified)."""
    import time

    for _ in range(rounds):  # PnP completes asynchronously; give it room
        time.sleep(3)
        if _adapter_present(vnet):
            _name_adapter(vnet)  # headless VNL path also leaves generic names
            return True
    exe = VL.rsplit("\\", 1)[0] + "\\drvInst64.exe"
    inf = VL.rsplit("\\", 1)[0] + "\\netadapter.inf"
    subprocess.run(
        [exe, "installRootDriver", "0", f"*{vnet.replace('vmnet', 'VMnetAdapter')}", inf, "1"],
        capture_output=True,
        timeout=120,
    )
    for _ in range(4):
        time.sleep(3)
        if _adapter_present(vnet):
            _name_adapter(vnet)
            return True
    return False


def install_adapter(vnet):
    install_adapter_start(vnet)
    return install_adapter_finish(vnet)


def _adapter_present(vnet):
    return int(vnet[5:]) in _adapters_present_set()


def _name_adapter(vnet):
    """drvInst installs with generic connection names; give it the VMnetN name."""
    want = f"VMware Network Adapter {vnet.replace('vmnet', 'VMnet')}"
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"$a = Get-NetAdapter | Where-Object {{ $_.InterfaceDescription -match 'VMnet{vnet[5:]}$' -and $_.Name -ne '{want}' }};"
            f" if ($a) {{ Rename-NetAdapter -InputObject $a -NewName '{want}' -Confirm:$false }}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _adapters_present_set():
    """VMnet segments that currently have an adapter device (one PS call)."""
    r = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-NetAdapter | ForEach-Object { if ($_.InterfaceDescription -match 'VMnet(\\d+)$') { $Matches[1] } }) -join ' '",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
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
    if present is None:
        time.sleep(3)
        present = _adapters_present_set()
    if n in present:
        r = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |"
                f" Where-Object {{ $_.FriendlyName -match 'VMnet{n}$' }} | Select-Object -Expand InstanceId",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        for iid in r.stdout.split():
            subprocess.run(["pnputil.exe", "/remove-device", iid], capture_output=True, timeout=120)
        time.sleep(3)
        present = _adapters_present_set()
    return n not in present


def uninstall_adapter(vnet, n):
    uninstall_adapter_start(vnet, n)
    return uninstall_adapter_finish(n)
