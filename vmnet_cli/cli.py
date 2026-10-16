# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.cli - see vmnet_cli.cli for the tool overview."""

import argparse
import sys

if sys.platform != "win32":
    sys.exit(
        "vmnet-cli must run on a Windows host with VMware Workstation "
        "installed (it drives vnetlib.dll)."
    )

from .commands import (
    cmd_adapters,
    cmd_add,
    cmd_autobridge,
    cmd_bridged,
    cmd_clear,
    cmd_edit,
    cmd_list,
    cmd_remove,
    cmd_restore,
    cmd_unpin,
)
from .commands_nat import cmd_export, cmd_import, cmd_natcfg, cmd_natfw, cmd_setip
from .vnl import VNetLib

"""
vmnet-cli — unofficial command-line interface to the VMware Workstation
Virtual Network Editor, built on the reverse-engineered vnetlib.dll VNL_* API
(Workstation 26H1,
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


def parse_vnet(s):
    """Accept only '2' or 'vmnet2' (letters then digits, nothing else) —
    mirrors the C tool's strict strtol parse; vnetlib's index resolution
    clamps, so sloppy parses would silently target other segments."""
    t = str(s)
    i = 0
    while i < len(t) and t[i].isascii() and t[i].isalpha():
        i += 1
    rest = t[i:]
    if not rest.isascii() or not rest.isdigit() or int(rest) > 1000000:
        raise argparse.ArgumentTypeError(
            f"expected a segment number or name (e.g. 2 or vmnet2), got {s!r}"
        )
    return int(rest)


def require_elevated():
    """Same bar as vmnetcfg.exe: full elevated Administrator token.
    SYSTEM is not required; Network Configuration Operators is not enough."""
    import ctypes

    if not ctypes.windll.shell32.IsUserAnAdmin():
        sys.exit(
            "vmnet-cli must run elevated as an Administrator "
            "(elevated prompt or Run as administrator); SYSTEM not required"
        )


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("adapters")
    sub.add_parser("list")
    a = sub.add_parser("add")
    a.add_argument("kind", choices=["hostonly", "nat"])
    a.add_argument("--name", required=True)
    a.add_argument("--subnet")
    a.add_argument("--mask")
    a.add_argument("--vnet", type=parse_vnet)
    a.add_argument("--dhcp", choices=["on", "off"], default="on", help="hostonly only")
    b = sub.add_parser("bridged")
    b.add_argument("--name", required=True)
    b.add_argument("--adapter", required=True)
    b.add_argument("--vnet", type=parse_vnet)
    e = sub.add_parser("edit")
    e.add_argument("--vnet", type=parse_vnet, required=True)
    e.add_argument("--name")
    e.add_argument("--subnet")
    e.add_argument("--mask")
    e.add_argument("--dhcp", choices=["on", "off"])
    e.add_argument("--nat", choices=["on", "off"])
    e.add_argument("--type", choices=["bridged", "hostonly", "nat"])
    e.add_argument("--adapter", choices=["on", "off"], help="host adapter checkbox")
    e.add_argument("--dhcp-begin")
    e.add_argument("--dhcp-end")
    e.add_argument("--lease", type=int, help="default lease seconds")
    e.add_argument("--max-lease", type=int)
    fw = sub.add_parser("natfw", help="NAT port forwarding (mapPortDlg)")
    fw.add_argument("action", choices=["list", "add", "remove"])
    fw.add_argument("--vnet", type=parse_vnet, required=True)
    fw.add_argument("--proto", choices=["tcp", "udp"])
    fw.add_argument("--hport", type=int)
    fw.add_argument("--vm-ip")
    fw.add_argument("--vm-port", type=int)
    fw.add_argument("--desc")
    nc = sub.add_parser("natcfg", help="NAT/DNS/NetBIOS advanced settings (natDlg)")
    nc.add_argument("action", choices=["show", "set"])
    nc.add_argument("--vnet", type=parse_vnet, required=True)
    for flag, typ in (
        ("gateway-ip", str),
        ("host-ip", str),
        ("configport", int),
        ("udp-timeout", int),
        ("dns1", str),
        ("dns2", str),
        ("dns3", str),
        ("dns-policy", str),
        ("dns-retries", int),
        ("dns-timeout", int),
        ("nbns-timeout", int),
    ):
        nc.add_argument("--" + flag, type=typ)
    for flag in ("ipv6", "active-ftp", "allow-any-oui", "dns-auto"):
        nc.add_argument("--" + flag, choices=["on", "off"])
    rd = sub.add_parser("restore-defaults", help="wipe custom nets, recreate vmnet1+vmnet8")
    rd.add_argument("--force", action="store_true")
    cl = sub.add_parser(
        "clear", aliases=["flush"], help="remove ALL vmnet networks incl. stock (vmnet0 stays)"
    )
    cl.add_argument("--force", action="store_true")
    i = sub.add_parser("set-ip")
    i.add_argument("--vnet", type=parse_vnet, required=True)
    i.add_argument("--addr", required=True)
    r = sub.add_parser(
        "remove",
        help="delete vmnet networks (adapter, config, conf, services) — batched across all --vnet args",
    )
    r.add_argument("--vnet", type=parse_vnet, required=True, action="append")
    r.add_argument("--force", action="store_true", help="allow removing stock vmnet1/vmnet8")
    u = sub.add_parser("unpin", help="only remove bridge binding(s) of a vnet, keep the network")
    u.add_argument("--vnet", type=parse_vnet, required=True)
    ab = sub.add_parser(
        "autobridge", help="bridge every physical NIC: Ethernet->LAN<n>, Wi-Fi->WLAN<n>"
    )
    ab.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    x = sub.add_parser("export")
    x.add_argument("--file", required=True)
    m = sub.add_parser("import")
    m.add_argument("--file", required=True)
    args = ap.parse_args()
    require_elevated()
    vl = VNetLib()
    {
        "adapters": lambda: cmd_adapters(vl),
        "list": lambda: cmd_list(vl),
        "add": lambda: cmd_add(vl, args),
        "bridged": lambda: cmd_bridged(vl, args),
        "edit": lambda: cmd_edit(vl, args),
        "set-ip": lambda: cmd_setip(vl, args),
        "remove": lambda: cmd_remove(vl, args),
        "unpin": lambda: cmd_unpin(vl, args),
        "autobridge": lambda: cmd_autobridge(vl, args),
        "natfw": lambda: cmd_natfw(vl, args),
        "natcfg": lambda: cmd_natcfg(vl, args),
        "restore-defaults": lambda: cmd_restore(vl, args),
        "clear": lambda: cmd_clear(vl, args),
        "flush": lambda: cmd_clear(vl, args),
        "export": lambda: cmd_export(vl, args),
        "import": lambda: cmd_import(vl, args),
    }[args.cmd]()


if __name__ == "__main__":
    main()
