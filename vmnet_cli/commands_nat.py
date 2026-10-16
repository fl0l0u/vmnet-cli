# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.commands_nat - see vmnet_cli.cli for the tool overview."""

import sys
import winreg

from .conf import NATVAL, regen_nat_conf
from .registry import CFG, reg_flag
from .services import restart_services
from .vnl import require_vnet


def cmd_natfw(vl, args):
    require_vnet(vl, args.vnet)
    vnet = f"vmnet{args.vnet}"
    if args.action != "list" and not args.proto:
        sys.exit("natfw add/remove need --proto tcp|udp")
    if args.action != "list" and not args.hport:
        sys.exit("natfw add/remove need --hport")
    proto = 1 if args.proto == "tcp" else 0  # VNL_SetNATPortForward arg2: 1=TCP 0=UDP
    if args.action == "list":
        for sub, label in (("TCPForward", "tcp"), ("UDPForward", "udp")):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\NAT\\{sub}") as k:
                    vals = {
                        winreg.EnumValue(k, i)[0]: winreg.EnumValue(k, i)[1]
                        for i in range(winreg.QueryInfoKey(k)[1])
                    }
                for port, target in sorted(vals.items()):
                    if port.endswith("Description"):
                        continue
                    desc = vals.get(port + "Description", "")
                    if isinstance(desc, bytes):
                        desc = desc.decode("utf-16-le", "replace").strip("\x00")
                    print(
                        f"  {vnet} {label} host:{port} -> {target}"
                        + (f"  ({desc})" if desc else "")
                    )
            except OSError:
                pass
        return
    if args.action == "add":
        if not (args.vm_ip and args.vm_port):
            sys.exit("natfw add needs --vm-ip and --vm-port")
        rc = vl._c(
            "VNL_SetNATPortForward",
            vnet.encode(),
            proto,
            args.hport,
            args.vm_ip.encode(),
            args.vm_port,
            args.desc,
            0,
        )  # desc: str -> wchar_t*
        print(
            f"* {vnet} map {args.proto} host:{args.hport} -> {args.vm_ip}:{args.vm_port}: "
            f"{'ok' if rc == 1 else 'rc=' + str(rc)}"
        )
    else:  # remove: same call with vmIP NULL (GUI-proven delete semantics)
        rc = vl._c("VNL_SetNATPortForward", vnet.encode(), proto, args.hport, None, 0, None, 0)
        print(
            f"* {vnet} unmap {args.proto} host:{args.hport}: {'ok' if rc == 1 else 'rc=' + str(rc)}"
        )
    # UpdateNATFromConfig rewrites the WHOLE conf from the given vnet's config —
    # regen the target last so its forwards/sections are the ones in the file.
    vl._c("VNL_UpdateNATFromConfig", vnet.encode())
    restart_services(dhcp=False, nat=True)


def cmd_natcfg(vl, args):
    require_vnet(vl, args.vnet)
    vnet = f"vmnet{args.vnet}"
    if not reg_flag(vnet, "NAT") and not (vl.features(vnet) or 0) & 0x10000:
        sys.exit(f"{vnet} is not a NAT network")
    key = f"{CFG}\\{vnet}\\NAT"
    if args.action == "show":
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
        except FileNotFoundError:
            sys.exit(f"no NAT config key for {vnet}")
        with k:
            for i in range(winreg.QueryInfoKey(k)[1]):
                name, val, _ = winreg.EnumValue(k, i)
                print(f"  {name} = {val}")
        return
    changed = False
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
        for flag, (rname, rtype) in NATVAL.items():
            val = getattr(args, flag, None)
            if val is None:
                continue
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


def cmd_setip(vl, args):
    require_vnet(vl, args.vnet)
    vnet = f"vmnet{args.vnet}"
    rc = vl._c("VNL_SetVnetAdapterAddr", vnet.encode(), args.addr.encode())
    print(f"* {vnet} adapter IP {args.addr}: {'ok' if rc == 1 else 'rc=' + str(rc)}")
    vl.update_adapter(vnet)  # apply to the live device, not just the config
    cur = vl.get_str("VNL_GetVnetAdapterAddr", vnet)
    print(f"  configured adapter addr: {cur!r}")


def cmd_export(vl, args):
    import os

    if os.path.exists(args.file):
        os.remove(args.file)  # export refuses existing files; match the C tool
    rc = vl._c("VNL_ExportDatabaseToFile", args.file)
    print(f"export -> {args.file}: {'ok' if rc == 1 else 'rc=' + str(rc)}")
    if rc != 1:
        sys.exit(1)


def cmd_import(vl, args):
    rc = vl._c("VNL_ImportDatabaseFromFile", args.file)
    print(f"import <- {args.file}: {'ok' if rc == 1 else 'rc=' + str(rc)}")
    if rc != 1:
        sys.exit(1)
    vl.update_dhcp("vmnet1")
    regen_nat_conf(vl)
    restart_services(dhcp=True, nat=True)
