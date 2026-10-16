# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.commands - see vmnet_cli.cli for the tool overview."""

import sys
import time
import winreg

from .adapters import (
    _adapter_present,
    classify_interfaces,
    install_adapter,
    install_adapter_start,
    physical_interfaces,
    uninstall_adapter,
)
from .batch import batch_apply, batch_new, remove_stage
from .conf import ensure_nat, regen_nat_conf, set_dhcp_param
from .registry import CFG, reg_bridge_bindings, reg_bridge_del, reg_bridge_set, reg_exists, reg_flag
from .services import cycle_bridge, restart_services
from .vnl import FEATURE_BITS, pick_vnet, require_vnet, vnet_in_use


def cmd_adapters(vl):
    iface = physical_interfaces()
    bound = reg_bridge_bindings()
    for name, guid in sorted(iface.items(), key=lambda kv: kv[1]):
        v = bound.get(guid)
        print(f"{name:30} {guid}  -> {'vmnet' + str(v) if v is not None else 'vmnet0 (auto)'}")


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
                if reg_flag(vnet, "DHCP"):
                    f |= 0x1000000
                if reg_flag(vnet, "NAT"):
                    f |= 0x10000
                if reg_flag(vnet, "Adapter"):
                    f |= 0x100
                if not f:
                    f = 1
            if any(v == n for v in bindings.values()):
                f |= 1
            if not f:
                continue
        bits = ", ".join(v for b, v in FEATURE_BITS.items() if f & b)
        name = vl.get_str("VNL_GetVnetDisplayName", f"vmnet{n}")
        addr = vl.get_str("VNL_GetVnetSubnetAddr", f"vmnet{n}")
        pins = [g for g, v in bindings.items() if v == n]
        extra = f" pinned={','.join(pins)}" if pins else ""
        print(f"vmnet{n:<2} {bits:40} name={name!r} subnet={addr}{extra}")


def cmd_add(vl, args):
    if args.vnet is not None:
        require_vnet(vl, args.vnet)
    if args.vnet == 0:
        sys.exit(
            "vmnet0 is the built-in bridge segment; it cannot be re-typed "
            "(segment 0 lives in the VMnetBridge driver, not in config)"
        )
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
    print(
        f"* add {args.kind}: {vnet} name={args.name!r} subnet={subnet}"
        f" dhcp={'on' if dhcp else 'off'} nat={'on' if is_nat else 'off'}"
    )
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
    for _ in range(10):  # adapter/NAT bits settle asynchronously (RECON §7)
        f = vl.features(vnet) or 0
        if f & want == want:
            break
        time.sleep(2)
    print(f"  {'OK' if f & want == want else 'WARNING'}: features=0x{f:08x}")


def cmd_edit(vl, args):
    vnet = f"vmnet{args.vnet}"
    n = args.vnet
    require_vnet(vl, n)
    if n == 0 and args.type:
        sys.exit("vmnet0 is the built-in bridge segment; it cannot be re-typed")
    if vl.features(vnet) is None:
        sys.exit(f"{vnet} not readable")
    dhcp_changed = nat_changed = subnet_changed = False
    if args.type:
        if args.type == "nat":
            ensure_nat(vnet, True)
            vl.set_use_dhcp(vnet, 1)
            dhcp_changed = nat_changed = True
            if not _adapter_present(vnet):
                install_adapter(vnet)
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\Adapter") as k:
                    winreg.SetValueEx(k, "UseAdapter", 0, winreg.REG_DWORD, 1)
        elif args.type == "hostonly":
            ensure_nat(vnet, False)
            nat_changed = True
            if not _adapter_present(vnet):
                install_adapter(vnet)
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\Adapter") as k:
                    winreg.SetValueEx(k, "UseAdapter", 0, winreg.REG_DWORD, 1)
        else:  # bridged: strip NAT/DHCP/adapter; bind a NIC with the `bridged` command
            ensure_nat(vnet, False)
            vl.set_use_dhcp(vnet, 0)
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
                vl._c(
                    "VNL_SetVnetAdapterAddr",
                    vnet.encode(),
                    (subnet.rsplit(".", 1)[0] + ".1").encode(),
                )
        else:
            uninstall_adapter(vnet, n)
        print(f"* {vnet} host adapter {args.adapter}")
    if args.name is not None:
        vl.set_str("VNL_SetVnetDisplayName", vnet, args.name)
        print(f"* {vnet} DisplayName={args.name!r}")
    if args.subnet or args.mask:
        if args.subnet:
            vl.set_str("VNL_SetVnetSubnetAddr", vnet, args.subnet)
        vl.set_str(
            "VNL_SetVnetSubnetMask", vnet, args.mask or vl.get_str("VNL_GetVnetSubnetMask", vnet)
        )
        subnet_changed = True
        print(
            f"* {vnet} subnet={vl.get_str('VNL_GetVnetSubnetAddr', vnet)}/{vl.get_str('VNL_GetVnetSubnetMask', vnet)}"
        )
    for key, val in (
        ("begin", args.dhcp_begin),
        ("end", args.dhcp_end),
        ("default_lease", args.lease),
        ("max_lease", args.max_lease),
    ):
        if val is not None:
            rc = set_dhcp_param(vl, vnet, key, val)
            print(f"* {vnet} DHCP {key}={val}: {'ok' if rc == 1 else 'rc=' + str(rc)}")
            dhcp_changed = True
    if args.dhcp:
        vl.set_use_dhcp(vnet, 1 if args.dhcp == "on" else 0)
        dhcp_changed = True
        print(f"* {vnet} UseDHCP={args.dhcp}")
    if args.nat:
        ensure_nat(vnet, args.nat == "on")
        nat_changed = True
        print(f"* {vnet} UseNAT={args.nat}")
    if subnet_changed or dhcp_changed:
        vl.update_dhcp(vnet)
    if subnet_changed or nat_changed:
        regen_nat_conf(vl)
    if subnet_changed or dhcp_changed or nat_changed:
        restart_services(dhcp=subnet_changed or dhcp_changed, nat=subnet_changed or nat_changed)
    print(f"  features=0x{(vl.features(vnet) or 0):08x}")


def cmd_restore(vl, args):
    if not args.force:
        sys.exit("restore-defaults removes ALL custom networks; pass --force")
    print("* restoring default networks (vmnet0 auto-bridge, vmnet1 host-only, vmnet8 NAT)")
    ctx = batch_new()
    for n in range(2, vl.count()):
        if n in (1, 8):
            continue
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
        install_adapter_start(vnet)  # kicked now, awaited together in apply
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
    ctx["dhcp"] = ctx["nat"] = True  # one restart for the whole restore
    batch_apply(vl, ctx)


def cmd_bridged(vl, args):
    iface = physical_interfaces()
    if args.adapter not in iface:
        sys.exit(
            f"ERROR: no network interface named {args.adapter!r} on this host. "
            f"Available: {', '.join(sorted(iface))}"
        )
    guid = iface[args.adapter]
    if args.vnet is not None:
        require_vnet(vl, args.vnet)
        if args.vnet == 0:
            sys.exit("vmnet0 is the built-in bridge segment; it cannot be pinned")
        n = args.vnet
    else:
        taken = set(reg_bridge_bindings().values())
        c = vl.count()
        n = next((k for k in range(2, c) if k not in taken and not vnet_in_use(vl, k)), None)
        if n is None:
            raise SystemExit(f"no free vmnet segment (2..{c - 1})")
    vnet = f"vmnet{n}"
    print(f"* {args.name}: {vnet} bridged to interface {args.adapter!r} ({guid})")
    reg_bridge_set(guid, n)
    vl.set_str("VNL_SetVnetDisplayName", vnet, args.name)
    vl.set_use_dhcp(vnet, 0)
    vl.set_use_nat(vnet, 0)
    cycle_bridge()
    f = vl.features(vnet)
    ok = f is not None and f & 0x1
    print(f"  {'OK' if ok else 'WARNING: bridged bit not set'}: {vnet} features=0x{(f or 0):08x}")


def cmd_unpin(vl, args):
    require_vnet(vl, args.vnet)
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
    named = {}  # display name -> vnet, so a segment from an earlier run is
    for k in range(1, vl.count()):  # adopted instead of duplicating the name
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
                print(
                    f"* {ifname} already pinned to {vnet} with host network "
                    "config; left alone (use unpin/remove to reclaim it)"
                )
                continue
            if vl.get_str("VNL_GetVnetDisplayName", vnet) != want:
                vl.set_str("VNL_SetVnetDisplayName", vnet, want)
                changed = True
                print(f"* {vnet} renamed to {want} ({ifname})")
            else:
                print(f"* {vnet} already bridges {ifname} as {want}")
            continue
        n = named.get(want)
        if n is not None and (
            n in pins.values() or n in planned or (vl.features(f"vmnet{n}") or 0) & ~0x1
        ):
            n = None  # name taken by a real network elsewhere
        if n is None:
            taken = set(pins.values()) | planned
            cmax = vl.count()
            n = next((k for k in range(2, cmax) if k not in taken and not vnet_in_use(vl, k)), None)
        if n is None:
            print(f"ERROR: no free vmnet segment (2..{cmax - 1}) for {ifname}")
            continue
        vnet = f"vmnet{n}"
        print(
            f"* autobridge {ifname} ({desc}; {kind}) -> {vnet} as {want}"
            + (" [dry-run]" if args.dry_run else "")
        )
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
        print(f"  {'OK' if ok else 'WARNING'}: vmnet{n} pinned to {guid} features=0x{(f or 0):08x}")


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
            continue  # silent segment: nothing to do
        remove_stage(vl, n, ctx)
    batch_apply(vl, ctx)


def cmd_remove(vl, args):
    for n in args.vnet:  # validate everything before touching anything
        require_vnet(vl, n)
        if n == 0:
            sys.exit("vmnet0 is the built-in bridge segment and cannot be removed")
        if n in (1, 8) and not args.force:
            sys.exit(f"vmnet{n} is a stock Workstation network; pass --force to remove it anyway")
    ctx = batch_new()
    for n in args.vnet:
        remove_stage(vl, n, ctx)
    batch_apply(vl, ctx)
