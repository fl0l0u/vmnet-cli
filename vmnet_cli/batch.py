# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.batch - see vmnet_cli.cli for the tool overview."""

import time
import winreg

from .adapters import (
    _adapters_present_set,
    _name_adapter,
    uninstall_adapter_finish,
    uninstall_adapter_start,
)
from .conf import regen_nat_conf
from .registry import CFG, reg_bridge_bindings, reg_bridge_del, reg_delete_tree, reg_flag
from .services import cycle_bridge, restart_services
from .vnl import FEATURE_BITS, VL


def batch_new():
    """Collects multi-network changes so every expensive wait/restart happens
    once for the whole batch instead of once per network."""
    return {"dhcp": False, "nat": False, "bridge": False, "gone": [], "added": [], "vnets": []}


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
        ctx["nat"] = True  # conf regen once at apply (whole-file rewrite)
    return True


def _present_safe():
    """Adapter enumeration must never abort a batch apply: a transient
    failure degrades to 'nothing present' (matching the C tool, whose
    enumeration just returns 0 on failure), with a warning. The service
    and bridge phases below must always run."""
    try:
        return _adapters_present_set()
    except Exception as e:
        print(f"  WARNING: adapter enumeration failed: {e}")
        return set()


def batch_apply(vl, ctx):
    """One wait for all PnP operations, one conf regen, one service restart,
    one bridge cycle — regardless of batch size."""
    if ctx["nat"]:
        regen_nat_conf(vl)
        print("  - vmnetnat.conf regenerated")
    if ctx["gone"]:
        try:
            time.sleep(3)
            present = _present_safe()
            for n in ctx["gone"]:
                if n in present:
                    uninstall_adapter_finish(n, present=present)
                    present = _present_safe()
                print(
                    f"  - host adapter device vmnet{n}: {'STILL PRESENT' if n in present else 'gone'}"
                )
        except Exception as e:
            print(f"  WARNING: adapter removal step failed: {e} (continuing)")
    if ctx["added"]:
        try:
            pending = list(ctx["added"])
            for _ in range(10):
                time.sleep(3)
                present = _present_safe()
                pending = [n for n in pending if n not in present]
                if not pending:
                    break
            import subprocess

            exe = VL.rsplit("\\", 1)[0] + "\\drvInst64.exe"
            inf = VL.rsplit("\\", 1)[0] + "\\netadapter.inf"
            for n in pending:
                try:
                    subprocess.run(
                        [exe, "installRootDriver", "0", f"*VMnetAdapter{n}", inf, "1"],
                        capture_output=True,
                        timeout=120,
                    )
                except (subprocess.TimeoutExpired, OSError):
                    pass  # keep waiting; do not abort the batch
            time.sleep(3)
            for _ in range(4):
                if not pending:
                    break
                time.sleep(3)
                present = _present_safe()
                pending = [n for n in pending if n not in present]
            present = _present_safe()
            for n in ctx["added"]:
                if n in present:
                    _name_adapter(f"vmnet{n}")
                print(
                    f"  - host adapter device vmnet{n}: {'ok' if n in present else 'pending/failed (PnP is async)'}"
                )
        except Exception as e:
            print(f"  WARNING: adapter install step failed: {e} (continuing)")
    if ctx["dhcp"] or ctx["nat"]:
        restart_services(dhcp=ctx["dhcp"], nat=ctx["nat"])
    if ctx["bridge"]:
        cycle_bridge()
    for n in ctx["vnets"]:
        left = vl.features(f"vmnet{n}") or 0  # absent (None) counts as removed
        print(f"  {'OK' if left == 0 else 'WARNING'}: vmnet{n} features now 0x{left:08x}")
