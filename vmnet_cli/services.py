# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.services - see vmnet_cli.cli for the tool overview."""

import subprocess
import time

from .vnl import VNetLib


def cycle_bridge():
    """Reload the bridge driver so it re-reads Parameters\\Adapters bindings."""
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


def restart_services(dhcp=True, nat=False):
    """VNL_Stop/Start* like vmnetcfg.exe does; sc.exe fallback."""
    for key, svc in (("dhcp", "VMnetDHCP"), ("nat", "VMware NAT Service")):
        if not (dhcp if key == "dhcp" else nat):
            continue
        vl = VNetLib()
        stop, start = "VNL_Stop" + key.upper(), "VNL_Start" + key.upper()
        if vl._c(stop) != 1:
            try:
                subprocess.run(["sc.exe", "stop", svc], capture_output=True, timeout=30)
            except FileNotFoundError:
                raise SystemExit(f"cannot stop {svc}: no VNL export and no sc.exe") from None
        time.sleep(2)
        if vl._c(start) != 1:
            try:
                subprocess.run(["sc.exe", "start", svc], capture_output=True, timeout=30)
            except FileNotFoundError:
                raise SystemExit(f"cannot start {svc}: no VNL export and no sc.exe") from None
        time.sleep(3)
