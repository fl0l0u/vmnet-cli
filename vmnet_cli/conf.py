# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.conf - see vmnet_cli.cli for the tool overview."""

import re
import sys
import time
import winreg

from .registry import CFG, reg_flag
from .vnl import VNetLib


def _nat_conf_device():
    """The `device = vmnetN` the current vmnetnat.conf renders (last wins)."""
    dev = None
    try:
        with open(r"C:\ProgramData\VMware\vmnetnat.conf", errors="replace") as f:
            for line in f:
                m = re.match(r"\s*device\s*=\s*(\S+)", line)
                if m:
                    dev = m.group(1)
    except OSError:
        pass
    return dev


def regen_nat_conf(vl):
    """vmnetnat.conf has ONE [host] section; regenerate for every NAT vnet,
    ascending, so the file stays consistent with config. The LAST vnet wins
    (each call rewrites the whole file) — but vnetlib intermittently no-ops
    a call (internal-lock serialization), leaving the conf rendering a
    removed vnet; verify the final render and retry it if stale."""
    last = None
    for n in range(2, vl.count()):
        v = f"vmnet{n}"
        if reg_flag(v, "NAT") or (vl.features(v) or 0) & 0x10000:
            vl._c("VNL_UpdateNATFromConfig", v.encode())
            last = v
    if last:
        for _ in range(3):
            if _nat_conf_device() == last:
                return
            time.sleep(1)
            vl._c("VNL_UpdateNATFromConfig", last.encode())
        print(
            f"warning: vmnetnat.conf still renders {_nat_conf_device()}, expected {last}",
            file=sys.stderr,
        )


def ensure_nat(vnet, on):
    vl = VNetLib()
    vl._c("VNL_SetVnetUseNAT", vnet.encode(), 1 if on else 0)
    if on and not reg_flag(vnet, "NAT"):
        # VNL_SetVnetUseNAT does not create the NAT subkey for a fresh vnet
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{CFG}\\{vnet}\\NAT") as k:
            winreg.SetValueEx(k, "UseNAT", 0, winreg.REG_DWORD, 1)


DHCP_PARAM = {"begin": 0x3426, "end": 0x3427, "default_lease": 0x342A, "max_lease": 0x342B}
# vmnetcfg.exe call sites proved these paramIds (0x342a/0x342b in its dhcpDlg) +
# live registry sweep mapped each to its DHCP subkey value name.


def set_dhcp_param(vl, vnet, key, value):
    v = str(value).encode()
    return vl._c("VNL_SetDHCPParam", vnet.encode(), DHCP_PARAM[key], v, len(v))


NATVAL = {  # cli flag -> (registry value name, type) — UpdateNATFromConfig reads these
    "gateway_ip": ("ip", winreg.REG_SZ),
    "host_ip": ("hostIp", winreg.REG_SZ),
    "configport": ("ConfigPort", winreg.REG_DWORD),
    "ipv6": ("natIp6Enable", "bool"),
    "active_ftp": ("activeFTP", "bool"),
    "allow_any_oui": ("allowAnyOUI", "bool"),
    "udp_timeout": ("udpTimeout", winreg.REG_DWORD),
    "dns_auto": ("DNSAutodetect", "bool"),
    "dns1": ("DNSNameServer1", winreg.REG_SZ),
    "dns2": ("DNSNameServer2", winreg.REG_SZ),
    "dns3": ("DNSNameServer3", winreg.REG_SZ),
    "dns_policy": ("DNSPolicy", winreg.REG_SZ),
    "dns_retries": ("DNSRetries", winreg.REG_DWORD),
    "dns_timeout": ("DNSTimeout", winreg.REG_DWORD),
    "nbns_timeout": ("NBNSTimeout", winreg.REG_DWORD),
}
