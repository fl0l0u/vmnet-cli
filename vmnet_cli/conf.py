# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.conf - see vmnet_cli.cli for the tool overview."""

import winreg

from .registry import CFG, reg_flag
from .vnl import VNetLib


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
