# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.vnl - see vmnet_cli.cli for the tool overview."""

import ctypes
import locale
import sys
from ctypes import byref, c_int, create_string_buffer, create_unicode_buffer

from .registry import CFG, reg_bridge_bindings, reg_exists

# VNL's char* APIs are ANSI: use the system codepage so strings round-trip
# exactly like they do through the C tool's char* arguments.
_ANSI = locale.getpreferredencoding(False)


VL = r"C:\Program Files\VMware\VMware Workstation\vnetlib.dll"

FEATURE_BITS = {0x1: "bridged", 0x100: "hostonly-adapter", 0x10000: "nat", 0x1000000: "dhcp"}
# Binding model (reverse engineered, verified live):
#   HKLM\SYSTEM\CurrentControlSet\Services\VMnetBridge\Parameters\Adapters\{adapter-guid}\VMnet = N
#   pins that physical adapter to vmnet segment N; reload with a VMnetBridge driver cycle.
#   VNL_GetVNetFeatures then reports bit 0x1 (bridged) on vmnetN.


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
            return 2  # missing export: let callers fall back (RECON §9 hygiene)
        f.restype = c_int
        return f(*[_vlbuf(a) for a in args])

    def count(self):
        return self._c("VNL_GetNumberOfVnets")

    def features(self, vnet):
        feat = c_int(0)
        rc = self._c("VNL_GetVNetFeatures", vnet.encode(), byref(feat))
        return feat.value if rc == 1 else None

    def get_str(self, fn, vnet):
        buf = create_string_buffer(512)
        ln = c_int(512)
        rc = self._c(fn, vnet.encode(), buf, byref(ln))
        return buf.value.decode(_ANSI, errors="replace") if rc in (0, 1) and buf.value else ""

    def set_str(self, fn, vnet, val):
        # VNL string APIs are ANSI (char*): encode like the C tool's char*
        # would, so names round-trip identically through both implementations.
        return self._c(
            fn, vnet.encode(), val.encode(_ANSI, "replace") if isinstance(val, str) else val
        )

    def set_use_dhcp(self, vnet, on):
        return self._c("VNL_SetVnetUseDHCP", vnet.encode(), on)

    def set_use_nat(self, vnet, on):
        return self._c("VNL_SetVnetUseNAT", vnet.encode(), on)

    def update_adapter(self, vnet=None):
        # dereferences arg1; pass NULL (rebuild all) or the vnet string explicitly
        return self._c("VNL_UpdateAdapterFromConfig", vnet.encode() if vnet else None)

    def update_dhcp(self, vnet):
        return self._c("VNL_UpdateDHCPFromConfig", vnet.encode())

    def stop_bridge(self):
        return self._c("VNL_StopBridge")

    def start_bridge(self):
        return self._c("VNL_StartBridge")


def require_vnet(vl, n):
    """VNL resolves out-of-range segment names by clamping reads (setters
    validate), so every --vnet must be range-checked before use."""
    c = vl.count()
    if not 0 <= n < c:
        sys.exit(f"vmnet{n} is not a valid segment (0..{c - 1})")


def vnet_in_use(vl, n):
    f = vl.features(f"vmnet{n}")
    # config key is ground truth too: features can transiently read 0
    return (f or 0) != 0 or reg_exists(CFG + f"\\vmnet{n}") or n in (0, 1, 8)


def pick_vnet(vl, n=None):
    if n is not None:
        return n
    taken = set(reg_bridge_bindings().values())
    c = vl.count()
    for k in range(2, c):
        if k not in taken and not vnet_in_use(vl, k):
            return k
    raise SystemExit(f"no free vmnet segment (2..{c - 1})")
