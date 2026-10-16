# SPDX-License-Identifier: Apache-2.0
"""vmnet_cli.registry - see vmnet_cli.cli for the tool overview."""

import winreg

BRIDGE_TABLE = r"SYSTEM\CurrentControlSet\Services\VMnetBridge\Parameters\Adapters"
CFG = r"SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig"


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
    except OSError:
        pass  # C tool ignores the rc too


def reg_exists(path):
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path).Close()
        return True
    except OSError:
        return False


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
