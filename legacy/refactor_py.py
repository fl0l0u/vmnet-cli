#!/usr/bin/env python3
"""Mechanically split vmnet-cli.py into the vmnet_cli package (behavior-preserving)."""
import re, os, sys

SRC = "vmnet-cli.py"
lines = open(SRC).read().splitlines(keepends=True)

starts = []
for i, ln in enumerate(lines):
    m = re.match(r"(?:def|class) ([A-Za-z_]\w*)", ln)
    if m:
        starts.append((i, m.group(1)))
        continue
    m = re.match(r"([A-Z_][A-Z_0-9]*) =", ln)
    if m:
        starts.append((i, m.group(1)))
        continue
    if ln.startswith('if __name__'):
        starts.append((i, "__main__guard__"))

def chunk_start(idx):
    s = starts[idx][0]
    j = s - 1
    while j >= 0:
        t = lines[j].strip()
        if t.startswith("#") or t == "":
            if t == "" and j < s - 1:
                break            # stop at blank line unless directly attached
            j -= 1
            continue
        break
    return j + 1

MAP = {
    "VL": "vnl", "FEATURE_BITS": "vnl", "_vlbuf": "vnl", "VNetLib": "vnl",
    "vnet_in_use": "vnl", "pick_vnet": "vnl",
    "BRIDGE_TABLE": "registry", "CFG": "registry",
    "reg_bridge_bindings": "registry", "reg_bridge_set": "registry",
    "reg_bridge_del": "registry", "reg_exists": "registry",
    "reg_flag": "registry", "reg_delete_tree": "registry",
    "cycle_bridge": "services", "restart_services": "services",
    "physical_interfaces": "adapters", "PHYSICAL_BUSES": "adapters",
    "NET_CLASS": "adapters", "_adapter_medium": "adapters",
    "classify_interfaces": "adapters", "install_adapter_start": "adapters",
    "install_adapter_finish": "adapters", "install_adapter": "adapters",
    "_adapter_present": "adapters", "_name_adapter": "adapters",
    "_adapters_present_set": "adapters", "uninstall_adapter_start": "adapters",
    "uninstall_adapter_finish": "adapters", "uninstall_adapter": "adapters",
    "DHCP_PARAM": "conf", "NATVAL": "conf", "regen_nat_conf": "conf",
    "ensure_nat": "conf", "set_dhcp_param": "conf",
    "batch_new": "batch", "remove_stage": "batch", "remove_vnet": "batch",
    "batch_apply": "batch",
    "cmd_adapters": "commands", "cmd_list": "commands", "cmd_add": "commands",
    "cmd_edit": "commands", "cmd_bridged": "commands", "cmd_unpin": "commands",
    "cmd_autobridge": "commands", "cmd_restore": "commands",
    "cmd_clear": "commands", "cmd_remove": "commands",
    "cmd_setip": "commands_nat", "cmd_natfw": "commands_nat",
    "cmd_natcfg": "commands_nat", "cmd_export": "commands_nat",
    "cmd_import": "commands_nat",
    "parse_vnet": "cli", "main": "cli", "__main__guard__": "cli",
}

os.makedirs("py/vmnet_cli", exist_ok=True)
modules = {}
unmapped = []
for k, (ln, name) in enumerate(starts):
    start = chunk_start(k)
    end = chunk_start(k + 1) if k + 1 < len(starts) else len(lines)
    end = max(end, ln + 1)
    text = "".join(lines[start:end])
    mod = MAP.get(name)
    if mod is None:
        unmapped.append((ln + 1, name))
        continue
    modules.setdefault(mod, []).append((name, text))
if unmapped:
    print("UNMAPPED (fix MAP):", unmapped)
    sys.exit(1)

# the module docstring (usage banner) lives before the first def: move to cli.py
doc = "".join(lines[:starts[0][0]])
m = re.match(r'(/\*.*?\*/|"""(?:[^"]|"(?!"")[\s\S])*?""")', doc.lstrip())
usage = '"""vmnet-cli - command-line clone of the VMware Network Editor (vmnetcfg.exe).\n\n'
# keep the original usage text: extract lines between the first and last docstring quotes
orig_doc = re.search(r'"""([\s\S]*?)"""', "".join(lines[:80]))
usage = '"""vmnet-cli - command-line clone of the VMware Network Editor.'
if orig_doc:
    usage = '"""' + orig_doc.group(1) + '"""'
modules.setdefault("cli", []).insert(0, ("__doc__", usage + "\n\n"))

STDLIB = ["argparse", "ctypes", "csv", "io", "os", "re", "subprocess", "sys", "time", "winreg"]
CTYPES = ["wintypes", "byref", "create_string_buffer", "create_unicode_buffer", "c_int"]

allnames = {mod: {n for n, _ in chunks} for mod, chunks in modules.items()}
for mod, chunks in sorted(modules.items()):
    body = "".join(t for _, t in chunks)
    used_std = [s for s in STDLIB if re.search(r"\b" + s + r"\b", body)]
    ctypes_used = re.search(r"\bctypes\b", body) or any(
        re.search(r"\b" + c + r"\b", body) for c in CTYPES)
    imp = ["import " + ", ".join(used_std)] if used_std else []
    if ctypes_used:
        cu = [c for c in CTYPES if re.search(r"\b" + c + r"\b", body)]
        if re.search(r"\bctypes\.", body) and "ctypes" not in used_std:
            imp.append("import ctypes")
        if cu:
            imp.append("from ctypes import " + ", ".join(cu))
    sib = []
    for other, names in sorted(allnames.items()):
        if other == mod:
            continue
        refs = sorted(n for n in names if n != "__doc__"
                      and re.search(r"\b" + re.escape(n) + r"\b", body))
        if refs:
            sib.append(f"from .{other} import " + ", ".join(refs))
    head = f'"""vmnet_cli.{mod} - see vmnet_cli.cli for the tool overview."""\n'
    out = head + "\n".join(imp) + ("\n" if imp else "")
    if sib:
        out += "\n" + "\n".join(sib) + "\n"
    out += "\n\n" + body
    open(f"py/vmnet_cli/{mod}.py", "w").write(out)
    print(f"py/vmnet_cli/{mod}.py: {len(chunks)} items")
open("py/vmnet_cli/__init__.py", "w").write(
    '"""vmnet_cli - CLI clone of vmnetcfg.exe over vnetlib.dll (RECON.md)."""\n')
