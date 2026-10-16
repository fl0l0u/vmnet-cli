#!/usr/bin/env python3
"""Mechanically split vmnet-cli.c into src/ modules (behavior-preserving)."""
import re, os, sys

SRC = "vmnet-cli.c"
lines = open(SRC).read().splitlines(keepends=True)

# ---- find top-level definition starts (col-0, not inside a function) ----
def_starts = []          # (lineno0, kind, name)
for i, ln in enumerate(lines):
    m = re.match(r"(?:static\s+)?(?:const\s+)?[A-Za-z_][A-Za-z0-9_ *\t]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(", ln)
    if m and (ln.startswith("static ") or ln[:1].isalpha()) and not ln.startswith("typedef"):
        # function definition or one-liner; exclude calls (col-0 never a call)
        def_starts.append((i, "fn", m.group(1)))
        continue
    if re.match(r"typedef struct", ln):
        def_starts.append((i, "struct", None))
        continue
    if re.match(r"typedef ", ln):
        def_starts.append((i, "typedef", ln.split("(")[0].split()[-1]))
        continue
    if re.match(r"static (const )?(char|int|WCHAR|HMODULE)\b[^;=]*[=;]", ln):
        def_starts.append((i, "data", ln.split("=")[0].split(";")[0].replace("static", "").strip().split()[-1].lstrip("*").split("[")[0]))
        continue
    if re.match(r"(int g_|char \*\*g_)", ln):
        def_starts.append((i, "data", ln.split("=")[0].split()[1].rstrip(";")))
        continue

# struct typedefs span multiple lines to "};" — mark ends
# chunks: comment block directly above belongs to the item
def chunk_start(idx):
    s = def_starts[idx][0]
    j = s - 1
    # absorb immediately-preceding comment lines (allowing the banner style)
    while j >= 0:
        t = lines[j].strip()
        if t.startswith("*") or t.startswith("/*") or t.startswith("//") or t.startswith("*/"):
            j -= 1
            continue
        break
    return j + 1

MAP = {
    "die": "util", "rcs": "util", "xmalloc": "util", "upper": "util",
    "ci_contains": "util", "ends_with": "util", "w2u8": "util", "u82w": "util",
    "sleep_ms": "util", "run_hidden": "util", "enable_privilege": "util",
    "subnet_host1": "util",
    "VL_PATH": "util", "VMWARE_DIR": "util", "BRIDGE_TABLE": "util",
    "CFG": "util", "NET_CLASS": "util",
    "vl_init": "vnl", "vfn": "vnl", "vneed": "vnl", "vlstr": "vnl",
    "VL_SCRATCH": "vnl-static", "vl_si": "vnl-static", "g_vl": "vnl-static",
    "v0": "vnl", "v1": "vnl", "v1i": "vnl", "v1s": "vnl", "vfeat": "vnl",
    "vgs": "vnl", "get_str": "vnl", "set_str": "vnl", "features": "vnl",
    "vnet_count": "vnl", "vnetstr": "vnl", "vnet_in_use": "vnl",
    "regen_nat_conf": "vnl", "ensure_nat": "vnl", "bits_str": "vnl",
    "pick_vnet": "vnl", "set_dhcp_param": "vnl",
    "ropen": "registry", "reg_get_dword": "registry", "reg_get_sz": "registry",
    "reg_set_dword": "registry", "reg_set_sz": "registry", "reg_exists": "registry",
    "reg_delete_tree": "registry", "reg_flag": "registry", "pins_get": "registry",
    "pin_of": "registry", "vnet_pinned": "registry", "pins_set": "registry",
    "pins_del": "registry",
    "svc_wait": "services", "svc_action": "services", "svc_stop_start": "services",
    "cycle_bridge": "services", "restart_services": "services",
    "nic_list": "adapters", "nic_present_vmnet": "adapters",
    "PHYS_BUSES": "adapters-static",
    "nic_present_set": "adapters", "pmt_for_guid": "adapters",
    "bus_of_desc": "adapters", "classify_nics": "adapters",
    "drvinst_install": "adapters", "install_adapter_start": "adapters",
    "install_adapter_finish": "adapters", "install_adapter": "adapters",
    "pnputil_remove_vmnet": "adapters", "uninstall_adapter_start": "adapters",
    "uninstall_adapter_finish": "adapters", "uninstall_adapter": "adapters",
    "batch_new": "batch", "set_has": "batch", "remove_stage": "batch",
    "batch_apply": "batch",
    "g_argc": "args", "g_argv": "args", "opt_str": "args", "opt_flag": "args",
    "parse_vnet": "args",
    "cmd_adapters": "cmds_topo", "cmd_list": "cmds_topo", "cmd_add": "cmds_topo",
    "cmd_edit": "cmds_topo", "cmd_bridged": "cmds_topo", "cmd_unpin": "cmds_topo",
    "cmd_autobridge": "cmds_topo",
    "cmd_setip": "cmds_cfg", "cmd_export": "cmds_cfg", "copy_tree": "cmds_cfg",
    "cmd_import": "cmds_cfg", "cmd_natfw": "cmds_cfg", "cmd_natcfg": "cmds_cfg",
    "cmd_remove": "cmds_remove", "cmd_clear": "cmds_remove",
    "cmd_restore": "cmds_remove",
    "main": "main",
}
HEADER_TYPES = ("Nic", "Pin", "Batch")   # struct typedef names

os.makedirs("src", exist_ok=True)
modules = {}
protos = []
types = []
unmapped = []

for k, (ln, kind, name) in enumerate(def_starts):
    start = chunk_start(k)
    end = chunk_start(k + 1) if k + 1 < len(def_starts) else len(lines)
    end = max(end, ln + 1)
    # include trailing blank lines up to next chunk start (chunk_start rewinds comments)
    text = "".join(lines[start:end])
    if kind in ("struct", "typedef"):
        # struct typedef: name is at "} Name;"
        m = re.search(r"}\s*(\w+);", text)
        nm = m.group(1) if m else name
        if kind == "struct" or nm in ("F0", "F1s", "F1si", "F1ss", "F1sip", "F3s",
                                      "F4", "F5i", "F3u", "F7pf"):
            types.append(text.rstrip() + "\n")
            continue
        # typedef struct one-liner handled above too
        types.append(text.rstrip() + "\n")
        continue
    mod = MAP.get(name)
    if mod is None:
        unmapped.append((ln + 1, kind, name))
        continue
    if mod.endswith("-static"):                 # module-private data
        modules.setdefault(mod[:-7], []).append(("private", name, text))
        continue
    if mod == "header":
        continue
    if kind == "data":
        # constants defined in util.c, externed in header
        decl = text.replace("static ", "", 1)
        modules.setdefault(mod, []).append(("data", name, decl))
        ext = text.replace("static const ", "extern const ").replace("static ", "extern ")
        ext = ext.split("=")[0].strip() + ";"
        protos.append(("data", ext))
        continue
    # function: strip leading static, emit prototype
    blines = text.splitlines(keepends=True)
    di = 0
    while di < len(blines) and re.match(r"\s*(/\*|\*|//)", blines[di]):
        di += 1
    if blines[di].startswith("static "):
        blines[di] = blines[di].replace("static ", "", 1)
        text = "".join(blines)
    sig = "".join(blines[di:di + 2])
    proto = sig.split("{")[0] if "{" in sig else blines[di]
    proto = re.sub(r"\s+", " ", proto).strip() + ";"
    modules.setdefault(mod, []).append(("fn", name, text))
    protos.append(("fn", proto))

if unmapped:
    print("UNMAPPED definitions (fix MAP):")
    for u in unmapped:
        print("  line", u[0], u[1], u[2])
    sys.exit(1)

# ---- write header ----
hdr = ["""/* vmnet.h - VMware virtual-network CLI, internal interface.
 *
 * Reverse-engineered surface: vnetlib.dll's VNL_* exports (see RECON.md).
 * Two invariants every module must honor:
 *   - every string passed to VNL_* goes through vlstr() (>=512-byte zeroed
 *     scratch): vnetlib zero-pads fixed-width string args IN PLACE.
 *   - most VNL calls return rc=1 for success; getters may write past their
 *     out-buffer's length field — out buffers must be big and pre-zeroed.
 */
#ifndef VMNET_H
#define VMNET_H

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <winreg.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ---- shared constants (defined in util.c) ---- */
"""]
for _, d in protos:
    if d.startswith("extern const"):
        hdr.append(d + "\n")
hdr.append("\n/* ---- shared types ---- */\n")
hdr += types
hdr.append("""
/* ---- module interfaces ---- */
/* util.c */
""")
seen = set()
for kind, d in protos:
    if kind == "fn" and d not in seen:
        seen.add(d)
        hdr.append(d + "\n")
# g_argc/g_argv externs
hdr.append("\nextern int g_argc;\nextern char **g_argv;\n")
hdr.append("\n#endif /* VMNET_H */\n")
open("src/vmnet.h", "w").write("".join(hdr))

# ---- write module files ----
DESCR = {
    "util": "small shared helpers: fatal error, string/file/locale glue, subprocess",
    "vnl": "vnetlib.dll loading + the VNL_* calling layer (vlstr discipline lives here)",
    "registry": "HKLM VMnetConfig database + VMnetBridge adapter pin table",
    "services": "VMnetDHCP / VMnetNAT / VMnetBridge service control via the SCM",
    "adapters": "host virtual NIC enumeration, classification and PnP install/remove",
    "batch": "stage/apply context: multi-network ops pay every wait ONCE",
    "args": "argv accessors shared by the command implementations",
    "cmds_topo": "commands: adapters, list, add, edit, bridged, unpin, autobridge",
    "cmds_cfg": "commands: set-ip, export, import, natfw, natcfg",
    "cmds_remove": "commands: remove, clear/flush, restore-defaults",
    "main": "entry point: command dispatch",
}
for mod, chunks in sorted(modules.items()):
    out = [f'/* {mod}.c - {DESCR.get(mod, "")} */\n#include "vmnet.h"\n\n']
    for kind, name, text in chunks:
        out.append(text if text.endswith("\n") else text + "\n")
        out.append("\n")
    open(f"src/{mod}.c", "w").write("".join(out))
    print(f"src/{mod}.c: {len(chunks)} items, {sum(t.count(chr(10)) for _, _, t in chunks)} lines")
