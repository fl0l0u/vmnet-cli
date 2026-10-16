#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""End-to-end test suite for vmnet-cli.py, run remotely against the Windows
test box over WinRM. Each command is validated against ground
truth: registry, generated conf files, PnP devices, and live feature bits.

Baseline assumed at start and restored at end: vmnet0 (auto-bridged) +
vmnet8 (NAT). Test segments: vmnet2..vmnet4. Exit code = number of failures.
"""

import os
import re
import sys
import time

import winrm

BOX = "http://" + os.environ.get("VMNET_TEST_BOX", "") + ":5985/wsman"
USER = os.environ.get("VMNET_TEST_USER")
PW = os.environ.get("VMNET_TEST_PW")
if not (os.environ.get("VMNET_TEST_BOX") and USER and PW):
    sys.exit(
        "set VMNET_TEST_BOX / VMNET_TEST_USER / VMNET_TEST_PW "
        "to your Windows test box before running"
    )
S = winrm.Session(BOX, auth=(USER, PW), transport="ntlm")
PY = r"C:\Temp\py\python.exe"
CLI = (
    r"C:\ludus\vmnet-cli.exe" if os.environ.get("VMNET_TOOL") == "exe" else r"C:\ludus\vmnet-cli.py"
)
CFG = r"HKLM\SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig"
BR = r"HKLM\SYSTEM\CurrentControlSet\Services\VMnetBridge\Parameters\Adapters"
DHCP_CONF = r"C:\ProgramData\VMware\vmnetdhcp.conf"
NAT_CONF = r"C:\ProgramData\VMware\vmnetnat.conf"

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   [{detail}]"), flush=True)


def ps(cmd):
    r = S.run_ps(cmd)
    out = r.std_out.decode(errors="replace")
    out = re.sub(r"#< CLIXML.*?(?:</Objs>|/>$)", "", out, flags=re.S)
    out = re.sub(r"<Objs.*?</Objs>", "", out, flags=re.S)
    return out, r.status_code


def cli(args):
    if CLI.lower().endswith(".exe"):
        out, rc = ps(f"& {CLI} {args} 2>&1 | Out-String")
    else:
        out, rc = ps(f"& {PY} {CLI} {args} 2>&1 | Out-String")
    return out, rc


def wait_for(fn, pred, timeout=90, step=5):
    end = time.time() + timeout
    val = fn()
    while time.time() < end and not pred(val):
        time.sleep(step)
        val = fn()
    return val


def list_state():
    """{n: dict(bits=set, name=str, subnet=str, pinned=[guids])}"""
    out, _ = cli("list")
    st = {}
    for m in re.finditer(r"^vmnet(\d+)\s+(.*?)\s+name='(.*?)'\s+subnet=(\S*)(.*)$", out, re.M):
        n, bits, name, subnet, rest = int(m[1]), m[2], m[3], m[4], m[5]
        st[n] = {
            "bits": {b.strip() for b in bits.split(",") if b.strip()},
            "name": name,
            "subnet": subnet,
            "pinned": re.findall(r"pinned=(\S+)", rest),
        }
    return st


def reg_val(path, value):
    out, rc = ps(f"reg query '{path}' /v {value} 2>$null | Out-String")
    m = re.search(rf"{value}\s+REG_\w+\s+(.+)", out)
    return m[1].strip() if rc == 0 and m else None


def reg_exists(path):
    _, rc = ps(f"reg query '{path}' >$null 2>&1; exit $LASTEXITCODE")
    return rc == 0


def device(n):
    out, _ = ps(
        f"$a = Get-NetAdapter | Where-Object {{ $_.InterfaceDescription "
        f"-match 'VMnet{n}$' }}; if ($a) {{ $a.Name + '|' + $a.Status }}"
    )
    return out.strip() or None


def adapter_ip(n):
    out, _ = ps(
        f"$a = Get-NetAdapter | Where-Object {{ $_.InterfaceDescription "
        f"-match 'VMnet{n}$' }}; if ($a) {{ (Get-NetIPAddress -InterfaceIndex "
        f"$a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress }}"
    )
    return out.strip() or None


def conf_count(path, pattern):
    out, _ = ps(f"(Select-String -Path '{path}' -Pattern '{pattern}').Count")
    return int(out.strip() or 0)


def pins_for(n):
    out, _ = ps(
        f"Get-ChildItem '{BR.replace('HKLM', 'HKLM:', 1)}' -ErrorAction SilentlyContinue | "
        f"ForEach-Object {{ $v = (Get-ItemProperty $_.PSPath -Name VMnet -ErrorAction "
        f"SilentlyContinue).VMnet; if ($v -eq {n}) {{ $_.PSChildName }} }}"
    )
    return [p.strip() for p in out.split() if p.strip().startswith("{")]


def pin_count():
    out, _ = ps(
        f"(Get-ChildItem '{BR.replace('HKLM', 'HKLM:', 1)}' -ErrorAction "
        "SilentlyContinue | Where-Object { $null -ne (Get-ItemProperty $_.PSPath "
        "-Name VMnet -ErrorAction SilentlyContinue).VMnet }).Count"
    )
    return int(out.strip() or 0)


def cleanup():
    for n in (4, 3, 2):
        try:
            cli(f"remove --vnet {n}")
        except Exception:
            pass
    try:
        cli("remove --vnet 1 --force")  # may exist after restore-defaults tests
    except Exception:
        pass
    for g in [g for n in (2, 3, 4) for g in pins_for(n)]:
        ps(f"reg delete '{BR}\\{g}' /f 2>$null")
    ps("sc.exe start VMnetDHCP 2>$null; sc.exe start 'VMware NAT Service' 2>$null")


# ---------------------------------------------------------------- run suite
def main():
    print(f"target: {BOX}  tool: {CLI}\n", flush=True)

    # -- baseline ----------------------------------------------------------
    st = list_state()
    check("T01 baseline: vmnet0 bridged present", 0 in st and "bridged" in st[0]["bits"], st)
    check(
        "T02 baseline: vmnet8 nat+dhcp present",
        8 in st and {"nat", "dhcp"} <= st[8]["bits"],
        st.get(8),
    )

    # -- adapters ----------------------------------------------------------
    out, rc = cli("adapters")
    check("T03 adapters lists physical Ethernet", "Ethernet" in out and rc == 0, out)

    # -- add hostonly ------------------------------------------------------
    out, rc = cli("add hostonly --name T-HO --vnet 2 --subnet 10.99.0.0")
    check("T04 add hostonly rc", rc == 0 and "OK" in out, out)
    check("T05 registry DisplayName", reg_val(f"{CFG}\\vmnet2", "DisplayName") == "T-HO")
    check("T06 registry subnet", reg_val(f"{CFG}\\vmnet2", "IPSubnetAddress") == "10.99.0.0")
    check("T07 registry UseDHCP", reg_val(f"{CFG}\\vmnet2\\DHCP", "UseDHCP") == "0x1")
    check(
        "T08 registry UseAdapter",
        wait_for(
            lambda: reg_val(f"{CFG}\\vmnet2\\Adapter", "UseAdapter"), lambda v: v == "0x1", 60, 10
        )
        == "0x1",
    )
    check("T09 vmnetdhcp.conf stanza", conf_count(DHCP_CONF, "10\\.99\\.0") > 0)
    d = wait_for(lambda: device(2), lambda v: v is not None, 90)
    check("T10 adapter device created", d is not None, "device never appeared")
    st = wait_for(list_state, lambda s: 2 in s and "dhcp" in s[2]["bits"], 45, 10)
    check(
        "T11 features hostonly+dhcp",
        2 in st and {"hostonly-adapter", "dhcp"} <= st[2]["bits"],
        st.get(2),
    )
    ip = wait_for(lambda: adapter_ip(2), lambda v: v == "10.99.0.1", 40, 10)
    check("T12 host adapter live IP .1", ip == "10.99.0.1", f"ip={ip}")

    # -- add nat (auto subnet) ----------------------------------------------
    out, rc = cli("add nat --name T-NAT --vnet 3")
    check("T13 add nat rc", rc == 0 and "OK" in out, out)
    check("T14 registry UseNAT subkey", reg_val(f"{CFG}\\vmnet3\\NAT", "UseNAT") == "0x1")
    sub3 = reg_val(f"{CFG}\\vmnet3", "IPSubnetAddress")
    check("T15 auto-assigned subnet", bool(sub3) and re.match(r"\d+\.\d+\.\d+\.0$", sub3), sub3)
    d = wait_for(lambda: device(3), lambda v: v is not None, 90)
    check("T16 nat adapter device created", d is not None)
    st = wait_for(list_state, lambda s: 3 in s and "nat" in s[3]["bits"], 45, 10)
    check(
        "T17 features nat+dhcp",
        3 in st and {"nat", "dhcp", "hostonly-adapter"} <= st[3]["bits"],
        st.get(3),
    )
    check("T18 vmnet8 NAT conf intact", conf_count(NAT_CONF, "192\\.168\\.251\\.2") > 0)

    # -- list ---------------------------------------------------------------
    st = list_state()
    check(
        "T19 list shows both test nets",
        st.get(2, {}).get("name") == "T-HO" and st.get(3, {}).get("name") == "T-NAT",
        st,
    )

    # -- edit ---------------------------------------------------------------
    out, rc = cli("edit --vnet 2 --name HO2 --dhcp off")
    check("T20 edit rename+dhcp-off rc", rc == 0, out)
    check("T21 DisplayName edited", reg_val(f"{CFG}\\vmnet2", "DisplayName") == "HO2")
    check("T22 UseDHCP off", reg_val(f"{CFG}\\vmnet2\\DHCP", "UseDHCP") == "0x0")
    check("T23 conf stanza removed", conf_count(DHCP_CONF, "10\\.99\\.0") == 0)
    # NOTE: the live "dhcp" feature bit reflects dhcpd's interface BINDING (the host
    # adapter holds an IP on the segment), NOT the UseDHCP config — it stays set while
    # the adapter has an IP. Config truth = UseDHCP registry (T22) + conf absence (T23);
    # the bit clearing is validated at removal time (T53).
    st = wait_for(list_state, lambda s: s.get(2, {}).get("name") == "HO2", 30, 5)
    check("T24 list reflects edit (name propagated)", st.get(2, {}).get("name") == "HO2", st.get(2))

    out, rc = cli("edit --vnet vmnet2 --subnet 10.88.0.0 --dhcp on")
    check("T25 edit subnet+dhcp-on (vmnetN arg form)", rc == 0, out)
    check("T26 subnet edited", reg_val(f"{CFG}\\vmnet2", "IPSubnetAddress") == "10.88.0.0")
    check("T27 new conf stanza", conf_count(DHCP_CONF, "10\\.88\\.0") > 0)
    st = wait_for(list_state, lambda s: 2 in s and "dhcp" in s[2]["bits"], 45, 10)
    check("T28 dhcp bit restored", "dhcp" in st.get(2, {}).get("bits", set()), st.get(2))

    # -- set-ip --------------------------------------------------------------
    out, rc = cli("set-ip --vnet 2 --addr 10.88.0.5")
    check("T29 set-ip rc+readback", rc == 0 and "ok" in out, out)
    ip = wait_for(lambda: adapter_ip(2), lambda v: v == "10.88.0.5", 40, 10)
    check("T30 live adapter IP changed", ip == "10.88.0.5", f"ip={ip}")

    # -- bridged + unpin ------------------------------------------------------
    out, rc = cli("bridged --name LAN-T --adapter Ethernet --vnet 4")
    check("T31 bridged rc", rc == 0, out)
    p = pins_for(4)
    check("T32 bridge pin written", len(p) == 1, p)
    st = wait_for(list_state, lambda s: 4 in s and "bridged" in s[4]["bits"], 45, 10)
    check("T33 vmnet4 bridged bit", 4 in st and "bridged" in st[4]["bits"], st.get(4))

    out, rc = cli("bridged --name BAD --adapter NoSuchIface --vnet 5")
    check(
        "T34 bridged bad adapter errors cleanly",
        rc != 0 or "no network interface" in out.lower(),
        out,
    )

    out, rc = cli("unpin --vnet 4")
    check("T35 unpin rc", rc == 0, out)
    check("T36 pin gone", not pins_for(4))
    st = wait_for(list_state, lambda s: 4 not in s, 45, 10)
    check(
        "T37 network survives unpin (registry intact)",
        reg_val(f"{CFG}\\vmnet4", "DisplayName") == "LAN-T",
        st.get(4),
    )

    out, rc = cli("remove --vnet 4")
    check("T38 remove bridged seg", rc == 0 and "OK" in out, out)
    check("T39 vmnet4 gone from list", 4 not in list_state())

    # -- export / import -------------------------------------------------------
    out, rc = cli(r"export --file C:\Temp\testbak.hiv")
    check("T40 export rc", rc == 0 and "ok" in out, out)
    out, _ = ps(
        "$b = [System.IO.File]::ReadAllBytes('C:\\Temp\\testbak.hiv')[0..3]; "
        "-join ($b | ForEach-Object {[char]$_})"
    )
    check("T41 export is regf hive", out.strip() == "regf", out)
    before = list_state()
    out, rc = cli(r"import --file C:\Temp\testbak.hiv")
    check("T42 import rc", rc == 0 and "ok" in out, out)
    st = wait_for(list_state, lambda s: 2 in s and 3 in s, 60, 10)
    check(
        "T43 import round-trip state equal",
        st.get(2, {}).get("subnet") == before[2]["subnet"]
        and st.get(3, {}).get("name") == before[3]["name"],
        (before.get(2), st.get(2)),
    )

    # -- guards -----------------------------------------------------------------
    # VNL getters can lazily create DisplayName-only "ghost" config keys on untouched
    # vnets; remove then cleans the ghost rather than saying "nothing to remove".
    out, rc = cli("remove --vnet 5")
    check(
        "T44 remove nonexistent = clean no-op",
        rc == 0 and ("nothing to remove" in out or "removing vmnet5" in out),
        out,
    )
    check("T44b vmnet5 features zero after", 5 not in list_state())

    # -- GUI parity: NAT port forwarding (mapPortDlg) -------------------------
    sub3 = st.get(3, {}).get("subnet") or list_state()[3]["subnet"]
    vmip = sub3.rsplit(".", 1)[0] + ".50"
    out, rc = cli(
        f"natfw add --vnet 3 --proto tcp --hport 8080 --vm-ip {vmip} --vm-port 22 --desc suite"
    )
    check("T44c natfw add", rc == 0 and "ok" in out, out)
    check("T44c2 natfw conf entry", conf_count(NAT_CONF, r"8080 = ") > 0)
    out, rc = cli("natfw list --vnet 3")
    check("T44d natfw list shows entry", "tcp host:8080" in out and vmip in out, out)
    out, rc = cli("natfw remove --vnet 3 --proto tcp --hport 8080")
    check("T44e natfw remove", rc == 0 and conf_count(NAT_CONF, r"8080 = ") == 0, out)

    # -- GUI parity: NAT advanced settings (natDlg/dnsDlg) ---------------------
    out, rc = cli("natcfg set --vnet 3 --dns-auto off --dns1 8.8.8.8 --dns-policy rotate")
    check("T44f natcfg set rc", rc == 0, out)
    check("T44f2 DNS registry", reg_val(f"{CFG}\\vmnet3\\NAT", "DNSNameServer1") == "8.8.8.8")
    check("T44f3 DNS conf uncommented", conf_count(NAT_CONF, r"^nameserver1 = 8\.8\.8\.8") > 0)

    # -- GUI parity: DHCP settings dialog (dhcpDlg) ----------------------------
    p2 = list_state()[2]["subnet"].rsplit(".", 1)[0]
    out, rc = cli(f"edit --vnet 2 --dhcp-begin {p2}.64 --dhcp-end {p2}.200 --lease 3600")
    check("T44g dhcp range set", rc == 0, out)
    check(
        "T44g2 conf range",
        conf_count(DHCP_CONF, rf"range {p2.replace('.', chr(92) + '.')}\.64") > 0,
    )
    check("T44g3 conf lease", conf_count(DHCP_CONF, "default-lease-time 3600") > 0)

    # -- GUI parity: host adapter checkbox + connection type ------------------
    out, rc = cli("edit --vnet 2 --adapter off")
    d = wait_for(lambda: device(2), lambda v: v is None, 90)
    check("T44h adapter off removes device", d is None, d)
    check("T44h2 UseAdapter=0", reg_val(f"{CFG}\\vmnet2\\Adapter", "UseAdapter") == "0x0")
    out, rc = cli("edit --vnet 2 --adapter on")
    d = wait_for(lambda: device(2), lambda v: v is not None, 120)
    check("T44i adapter on recreates device", d is not None, d)
    cli("add hostonly --name TYPEX --vnet 4 --subnet 10.77.0.0")
    out, rc = cli("edit --vnet 4 --type bridged")
    check(
        "T44j type->bridged clears nat/dhcp",
        reg_val(f"{CFG}\\vmnet4\\NAT", "UseNAT") in (None, "0x0")
        and reg_val(f"{CFG}\\vmnet4\\DHCP", "UseDHCP") in (None, "0x0"),
        out,
    )
    d = wait_for(lambda: device(4), lambda v: v is None, 90)
    check("T44j2 type->bridged removes adapter", d is None, d)
    cli("remove --vnet 4")
    out, rc = cli("remove --vnet 0")
    check("T45 vmnet0 protected", rc != 0 or "refus" in out.lower(), out)
    check("T46 vmnet0 still alive", 0 in list_state())
    out, rc = cli("remove --vnet 8")
    check("T47 vmnet8 needs --force", rc != 0 or "force" in out.lower(), out)
    check("T48 vmnet8 still alive", 8 in list_state())

    # -- full removal -------------------------------------------------------------
    out, rc = cli("remove --vnet 2")
    check("T49 remove hostonly rc", rc == 0 and "OK" in out, out)
    d = wait_for(lambda: device(2), lambda v: v is None, 90)
    check("T50 vmnet2 device deleted", d is None, d)
    check("T51 vmnet2 registry deleted", not reg_exists(f"{CFG}\\vmnet2"))
    check("T52 vmnet2 conf purged", conf_count(DHCP_CONF, "10\\.88\\.0") == 0)
    check("T53 vmnet2 features zero", 2 not in list_state())

    out, rc = cli("remove --vnet 3")
    check("T54 remove nat rc", rc == 0 and "OK" in out, out)
    d = wait_for(lambda: device(3), lambda v: v is None, 90)
    check("T55 vmnet3 device deleted", d is None, d)
    check(
        "T56 vmnetnat.conf back to vmnet8",
        conf_count(NAT_CONF, "device = vmnet8") > 0 and conf_count(NAT_CONF, "vmnet3") == 0,
    )
    ps("sc.exe stop VMnetDHCP 2>$null; sc.exe start VMnetDHCP 2>$null")

    # -- auto vnet pick + final baseline --------------------------------------------
    out, rc = cli(
        "add hostonly --name AUTOPICK"
    )  # tests auto segment pick; NOT the autobridge command
    check("T57 auto vnet pick", rc == 0 and "vmnet2 " in out, out)
    cli("remove --vnet 2")
    st = list_state()
    check(
        "T58 final baseline vmnet0+vmnet8 only",
        set(st) == {0, 8} and "bridged" in st[0]["bits"] and {"nat", "dhcp"} <= st[8]["bits"],
        st,
    )

    out, rc = cli("add hostonly --name HO0 --vnet 0")
    check("T59 add refuses vmnet0", rc != 0 or "cannot be re-typed" in out, out)
    out, rc = cli("add hostonly --name BUSY --vnet 8")
    check("T60 add refuses in-use segment", rc != 0 or "already in use" in out, out)

    # -- GUI parity: Restore Defaults -------------------------------------------
    out, rc = cli("restore-defaults")
    check("T61 restore-defaults refuses without --force", rc != 0 or "force" in out.lower(), out)
    cli("add hostonly --name JUNK --vnet 4 --subnet 10.77.0.0")
    out, rc = cli("restore-defaults --force")
    check(
        "T62 restore-defaults wipes custom + recreates defaults",
        rc == 0 and "recreated vmnet1" in out and 4 not in list_state(),
        out,
    )
    st = list_state()
    check("T62b vmnet1+vmnet8 present after restore", 1 in st and 8 in st, st)
    check(
        "T62c stale conf blocks purged",
        conf_count(DHCP_CONF, "10\\.77\\.0") == 0 and conf_count(DHCP_CONF, "10\\.66") == 0,
    )
    cli("remove --vnet 1 --force")  # back to this box's stock-minus-vmnet1 baseline

    # -- autobridge: one bridge net per physical NIC (LAN<n> / WLAN<n>) --------
    adapters_out, _ = cli("adapters")
    pc0 = pin_count()
    out, rc = cli("autobridge --dry-run")
    check(
        "T63 autobridge dry-run plans LAN1, changes nothing",
        rc == 0 and "LAN1" in out and "[dry-run]" in out and pin_count() == pc0,
        out,
    )
    out, rc = cli("autobridge")
    st = list_state()
    lan = [n for n, v in st.items() if v.get("name") == "LAN1"]
    check(
        "T64 autobridge pins NIC as LAN1 bridged",
        rc == 0 and len(lan) == 1 and "bridged" in st[lan[0]]["bits"] and pin_count() == pc0 + 1,
        out,
    )
    check(
        "T64b pinned guid is the physical NIC",
        bool(lan) and all(g in adapters_out for g in pins_for(lan[0])),
        pins_for(lan[0]) if lan else None,
    )
    out, rc = cli("autobridge")
    check("T65 autobridge idempotent", "already bridges" in out and pin_count() == pc0 + 1, out)
    for n in lan:
        cli(f"unpin --vnet {n}")
        cli(f"remove --vnet {n}")
    check(
        "T66 autobridge cleanup, baseline restored",
        set(list_state()) == {0, 8} and pin_count() == pc0,
    )

    # -- clear / flush: remove EVERY network (vmnet0 stays) --------------------
    cli("add hostonly --name CLR --vnet 2 --subnet 10.88.0.0")
    cli("add nat --name CLR2 --vnet 3 --subnet 10.89.0.0")
    out, rc = cli("clear")
    check("T67 clear refuses without --force", rc != 0 or "force" in out.lower(), out)
    out, rc = cli("flush --force")
    st = list_state()
    check(
        "T68 flush --force removes everything incl. stock, vmnet0 stays",
        rc == 0 and set(st) == {0},
        out + str(st),
    )
    check("T68b no pins left after clear", pin_count() == pc0, pins_for(2))
    cli("restore-defaults --force")
    cli("remove --vnet 1 --force")
    st = list_state()
    check(
        "T69 baseline restored after clear test",
        set(st) == {0, 8} and {"nat", "dhcp"} <= st[8]["bits"],
        st,
    )

    fails = [n for n, ok in RESULTS if not ok]
    print(
        f"\n{len(RESULTS) - len(fails)}/{len(RESULTS)} passed"
        + (": " + ", ".join(fails) if fails else " — ALL GREEN")
    )
    return len(fails)


if __name__ == "__main__":
    try:
        code = main()
    finally:
        print("cleanup pass…", flush=True)
        cleanup()
    sys.exit(code)
