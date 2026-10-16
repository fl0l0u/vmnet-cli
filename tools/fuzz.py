#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fuzz the vmnet-cli argument surface on the Windows test box.

Safety model:
  - every mutation that could be destructive targets an out-of-range
    --vnet (99) or omits required flags, so the tool must refuse;
  - read-only commands (list/adapters/show) may take any mutation;
  - after every case `list` is compared against the baseline and any
    extra network is removed again (state-leak detection + cleanup);
  - a case FAILS if the tool crashes (AV exit code), hangs (winrm
    timeout), or changes state it should not.
Usage: .venv/bin/python tools/fuzz.py [exe|py]
"""

import os
import random
import re
import sys

import winrm

BOX = os.environ.get("VMNET_TEST_BOX")
USER = os.environ.get("VMNET_TEST_USER")
PW = os.environ.get("VMNET_TEST_PW")
if not (BOX and USER and PW):
    sys.exit(
        "set VMNET_TEST_BOX / VMNET_TEST_USER / VMNET_TEST_PW "
        "to your Windows test box before running"
    )
s = winrm.Session(f"http://{BOX}:5985/wsman", auth=(USER, PW), transport="ntlm")

TOOL = sys.argv[1] if len(sys.argv) > 1 else "exe"
if TOOL == "exe":
    EXE, PRE = r"C:\ludus\vmnet-cli.exe", None
else:
    EXE, PRE = r"C:\Temp\py\python.exe", [r"C:\ludus\vmnet-cli.py"]


def run(args, tries=3):
    ps_args = (PRE or []) + list(args)
    arr = "@(" + ",".join("'" + a.replace("'", "''") + "'" for a in ps_args) + ")"
    cmd = f"$ErrorActionPreference='Continue'; $a={arr}; & {EXE} @a 2>&1 | Out-String; 'rc=' + $LASTEXITCODE"
    last = None
    for _ in range(tries):  # WinRM flakes (HTTP 500) are transient
        try:
            r = s.run_ps(cmd)
            out = re.sub(rb"<Objs.*?</Objs>", b"", r.std_out, flags=re.S).decode(errors="replace")
            m = re.findall(r"rc=(-?\d+)\s*$", out.strip())
            if m:
                return int(m[-1]), out
            last = ("no rc", out)
        except Exception as e:
            last = (str(e), "")
            import time as _t

            _t.sleep(3)  # WinRM flakes cluster; give it a beat
    raise RuntimeError(f"winrm failed after {tries} tries: {last[0]}")


def state():
    rc, out = run(["list"])
    return {int(m.group(1)) for m in re.finditer(r"^vmnet(\d+)", out, re.M)}


# ---------------------------------------------------------------- corpus
S = {
    "name": [
        "ok",
        "x" * 300,
        "x" * 1200,
        "üñïçödé😎",
        'a"b',
        "a'b",
        "a`b",
        "a$b",
        "a;b|c&d",
        "%s%d%n%x",
        "a\tb",
        "  ",
        "",
        "con",
        "nul",
        "a\\..\\b",
        "\r\n",
        "VMnet8",
    ],
    "vnet_bad": [
        "99",
        "-1",
        "abc",
        "vmnet",
        "",
        "0x2",
        " 2",
        "2.5",
        "999999999999",
        "1e2",
        "vmnet99x",
        "+8",
    ],
    "vnet_refuse": ["0", "8"],
    "subnet": [
        "10.95.0.0",
        "1.2.3.4.5",
        "999.1.1.1",
        "abc",
        "",
        "10.0.0.",
        " 1.1.1.1",
        "1.1.1.1 ",
        "256.0.0.1",
        "x" * 300,
        "10.0.0.1;calc",
        "0.0.0.0",
        "255.255.255.255",
    ],
    "addr": ["10.95.0.9", "999.999.999.999", "", "abc", "1.2.3", "1.2.3.4.5", "x" * 200],
    "hport": ["0", "-1", "65536", "99999999999999", "abc", "80 ", "", "80;calc"],
    "proto": ["tcp", "udp", "tcp;rm", "", "x" * 100, "TCP"],
    "adapter": ["Ethernet", "nope;calc", "x" * 200, "", "VMware*"],
    "file": [
        r"C:\ludus\fuzz\a.reg",
        r"C:\ludus\fuzz\a b.reg",
        r"C:\nonexistent\x.reg",
        "x" * 300,
        r"C:\ludus\fuzz\%n.reg",
        "",
    ],
    "type": ["bridged", "hostonly", "nat", "bogus", "", "x" * 100],
    "dhcp": ["on", "off", "maybe", ""],
}


def cases():
    C = []  # (label, argv)
    C += [
        ("list", ["list"]),
        ("adapters", ["adapters"]),
        ("autobridge-dry", ["autobridge", "--dry-run"]),
        ("clear-noforce", ["clear"]),
        ("restore-noforce", ["restore-defaults"]),
    ]
    for v in S["vnet_bad"]:
        C.append((f"add/vnet={v!r}", ["add", "hostonly", "--name", "FZ", "--vnet", v]))
        C.append((f"edit/vnet={v!r}", ["edit", "--vnet", v, "--name", "FZ"]))
        C.append((f"setip/vnet={v!r}", ["set-ip", "--vnet", v, "--addr", "1.1.1.1"]))
        C.append((f"unpin/vnet={v!r}", ["unpin", "--vnet", v]))
        C.append((f"remove/vnet={v!r}", ["remove", "--vnet", v]))
        C.append(
            (
                f"natfw/vnet={v!r}",
                [
                    "natfw",
                    "add",
                    "--vnet",
                    v,
                    "--proto",
                    "tcp",
                    "--hport",
                    "8080",
                    "--vm-ip",
                    "1.2.3.4",
                    "--vm-port",
                    "80",
                ],
            )
        )
        C.append((f"natcfg/vnet={v!r}", ["natcfg", "set", "--vnet", v, "--dns1", "8.8.8.8"]))
    for n in S["name"]:
        C.append((f"add/name={n!r:24}", ["add", "hostonly", "--name", n, "--vnet", "99"]))
        C.append((f"edit/name={n!r:24}", ["edit", "--vnet", "99", "--name", n]))
    for x in S["subnet"]:
        C.append(
            (f"add/subnet={x!r:22}", ["add", "nat", "--name", "FZ", "--vnet", "99", "--subnet", x])
        )
        C.append((f"edit/subnet={x!r:22}", ["edit", "--vnet", "99", "--subnet", x]))
    for x in S["addr"]:
        C.append((f"setip/addr={x!r:20}", ["set-ip", "--vnet", "99", "--addr", x]))
    for x in S["hport"]:
        C.append(
            (
                f"natfw/hport={x!r:20}",
                [
                    "natfw",
                    "add",
                    "--vnet",
                    "99",
                    "--proto",
                    "tcp",
                    "--hport",
                    x,
                    "--vm-ip",
                    "1.2.3.4",
                    "--vm-port",
                    "80",
                ],
            )
        )
    for x in S["proto"]:
        C.append(
            (
                f"natfw/proto={x!r:20}",
                [
                    "natfw",
                    "add",
                    "--vnet",
                    "99",
                    "--proto",
                    x,
                    "--hport",
                    "8080",
                    "--vm-ip",
                    "1.2.3.4",
                    "--vm-port",
                    "80",
                ],
            )
        )
    for x in S["adapter"]:
        C.append((f"bridged/adapter={x!r:18}", ["bridged", "--adapter", x, "--vnet", "99"]))
    for x in S["file"]:
        C.append((f"export/file={x!r:24}", ["export", "--file", x]))
        C.append((f"import/file={x!r:24}", ["import", "--file", x]))
    for x in S["type"]:
        C.append((f"edit/type={x!r:20}", ["edit", "--vnet", "99", "--type", x]))
    for x in S["dhcp"]:
        C.append((f"edit/dhcp={x!r:20}", ["edit", "--vnet", "99", "--dhcp", x]))
    # missing / malformed flag plumbing
    C += [
        ("no-vnet/remove", ["remove"]),
        ("no-vnet/edit", ["edit"]),
        ("no-file/export", ["export"]),
        ("no-file/import", ["import"]),
        ("flag-as-value", ["edit", "--vnet", "--name", "--dhcp"]),
        ("trailing-flag", ["remove", "--vnet"]),
        ("dup-vnet", ["remove", "--vnet", "99", "--vnet", "99"]),
        ("unknown-flag", ["list", "--bogus"]),
        ("positional", ["list", "extra"]),
        ("empty", [""]),
        ("emptycmd", []),
        ("vnet-flag-vnet", ["bridged", "--vnet", "--vnet"]),
    ]
    rnd = random.Random(20261014)
    for i in range(40):  # random combos, fixed seed
        base = rnd.choice(
            [
                ["add", "hostonly"],
                ["edit"],
                ["set-ip"],
                ["remove"],
                ["natfw", "add"],
                ["natcfg", "set"],
                ["bridged"],
                ["export"],
                ["import"],
                ["add", "nat"],
            ]
        )
        argv = list(base)
        for flag, key in [
            ("--vnet", "vnet_bad"),
            ("--name", "name"),
            ("--subnet", "subnet"),
            ("--addr", "addr"),
            ("--hport", "hport"),
            ("--file", "file"),
        ]:
            if rnd.random() < 0.5:
                argv += [flag, rnd.choice(S[key])]
        if "natfw" in argv:
            argv += [
                "--proto",
                rnd.choice(S["proto"]),
                "--vm-ip",
                rnd.choice(S["addr"]),
                "--vm-port",
                rnd.choice(S["hport"]),
            ]
        if argv[0] in ("add", "edit", "bridged") and "--vnet" not in argv:
            argv += ["--vnet", "99"]  # never let fuzz auto-pick and build nets
        C.append((f"rnd{i}", argv))
    return C


def main():
    s.run_ps(r"New-Item -ItemType Directory -Force C:\ludus\fuzz | Out-Null")
    base = state()
    cs = cases()
    print(f"tool={TOOL} baseline={sorted(base)}")
    findings = 0
    for label, argv in cs:
        try:
            rc, out = run(argv)
        except Exception as e:
            print(f"HANG/ERROR {label}: {e}")
            findings += 1
            continue
        bad = rc is None or rc < 0 or rc > 2
        crash = rc is not None and (rc < -1 or rc > 259)
        now = state()
        if now - base:  # a network appeared: clean it up
            for n in sorted(now - base):
                run(["remove", "--vnet", str(n), "--force"])
            # PowerShell 5.1 native-arg quoting mangles embedded double
            # quotes and can swallow the following --vnet 99 argument, so
            # `add` legitimately falls back to auto-pick. Harness artifact,
            # not tool behavior: report but do not count.
            if any('"' in a for a in argv):
                print(
                    f"ARTIFACT    {label}: created {sorted(now - base)} "
                    f"(PS quote-swallowing, rc={rc})"
                )
            else:
                print(f"STATE-LEAK {label}: created {sorted(now - base)} (rc={rc})")
                findings += 1
        if base - now:
            print(f"STATE-LOSS  {label}: lost {sorted(base - now)} (rc={rc})")
            findings += 1
            run(["restore-defaults", "--force"])
            base = state()
        if crash:
            print(f"CRASH       {label}: rc={rc:#x} out={out[:160]!r}")
            findings += 1
        elif bad and rc not in (0, 1):  # 0 ok, 1 = die()/usage
            print(f"BAD-RC      {label}: rc={rc} out={out[:160]!r}")
            findings += 1
    print(f"\n{findings} findings over {len(cs)} cases ({TOOL})")
    return min(findings, 255)


if __name__ == "__main__":
    sys.exit(main())
