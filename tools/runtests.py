#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""runtests.py - supervised harness for the remote e2e suite / fuzzing.

Never blocks the caller: launches the target as a child process, polls
locally AND monitors the VM's process tree over WinRM, detects stalls, and
tears down stragglers on the box (a looping vmnet-cli starves vnetlib's
internal lock — RECON invariant 4 — so abort must kill remotely too).

Usage (env: VMNET_TEST_BOX/_USER/_PW required):
    python tools/runtests.py suite [exe|py]     # tests/test_vmnet_cli.py
    python tools/runtests.py fuzz [exe|py]      # tools/fuzz.py

Exit codes: 0 done+passed | 1 finished w/ failures | 3 aborted (stall/timeout)

Status for pollers: /tmp/opencode/runtests/status.json
"""

import json
import os
import subprocess
import sys
import threading
import time

import winrm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# /tmp/opencode is the approved scratch root on the operator's workstation;
# this file is dev harness tooling, not shipped package code.
STATE = "/tmp/opencode/runtests"  # nosec B108
os.makedirs(STATE, exist_ok=True)
STATUS = os.path.join(STATE, "status.json")

BOX = os.environ.get("VMNET_TEST_BOX")
USER = os.environ.get("VMNET_TEST_USER")
PW = os.environ.get("VMNET_TEST_PW")
if not (BOX and USER and PW):
    sys.exit("set VMNET_TEST_BOX / VMNET_TEST_USER / VMNET_TEST_PW")

RUN_TIMEOUT = int(os.environ.get("RUNTESTS_TIMEOUT", "2400"))  # hard cap
STALL_LIMIT = int(os.environ.get("RUNTESTS_STALL", "300"))  # no log growth
PS = r"$ProgressPreference='silentlycontinue'; Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'vmnet-cli|python|drvInst|pnputil' } | Select-Object ProcessId,Name,KernelModeTime,UserModeTime,CommandLine | ConvertTo-Json -Compress"


def write_status(d):
    tmp = STATUS + ".tmp"
    json.dump(d, open(tmp, "w"), indent=1)
    os.replace(tmp, STATUS)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "suite"
    tool = sys.argv[2] if len(sys.argv) > 2 else "exe"
    assert mode in ("suite", "fuzz")
    script = os.path.join(ROOT, "tests/test_vmnet_cli.py" if mode == "suite" else "tools/fuzz.py")
    log = os.path.join(STATE, f"{mode}-{tool}.log")

    # PYTHONUNBUFFERED: a block-buffered child never grows the log file
    # (8KB chunks) and would trigger a false stall abort (proven: fuzz run)
    env = dict(os.environ, VMNET_TOOL=tool, PYTHONUNBUFFERED="1")
    child = subprocess.Popen(
        [sys.executable, script] + ([tool] if mode == "fuzz" else []),
        cwd=ROOT,
        env=env,
        stdout=open(log, "wb"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    t0 = time.time()
    state = {
        "mode": mode,
        "tool": tool,
        "pid": child.pid,
        "started": t0,
        "log": log,
        "state": "running",
        "last_growth": t0,
        "exit": None,
        "remote": [],
    }
    write_status(state)

    sess = [None]

    def remote_procs():
        """WinRM snapshots in a watchdog thread: a hung run_ps must never
        stall the polling loop."""
        while state["state"] == "running":
            try:
                if sess[0] is None:
                    sess[0] = winrm.Session(
                        f"http://{BOX}:5985/wsman", auth=(USER, PW), transport="ntlm"
                    )
                    sess[0].timeout = 60
                out = sess[0].run_ps(PS).std_out.decode(errors="replace").strip()
                d = (
                    json.loads(out)
                    if out.startswith("{")
                    else json.loads(f"[{out}]")
                    if out.startswith("[")
                    else []
                )
                state["remote"] = d
                state["remote_ok"] = True
            except Exception as e:
                state["remote_ok"] = False
                state["remote_err"] = str(e)[:200]
            write_status(state)
            time.sleep(15)

    threading.Thread(target=remote_procs, daemon=True).start()

    def teardown(reason):
        state["state"] = "aborting"
        state["abort_reason"] = reason
        write_status(state)
        try:
            child.kill()
        except Exception:
            pass
        # kill stragglers ON THE BOX (vnetlib lock starvation guard). MUST be a
        # fresh session: winrm.Session is not thread-safe and the watchdog
        # thread may still hold sess[0]; sharing it once lost the kill and a
        # spinning import survived to lock the hive mount (proven live).
        try:
            for _ in range(3):
                s = winrm.Session(f"http://{BOX}:5985/wsman", auth=(USER, PW), transport="ntlm")
                s.timeout = 60
                s.run_ps(
                    "Get-Process vmnet-cli -ErrorAction SilentlyContinue | "
                    "Stop-Process -Force; 'ok'"
                )
                n = (
                    s.run_ps(
                        "Get-Process vmnet-cli -ErrorAction SilentlyContinue | "
                        "Measure-Object | Select-Object -Expand Count"
                    )
                    .std_out.decode()
                    .strip()
                )
                if n in ("", "0"):
                    # an import killed mid-flight leaves HKLM\VMnetCliImp mounted
                    # and the hive file locked — unload it too.
                    s.run_ps("reg unload HKLM\\VMnetCliImp 2>&1 | Out-Null; 'ok'")
                    break
        except Exception as e:
            state["teardown_err"] = str(e)[:200]

    while child.poll() is None:
        now = time.time()
        try:
            size = os.path.getsize(log)
            if size != state.get("log_size", -1):
                state["log_size"] = size
                state["last_growth"] = now
        except OSError:
            pass
        if now - t0 > RUN_TIMEOUT:
            teardown(f"hard timeout {RUN_TIMEOUT}s")
            break
        if now - state["last_growth"] > STALL_LIMIT:
            teardown(f"log stalled {STALL_LIMIT}s; remote={len(state['remote'])} proc(s) alive")
            break
        time.sleep(5)

    state["exit"] = child.poll()
    state["elapsed"] = round(time.time() - t0, 1)
    tail = open(log, "rb").read().decode(errors="replace")[-2000:]
    state["tail"] = tail
    if state["state"] != "aborting":
        rc = state["exit"]
        checks = tail.count("PASS") + tail.count("FAIL")
        state["state"] = "done"
        state["checks_seen"] = checks
        state["result"] = "pass" if rc == 0 else "fail"
        print(f"[runtests] finished rc={rc} elapsed={state['elapsed']}s checks~{checks}")
    else:
        state["state"] = "aborted"
        print(f"[runtests] ABORTED: {state.get('abort_reason')}")
        print(f"[runtests] remote procs at abort: {json.dumps(state['remote'])[:600]}")
    write_status(state)
    sys.exit(0 if state.get("result") == "pass" else (3 if state["state"] == "aborted" else 1))


if __name__ == "__main__":
    main()
