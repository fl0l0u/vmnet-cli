#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deploy the refactored project to the Windows test box and compile there:
  src/*.c            -> C:\\ludus\\src\\        (built with portable MinGW-w64
                                                   at C:\\Temp\\mingw64 to
                                                   C:\\ludus\\vmnet-cli.exe)
  vmnet_cli/*.py     -> C:\\ludus\\vmnet_cli\\
  tools/vmnet-cli.py -> C:\\ludus\\vmnet-cli.py   (launcher, entry point used
                                                   by the test suite)
"""

import glob
import os
import re
import sys

import winrm
from impacket.smbconnection import SMBConnection

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOX = os.environ.get("VMNET_TEST_BOX")
USER = os.environ.get("VMNET_TEST_USER")
PW = os.environ.get("VMNET_TEST_PW")
if not (BOX and USER and PW):
    sys.exit(
        "set VMNET_TEST_BOX / VMNET_TEST_USER / VMNET_TEST_PW "
        "to your Windows test box before running"
    )

s = winrm.Session(f"http://{BOX}:5985/wsman", auth=(USER, PW), transport="ntlm")
for d in ("C:\\ludus\\src", "C:\\ludus\\vmnet_cli"):
    s.run_ps(f"New-Item -ItemType Directory -Force {d} | Out-Null; $LASTEXITCODE")
c = SMBConnection(BOX, BOX)
c.login(USER, PW)


def put(local, remote_dir, name=None):
    try:
        c.mkdir("C$", remote_dir)
    except Exception:
        pass  # exists
    with open(local, "rb") as f:
        c.putFile("C$", f"{remote_dir}\\{name or os.path.basename(local)}", lambda n: f.read(n))


for f in sorted(glob.glob(os.path.join(ROOT, "src", "*"))):
    put(f, "ludus\\src")
    print("uploaded", f)
for f in sorted(glob.glob(os.path.join(ROOT, "vmnet_cli", "*.py"))):
    put(f, "ludus\\vmnet_cli")
    print("uploaded", f)
put(os.path.join(ROOT, "tools", "vmnet-cli.py"), "ludus", "vmnet-cli.py")
print("uploaded launcher")
c.close()

GCC = r"C:\Temp\mingw64\bin\gcc.exe"
cmd = (
    f'cmd /c "{GCC} -O2 -s -Wall -IC:\\ludus\\src '
    f"-o C:\\ludus\\vmnet-cli.exe C:\\ludus\\src\\*.c C:\\ludus\\src\\version.rc "
    '-ladvapi32 -liphlpapi -lsetupapi 2>&1"; '
    "'exit=' + $LASTEXITCODE"
)
r = s.run_ps(cmd)
out = re.sub(rb"<Objs.*?</Objs>", b"", r.std_out, flags=re.S).decode(errors="replace")
print(out.strip()[-4000:])
sys.exit(0 if "exit=0" in out else 1)
