#!/usr/bin/env python3
"""Extract ASCII + UTF-16LE strings from PE files, filter for config/IPC patterns."""
import re, sys, os

BASE = os.environ.get("VMWARE_DIR")   # local VMware Workstation install dir
if not BASE: sys.exit("set VMWARE_DIR to your local 'VMware Workstation' install dir")

def ascii_strings(data, minlen=5):
    return re.findall(rb'[\x20-\x7e]{%d,}' % minlen, data)

def utf16_strings(data, minlen=5):
    return [m.group().decode('utf-16-le', errors='ignore')
            for m in re.finditer(rb'(?:[\x20-\x7e]\x00){%d,}' % minlen, data)]

PATTERN = re.compile(
    r'(pipe|vmnet|software\\\\|HKLM|\.conf|\.ini|dhcp|nat\b|^nat|bridge|service|'
    r'\\\\\.\\\\|Global\\\\|config\.ini|ProgramData|vnetlib|VNetLib|\.sys|\.inf|'
    r'registry|Registry|backup|database|Database|subnet|Subnet)', re.I)

for fname in sys.argv[1:]:
    path = os.path.join(BASE, fname)
    data = open(path, 'rb').read()
    found = set()
    for s in ascii_strings(data):
        s = s.decode('latin1')
        if PATTERN.search(s):
            found.add(s)
    for s in utf16_strings(data):
        if PATTERN.search(s):
            found.add(s)
    print(f"=== {fname}: {len(found)} matching strings ===")
    for s in sorted(found):
        print(s)
    print()
