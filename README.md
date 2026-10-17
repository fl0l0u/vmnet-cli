<h1 align="center">
  <br>
  vmnet-cli
  <br>
</h1>

<h4 align="center">Command-line VMware Workstation Virtual Network Editor — full vmnetcfg.exe parity over the reverse-engineered vnetlib.dll API</h4>

<p align="center">
  <a href="https://github.com/fl0l0u/vmnet-cli/releases/latest">
    <img src="https://img.shields.io/github/v/release/fl0l0u/vmnet-cli?style=flat-square&label=release&color=green&cacheSeconds=3600" alt="Release">
  </a>
  <a href="https://pypi.org/project/vmnet-cli/">
    <img src="https://img.shields.io/pypi/v/vmnet-cli?style=flat-square&color=blue&cacheSeconds=3600" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/vmnet-cli/">
    <img src="https://img.shields.io/pypi/pyversions/vmnet-cli?style=flat-square&cacheSeconds=3600" alt="Python Version">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/platform-Windows-lightgrey?style=flat-square" alt="Platform">
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#development">Development</a> •
  <a href="#license">License</a>
</p>

---

**vmnet-cli** is an **unofficial**, dependency-free CLI clone of VMware
Workstation's **Virtual Network Editor** (`vmnetcfg.exe`), built directly on
the reverse-engineered `vnetlib.dll` `VNL_*` API. Manage hostonly, NAT and
bridged networks, port forwards, DHCP and the virtual adapters — from a
terminal, elevated, without opening the GUI.

## Features

| Feature | Description |
|---------|-------------|
| **Full vmnetcfg.exe parity** | Every Virtual Network Editor operation: add/edit/remove networks, bridging, NAT port forwards, DHCP, IP pools |
| **Two identical implementations** | Native C x64 `.exe` (MinGW-w64, single small binary, no runtime deps) and Python 3 (pure `ctypes`) |
| **Zero dependencies** | No pip packages, no runtime DLLs — the tool only loads `vnetlib.dll` from your own Workstation install |
| **Phased batch engine** | Multi-network operations mirror the GUI's Apply machinery exactly: all config changes first, then ONE adapter PnP settle, ONE conf regen, ONE service restart, ONE bridge cycle |
| **Config backup/restore** | `export` / `import` of the `VMnetConfig` registry hive |
| **Automation-ready** | `autobridge` with `--dry-run`, idempotent commands, exit codes, scriptable batch mode |

### Command coverage

| Command | Description |
|---------|-------------|
| `adapters` | List physical interfaces (VMware adapters filtered out) |
| `list` | List vmnet segments + features |
| `add hostonly\|nat\|bridged` | Create a network, optionally pinned to a physical adapter |
| `edit --vnet N` | Change type, name, subnet, mask, DHCP, NAT, leases, IP pools |
| `bridged` / `unpin` | Pin a bridge to a physical adapter / drop the binding, keep the network |
| `set-ip --vnet N` | Set the host adapter IP |
| `natfw list\|add\|remove` | Manage NAT port forwards |
| `natcfg show\|set` | Gateway, DNS, timeouts, IPv6, and other NAT/DHCP parameters |
| `remove --vnet N` | Delete a network entirely (phased batch, `--force` for vmnet1/8) |
| `clear` / `flush` | Remove EVERY network (`--force`; vmnet0 stays) |
| `restore-defaults` | Wipe custom nets, recreate vmnet1 + vmnet8 |
| `autobridge` | Bridge each physical NIC: Ethernet→LAN\<n\>, Wi-Fi→WLAN\<n\> (`--dry-run`) |
| `export` / `import` | Save / restore the config registry hive |

---

## Installation

> Runs **elevated as an Administrator** on the Windows host where VMware
> Workstation is installed — same requirement as `vmnetcfg.exe` itself.
> SYSTEM is **not** needed; the Network Configuration Operators group is
> **not** sufficient (no service start/stop rights, no `HKLM` writes).
> On other platforms it exits with a clear error.

### From PyPI

```bash
pipx install vmnet-cli
# or
pip install vmnet-cli
```

### From GitHub Releases (no Python needed)

Grab `vmnet-cli-windows-x64.exe` from the [latest
release](https://github.com/fl0l0u/vmnet-cli/releases/latest) — a single self-contained native binary compiled from
`src/` with MinGW-w64.

### From Source

```bash
git clone https://github.com/fl0l0u/vmnet-cli.git
cd vmnet-cli
pip install -e .
```

### Verify Installation

```bash
vmnet-cli --help
vmnet-cli list
```

---

## Quick Start

```bash
# Inspect the current setup
vmnet-cli list
vmnet-cli adapters

# Create a host-only network on VMnet2
vmnet-cli add hostonly --name LAN2 --subnet 192.168.90.0 --mask 255.255.255.0 --vnet 2

# Create a NAT network with a port forward
vmnet-cli add nat --name NAT2 --vnet 3
vmnet-cli natfw add --vnet 3 --proto tcp --hport 2222 --vm-ip 192.168.150.5 --vm-port 22 --desc ssh

# Bridge every physical NIC (preview first)
vmnet-cli autobridge --dry-run
vmnet-cli autobridge

# Backup before experimenting, restore if it goes sideways
vmnet-cli export --file backup.xml
vmnet-cli restore-defaults --force
vmnet-cli import --file backup.xml
```

---

## Usage

### Command overview

```
adapters | list | add hostonly|nat|bridged | edit | bridged | unpin
set-ip | natfw list|add|remove | natcfg show|set | export | import
remove [--vnet N]...  |  clear|flush --force  |  restore-defaults --force
autobridge [--dry-run]
```

Multi-network operations (`remove` with repeated `--vnet`, `clear`,
`restore-defaults`) run in **phases** exactly like the GUI's Apply machinery:
all config changes first, then ONE adapter PnP settle wait, ONE conf regen,
ONE service restart, ONE bridge cycle.

---

## Architecture

### C layout (`src/`)

| File | Responsibility |
|------|----------------|
| `vmnet.h` | shared types, constants, all prototypes; states the two ABI invariants |
| `util.c` | `die`, string/subprocess glue, privileges, shared constants |
| `vnl.c` | `vnetlib.dll` loading + the VNL calling layer (`vlstr` lives here) |
| `registry.c` | `VMnetConfig` database + `VMnetBridge` adapter-pin table |
| `services.c` | VMnetDHCP / VMnetNAT / VMnetBridge control via the SCM |
| `adapters.c` | virtual-NIC enumeration, physical classification, PnP install/remove |
| `batch.c` | the stage/apply batch context (`remove_stage`, `batch_apply`) |
| `args.c` | argv accessors (`opt_str`, `opt_flag`, `parse_vnet`) |
| `cmds_topo.c` | adapters, list, add, edit, bridged, unpin, autobridge |
| `cmds_cfg.c` | set-ip, export, import, natfw, natcfg |
| `cmds_remove.c` | remove, clear/flush, restore-defaults |
| `main.c` | command dispatch |

### Python layout (`vmnet_cli/`)

Same module boundaries: `vnl` / `registry` / `services` / `adapters` / `conf` /
`batch` / `commands` / `commands_nat` / `cli` (argparse + dispatch). Imports
flow one way:

```
cli → commands → batch → {adapters, conf, services} → {vnl} → registry
```

---

## Development

### Non-negotiable API invariants (from RECON.md)

`RECON.md` is the authoritative record of everything learned about the API —
read it before changing anything that touches `VNL_*`.

1. **Fixed-width string args.** vnetlib zero-pads string arguments ~260 bytes
   IN PLACE. In C every VNL string arg goes through `vlstr()` (512-byte
   scratch); in Python `_c` wraps every bytes/str arg in a roomy buffer.
   Never pass a literal, stack array, or tight `.encode()` bytes to VNL_*.
2. **rc semantics.** Most calls return `1` = success. `VNL_GetVNetFeatures`
   returns `rc=0` (output untouched) when the vnet is absent; getters may not
   write their out-buffer at all — out buffers must be big and pre-zeroed.
3. **`VNL_SetNATParam` crashes.** NAT settings go to the registry;
   `VNL_UpdateNATFromConfig` renders them.
4. **Concurrency.** Never leave a looping vnetlib process running; vnetlib
   serializes on an internal lock and will starve other callers.
5. **vmnet0** is the bridge driver's auto segment: never removable, never
   re-typeable, never explicitly pinned. vmnet1/vmnet8 removal needs `--force`.
6. **Out-of-range `--vnet`** values are refused up front: vnetlib *clamps*
   oversized indices when reading another segment's features (setters do
   validate), so every `--vnet` goes through `require_vnet()` / `require_vnet`.

### Build & test

Everything is built ON the Windows test box (no cross toolchain needed for
development). Style and static checks are enforced by the `lint` CI job:
`clang-format` (config in `.clang-format`, pinned version — hand-aligned blocks
are guarded with `clang-format off` regions), `cppcheck`, and `ruff`
(`pipx run ruff format .` locally). Test scripts talk to a Windows test box; point them at yours
with the `VMNET_TEST_BOX` / `VMNET_TEST_USER` / `VMNET_TEST_PW` environment
variables (`tools/deploy.py`, `tests/test_vmnet_cli.py`, `tools/fuzz.py`).

```bash
python tools/deploy.py                                # uploads src/ + vmnet_cli/, compiles exe
VMNET_TOOL=exe .venv/bin/python tests/test_vmnet_cli.py   # 89-check e2e suite (exit = fails)
```

`tools/deploy.py` writes `C:\ludus\vmnet-cli.exe` from `C:\ludus\src\*.c` with the
portable MinGW at `C:\Temp\mingw64`, and stages the Python package at
`C:\ludus\vmnet_cli\` behind launcher `C:\ludus\vmnet-cli.py`.

Releases are built by [`.github/workflows/release.yml`](.github/workflows/release.yml):
pushing a `v*` tag publishes the wheel + sdist and the cross-compiled
`vmnet-cli-windows-x64.exe` as a GitHub release (and to PyPI via trusted
publishing).

### Repo layout

| Path | Contents |
|------|----------|
| `src/` | native C implementation |
| `vmnet_cli/` | Python package (launcher: `tools/vmnet-cli.py`) |
| `RECON.md` | the vnetlib.dll reverse-engineering record |
| `analysis/` | static-analysis scripts used for RECON.md (run against your own local copies of vmnetcfg.exe / vnetlib.dll; the binaries and their derived dumps are proprietary and not in this repo) |
| `legacy/` | original single-file implementations, for reference |
| `deploy.py` / `test_vmnet_cli.py` / `fuzz.py` | test-box deploy + e2e suite + fuzzing |

---

## License

Licensed under the [Apache License 2.0](LICENSE) - see the [LICENSE](LICENSE)
file for details.

vmnet-cli is an independent project and contains **no VMware code or
binaries**; it drives `vnetlib.dll` from the user's own installed copy of
VMware Workstation. It is not affiliated with, sponsored by, or endorsed by
VMware or Broadcom. VMware and VMware Workstation are trademarks of their
respective owners.

---

## Credits & References

- Target application: VMware Workstation's Virtual Network Editor
  (`vmnetcfg.exe`) and its `vnetlib.dll` `VNL_*` API
- [`RECON.md`](RECON.md) — full API reverse engineering (static analysis of
  Workstation 26H1, build 25688693)
