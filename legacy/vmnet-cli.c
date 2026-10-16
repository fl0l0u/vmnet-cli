/*
 * vmnet-cli.c — VMware Workstation virtual network manager (full vmnetcfg.exe
 * Network Editor parity) in a single dependency-free Windows executable.
 *
 * Talks to vnetlib.dll through LoadLibrary/GetProcAddress (the GUI's own
 * contract), reads/writes the VMnetLib registry schema directly, and enumerates
 * physical NICs with iphlpapi + setupapi. No PowerShell, no reg.exe, no sc.exe,
 * no Python — only in-box Win32 APIs.
 *
 * Build (MinGW-w64):
 *   gcc -O2 -s -o vmnet-cli.exe vmnet-cli.c -ladvapi32 -liphlpapi -lsetupapi
 *
 * Usage:
 *   vmnet-cli.exe adapters                          list physical interfaces
 *   vmnet-cli.exe list                              list vmnet segments + features
 *   vmnet-cli.exe add hostonly --name X [--subnet A [--mask M]] [--vnet N] [--dhcp on|off]
 *   vmnet-cli.exe add nat     --name X [--subnet A [--mask M]] [--vnet N]
 *   vmnet-cli.exe bridged --name LAN --adapter Ethernet [--vnet N]
 *   vmnet-cli.exe edit --vnet N [--name X] [--subnet A] [--mask M] [--dhcp on|off] [--nat on|off]
 *                      [--type bridged|hostonly|nat] [--adapter on|off]
 *                      [--dhcp-begin A --dhcp-end A] [--lease S --max-lease S]
 *   vmnet-cli.exe set-ip --vnet N --addr A
 *   vmnet-cli.exe natfw list  --vnet N
 *   vmnet-cli.exe natfw add   --vnet N --proto tcp|udp --hport P --vm-ip A --vm-port P [--desc D]
 *   vmnet-cli.exe natfw remove --vnet N --proto tcp|udp --hport P
 *   vmnet-cli.exe natcfg show|set --vnet N [--gateway-ip A] [--host-ip A] [--configport P]
 *                      [--ipv6 on|off] [--active-ftp on|off] [--allow-any-oui on|off]
 *                      [--udp-timeout S] [--dns-auto on|off] [--dns1 A --dns2 A --dns3 A]
 *                      [--dns-policy order|rotate|burst] [--dns-retries N] [--dns-timeout S]
 *                      [--nbns-timeout S]
 *   vmnet-cli.exe remove --vnet N [--force]
 *   vmnet-cli.exe clear|flush --force           remove EVERY network (vmnet0 stays)
 *   vmnet-cli.exe unpin --vnet N
 *   vmnet-cli.exe autobridge [--dry-run]     Ethernet->LAN<n>, Wi-Fi->WLAN<n>
 *   vmnet-cli.exe restore-defaults --force
 *   vmnet-cli.exe export --file F
 *   vmnet-cli.exe import --file F
 */
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

static const char *VL_PATH =
    "C:\\Program Files\\VMware\\VMware Workstation\\vnetlib.dll";
static const char *VMWARE_DIR = "C:\\Program Files\\VMware\\VMware Workstation";
static const char *BRIDGE_TABLE =
    "SYSTEM\\CurrentControlSet\\Services\\VMnetBridge\\Parameters\\Adapters";
static const char *CFG = "SOFTWARE\\VMware, Inc.\\VMnetLib\\VMnetConfig";
static const char *NET_CLASS =
    "SYSTEM\\CurrentControlSet\\Control\\Class"
    "\\{4d36e972-e325-11ce-bfc1-08002be10318}";

/* ------------------------------------------------------------------ utils */
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* "ok" for rc==1, else the actual rc for diagnostics. */
static const char *rcs(int rc)
{
    static char b[16];
    if (rc == 1) return "ok";
    snprintf(b, sizeof b, "rc=%d", rc);
    return b;
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p) die("out of memory");
    return p;
}

static void upper(char *s)
{
    for (; *s; s++) if (*s >= 'a' && *s <= 'z') *s -= 32;
}

static int ci_contains(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (size_t i = 0; hay[i]; i++)
        if (_strnicmp(hay + i, needle, n) == 0) return 1;
    return 0;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}

static void w2u8(const WCHAR *w, char *out, int outlen)
{
    out[0] = 0;    /* WideCharToMultiByte writes NOTHING on failure — never
                      leave the caller's buffer unterminated */
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outlen, NULL, NULL))
        out[outlen - 1] = 0;
}

static WCHAR *u82w(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    WCHAR *w = xmalloc(((size_t)n + 64) * sizeof(WCHAR));
    memset(w, 0, ((size_t)n + 64) * sizeof(WCHAR));   /* fixed-field slack */
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static void sleep_ms(int ms) { Sleep((DWORD)ms); }

/* Run a command line synchronously (hidden window), return exit code or -1. */
static int run_hidden(const char *cmdline)
{
    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessA(NULL, (char *)cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD code = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
}

/* --------------------------------------------------------------- vnetlib */
static HMODULE g_vl;

static void vl_init(void)
{
    g_vl = LoadLibraryA(VL_PATH);
    if (!g_vl) {
        /* fall back to the registered install path */
        char dir[MAX_PATH] = "";
        DWORD sz = sizeof(dir);
        HKEY k;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\VMware, Inc.\\VMware Workstation", 0,
                KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
            RegQueryValueExA(k, "InstallPath", NULL, NULL, (BYTE *)dir, &sz);
            RegCloseKey(k);
        }
        if (dir[0]) {
            char path[MAX_PATH * 2];
            snprintf(path, sizeof(path), "%s\\vnetlib.dll", dir);
            g_vl = LoadLibraryA(path);
        }
    }
    if (!g_vl) die("cannot load vnetlib.dll (is VMware Workstation installed?)");
}

static void *vfn(const char *name)
{
    return (void *)GetProcAddress(g_vl, name);   /* NULL = not exported */
}
static void *vneed(const char *name)
{
    void *p = vfn(name);
    if (!p) die("vnetlib: missing export %s", name);
    return p;
}

/* vnetlib treats every string argument as a FIXED-WIDTH field: it reads and
   normalizes (zero-pads) ~260 bytes in place. Handing it a stack array or an
   argv pointer corrupts the caller (proven: loop counters zeroed, export
   silently failing). Python ctypes never showed this because str/bytes args
   are marshalled into fresh heap temporaries. Every VNL_* string argument
   MUST go through a large zeroed scratch buffer. */
static char VL_SCRATCH[8][512];
static int vl_si;
static char *vlstr(const char *s)
{
    char *b = VL_SCRATCH[(vl_si++) & 7];
    memset(b, 0, 512);
    if (s) strncpy(b, s, 511);
    return b;
}

typedef int (*F0)(void);
typedef int (*F1s)(const char *);
typedef int (*F1si)(const char *, int);
typedef int (*F1ss)(const char *, const char *);
typedef int (*F1sip)(const char *, int *);
typedef int (*F3s)(const char *, char *, int *);
typedef int (*F4)(const char *, int, const char *, int);
typedef int (*F5i)(const char *, void *, int, int, int *);
typedef int (*F3u)(const char *, void *, int *);
typedef int (*F7pf)(const char *, int, unsigned short, const char *,
                    unsigned short, const WCHAR *, int);

static int v0(const char *fn)
{
    F0 f = (F0)vfn(fn);
    return f ? f() : 2;   /* 2 = "not implemented here" -> callers fall back */
}
static int v1(const char *fn, const char *v)
{
    F1s f = (F1s)vfn(fn);
    if (!f) die("vnetlib: missing export %s", fn);
    return f(vlstr(v));
}
static int v1i(const char *fn, const char *v, int i)
{
    F1si f = (F1si)vfn(fn);
    if (!f) die("vnetlib: missing export %s", fn);
    return f(vlstr(v), i);
}
static int v1s(const char *fn, const char *v, const char *s)
{
    F1ss f = (F1ss)vfn(fn);
    if (!f) die("vnetlib: missing export %s", fn);
    return f(vlstr(v), s ? vlstr(s) : NULL);
}
static int vfeat(const char *v, int *f)
{
    return ((F1sip)vneed("VNL_GetVNetFeatures"))(vlstr(v), f);
}
static int vgs(const char *fn, const char *v, char *buf, int len)
{
    static char out[512];          /* vnetlib may normalize past len, like
                                      the vnet arg — use a big scratch out */
    int l = 512;
    memset(out, 0, sizeof out);    /* vnetlib may not write at all: never leak */
    int rc = ((F3s)vneed(fn))(vlstr(v), out, &l);
    buf[0] = 0;
    if (rc == 0 || rc == 1) {
        out[511] = 0;
        strncpy(buf, out, (size_t)len - 1);
        buf[len - 1] = 0;
    }
    return (int)strlen(buf);
}
static int features(const char *vnet)   /* -1 when unreadable */
{
    int f = 0;
    return vfeat(vnet, &f) == 1 ? f : -1;
}
static void get_str(const char *fn, const char *vnet, char *out, int outlen)
{
    out[0] = 0;
    if (outlen > 512) outlen = 512;
    vgs(fn, vnet, out, outlen);
}
static int set_str(const char *fn, const char *vnet, const char *val)
{
    return v1s(fn, vnet, val);
}
static int set_dhcp_param(const char *vnet, int pid, const char *val)
{
    return ((F4)vneed("VNL_SetDHCPParam"))(vlstr(vnet), pid,
                                         val ? vlstr(val) : NULL,
                                         val ? (int)strlen(val) : 0);
}

/* -------------------------------------------------------------- registry */
static LONG ropen(const char *path, ACCESS_MASK acc, HKEY *k)
{
    return RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, acc | KEY_WOW64_64KEY, k);
}

static int reg_get_dword(const char *path, const char *name, DWORD *val)
{
    HKEY k;
    if (ropen(path, KEY_READ, &k)) return 0;
    DWORD t, sz = sizeof *val;
    LONG rc = RegQueryValueExA(k, name, NULL, &t, (BYTE *)val, &sz);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS && t == REG_DWORD;
}

static int reg_get_sz(const char *path, const char *name, char *buf, DWORD bsz)
{
    HKEY k;
    buf[0] = 0;
    if (ropen(path, KEY_READ, &k)) return 0;
    DWORD t, sz = bsz;
    LONG rc = RegQueryValueExA(k, name, NULL, &t, (BYTE *)buf, &sz);
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS) return 0;
    if (t == REG_MULTI_SZ || t == REG_EXPAND_SZ) buf[bsz - 1] = 0;
    else if (t != REG_SZ) { buf[0] = 0; return 0; }
    return 1;
}

static void reg_set_dword(const char *path, const char *name, DWORD val)
{
    HKEY k;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0,
            KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &k, NULL))
        die("cannot write HKLM\\%s", path);
    RegSetValueExA(k, name, 0, REG_DWORD, (BYTE *)&val, sizeof val);
    RegCloseKey(k);
}

static void reg_set_sz(const char *path, const char *name, const char *val)
{
    HKEY k;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0,
            KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &k, NULL))
        die("cannot write HKLM\\%s", path);
    RegSetValueExA(k, name, 0, REG_SZ, (BYTE *)val, (DWORD)strlen(val) + 1);
    RegCloseKey(k);
}

static int reg_exists(const char *path)
{
    HKEY k;
    if (ropen(path, KEY_READ, &k)) return 0;
    RegCloseKey(k);
    return 1;
}

static LONG reg_delete_tree(const char *path)
{
    WCHAR *w = u82w(path);
    LONG rc = RegDeleteTreeW(HKEY_LOCAL_MACHINE, w);
    free(w);
    return rc == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : rc;  /* absent = no-op */
}

/* True if VMnetConfig\vnet\sub\Use<sub> == 1 (registry is config truth). */
static int reg_flag(const char *vnet, const char *sub)
{
    char path[512], valname[64];
    DWORD v = 0;
    snprintf(path, sizeof path, "%s\\%s\\%s", CFG, vnet, sub);
    snprintf(valname, sizeof valname, "Use%s", sub);
    return reg_get_dword(path, valname, &v) && v == 1;
}

/* bridge pins: {guid: vnet} from the driver's Adapters subkeys */
typedef struct { char guid[64]; int vnet; } Pin;
static int pins_get(Pin *out, int max)
{
    int n = 0;
    HKEY k;
    if (ropen(BRIDGE_TABLE, KEY_READ, &k)) return 0;
    for (int i = 0; n < max; i++) {
        char sub[64];
        DWORD sl = sizeof sub;
        if (RegEnumKeyExA(k, i, sub, &sl, NULL, NULL, NULL, NULL)) break;
        char path[256];
        snprintf(path, sizeof path, "%s\\%s", BRIDGE_TABLE, sub);
        DWORD v;
        if (reg_get_dword(path, "VMnet", &v)) {
            strcpy(out[n].guid, sub);
            upper(out[n].guid);
            out[n].vnet = (int)v;
            n++;
        }
    }
    RegCloseKey(k);
    return n;
}
static int pin_of(const Pin *pins, int npins, const char *guid, int *vn)
{
    for (int i = 0; i < npins; i++)
        if (strcmp(pins[i].guid, guid) == 0) { *vn = pins[i].vnet; return 1; }
    return 0;
}
static int vnet_pinned(const Pin *pins, int npins, int n)
{
    for (int i = 0; i < npins; i++) if (pins[i].vnet == n) return 1;
    return 0;
}
static void pins_set(const char *guid, int vnet)
{
    char path[256];
    snprintf(path, sizeof path, "%s\\%s", BRIDGE_TABLE, guid);
    reg_set_dword(path, "VMnet", (DWORD)vnet);
}
static void pins_del(const char *guid)
{
    char path[256];
    snprintf(path, sizeof path, "%s\\%s", BRIDGE_TABLE, guid);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, path);
}

/* --------------------------------------------------------------- services */
static void svc_wait(SC_HANDLE s, DWORD want, int seconds)
{
    SERVICE_STATUS st;
    for (int i = 0; i < seconds * 4; i++) {
        if (!QueryServiceStatus(s, &st)) return;
        if (st.dwCurrentState == want) return;
        sleep_ms(250);
    }
}

static void svc_action(const WCHAR *name, int start)
{
    SC_HANDLE m = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!m) return;
    SC_HANDLE s = OpenServiceW(m, name,
        SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (s) {
        SERVICE_STATUS st;
        if (start) {
            StartServiceW(s, 0, NULL);          /* already running = ok */
            svc_wait(s, SERVICE_RUNNING, 30);
        } else {
            ControlService(s, SERVICE_CONTROL_STOP, &st);
            svc_wait(s, SERVICE_STOPPED, 20);
        }
        CloseServiceHandle(s);
    }
    CloseServiceHandle(m);
}

static void svc_stop_start(const WCHAR *name)
{
    svc_action(name, 0);
    sleep_ms(2000);
    svc_action(name, 1);
    sleep_ms(3000);
}

/* Reload the bridge driver so it re-reads Parameters\\Adapters bindings. */
static void cycle_bridge(void) { svc_stop_start(L"VMnetBridge"); }

/* VNL_Stop/Start* like vmnetcfg.exe does; SCM fallback on failure. */
static void restart_services(int dhcp, int nat)
{
    if (dhcp) {
        int rc = v0("VNL_StopDHCP");
        if (rc != 0 && rc != 1) svc_action(L"VMnetDHCP", 0);
        sleep_ms(2000);
        rc = v0("VNL_StartDHCP");
        if (rc != 0 && rc != 1) svc_action(L"VMnetDHCP", 1);
        sleep_ms(3000);
    }
    if (nat) {
        int rc = v0("VNL_StopNAT");
        if (rc != 0 && rc != 1) svc_action(L"VMware NAT Service", 0);
        sleep_ms(2000);
        rc = v0("VNL_StartNAT");
        if (rc != 0 && rc != 1) svc_action(L"VMware NAT Service", 1);
        sleep_ms(3000);
    }
}

/* ------------------------------------------------------ adapter inventory */
typedef struct {
    char guid[64];      /* connection GUID, uppercased (= bridge pin key) */
    char name[160];     /* FriendlyName */
    char desc[192];     /* InterfaceDescription */
    int  ifindex;
    int  iftype;
} Nic;

static int nic_list(Nic *out, int max)
{
    ULONG len = 65536;
    IP_ADAPTER_ADDRESSES *aa = xmalloc(len), *p;
    ULONG rc;
    while ((rc = GetAdaptersAddresses(AF_UNSPEC,
               GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
               GAA_FLAG_SKIP_DNS_SERVER, NULL, aa, &len)) == ERROR_BUFFER_OVERFLOW) {
        free(aa);
        aa = xmalloc(len);
    }
    int n = 0;
    if (rc == ERROR_SUCCESS) {
        for (p = aa; p && n < max; p = p->Next) {
            if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            strcpy(out[n].guid, p->AdapterName);
            upper(out[n].guid);
            w2u8(p->FriendlyName, out[n].name, sizeof out[n].name);
            w2u8(p->Description, out[n].desc, sizeof out[n].desc);
            out[n].ifindex = (int)p->IfIndex;
            out[n].iftype = (int)p->IfType;
            n++;
        }
    }
    free(aa);
    /* sort by ifIndex (matches the Python tool's ordering) */
    for (int i = 1; i < n; i++)
        for (int j = i; j > 0 && out[j].ifindex < out[j - 1].ifindex; j--) {
            Nic t = out[j];
            out[j] = out[j - 1];
            out[j - 1] = t;
        }
    return n;
}

static int nic_present_vmnet(int n)
{
    Nic nics[64];
    char suffix[24];
    snprintf(suffix, sizeof suffix, "VMnet%d", n);
    int c = nic_list(nics, 64);
    for (int i = 0; i < c; i++)
        if (ends_with(nics[i].desc, suffix)) return 1;
    return 0;
}

/* *PhysicalMediaType from the adapter's Class Net key (71 = IEEE 802.11). */
static int pmt_for_guid(const char *guid)
{
    HKEY k;
    if (ropen(NET_CLASS, KEY_READ, &k)) return 0;
    int pmt = 0;
    for (int i = 0; i < 64; i++) {
        char sub[12];
        DWORD sl = sizeof sub;
        if (RegEnumKeyExA(k, i, sub, &sl, NULL, NULL, NULL, NULL)) break;
        char path[512];
        snprintf(path, sizeof path, "%s\\%s", NET_CLASS, sub);
        char id[64];
        if (reg_get_sz(path, "NetCfgInstanceId", id, sizeof id)) {
            upper(id);
            if (strcmp(id, guid) == 0) {
                DWORD v;
                if (reg_get_dword(path, "*PhysicalMediaType", &v)) pmt = (int)v;
                break;
            }
        }
    }
    RegCloseKey(k);
    return pmt;
}

/* PnP bus prefix (PCI/USB/…) of the device whose description matches desc.
   Software drivers (TAP, WireGuard, ZeroTier, VMware VMnet) are ROOT\ or SWD\
   enumerated — whatever medium their driver claims. */
static void bus_of_desc(const char *desc, char *bus, int buslen)
{
    static const GUID classNet = { 0x4d36e972, 0xe325, 0x11ce,
        { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };
    bus[0] = 0;
    HDEVINFO set = SetupDiGetClassDevsA(&classNet, NULL, NULL, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return;
    SP_DEVINFO_DATA di = { .cbSize = sizeof di };
    for (int i = 0; SetupDiEnumDeviceInfo(set, i, &di); i++) {
        char d[256];
        if (!SetupDiGetDeviceRegistryPropertyA(set, &di, SPDRP_DEVICEDESC, NULL,
                (BYTE *)d, sizeof d, NULL))
            continue;
        if (_stricmp(d, desc) != 0) continue;
        WCHAR id[320];
        if (SetupDiGetDeviceInstanceIdW(set, &di, id, 320, NULL)) {
            w2u8(id, d, sizeof d);
            char *bs = strchr(d, '\\');
            if (bs) {
                size_t l = (size_t)(bs - d);
                if (l >= (size_t)buslen) l = (size_t)buslen - 1;
                memcpy(bus, d, l);
                bus[l] = 0;
                upper(bus);
            }
        }
        break;
    }
    SetupDiDestroyDeviceInfoList(set);
}

static const char *PHYS_BUSES[] = { "PCI", "VPCI", "USB", "PCMCIA", "SDIO",
    "SDCC", "SD", "IEEE1394", "MDIO", "ACPI" };

/* Physical NICs only (Ethernet/Wi-Fi), in ifIndex order. */
static int classify_nics(Nic *out, int max)
{
    Nic all[64];
    int n = nic_list(all, 64), c = 0;
    for (int i = 0; i < n && c < max; i++) {
        if (ci_contains(all[i].desc, "VMware")) continue;
        char bus[64];
        bus_of_desc(all[i].desc, bus, sizeof bus);
        if (!bus[0]) continue;
        int ok = 0;
        for (size_t b = 0; b < sizeof PHYS_BUSES / sizeof *PHYS_BUSES; b++)
            if (strncmp(bus, PHYS_BUSES[b], strlen(PHYS_BUSES[b])) == 0)
                ok = 1;
        if (!ok) continue;
        switch (all[i].iftype) {
        case 24: case 131: case 135: case 136: case 148:
        case 154: case 166: case 181: case 209:
            continue;                 /* ppp / tunnels — not LAN/WLAN */
        default: break;
        }
        out[c++] = all[i];
    }
    return c;
}

/* ------------------------------------------------------- high-level ops */
static int vnet_count(void) { return v0("VNL_GetNumberOfVnets"); }

static void vnetstr(int n, char *out) { snprintf(out, 64, "vmnet%d", n); }

static int vnet_in_use(int n)
{
    char v[64];
    vnetstr(n, v);
    int f = features(v);
    if (f < 0) f = 0;
    char path[256];
    snprintf(path, sizeof path, "%s\\%s", CFG, v);
    /* config key is ground truth too: features can transiently read 0 */
    return f != 0 || reg_exists(path) || n == 0 || n == 1 || n == 8;
}

static void regen_nat_conf(void)
{
    char v[64];
    for (int n = 2; n < vnet_count(); n++) {
        vnetstr(n, v);
        if (reg_flag(v, "NAT") || (features(v) > 0 && (features(v) & 0x10000)))
            v1("VNL_UpdateNATFromConfig", v);
    }
}

static void ensure_nat(const char *vnet, int on)
{
    v1i("VNL_SetVnetUseNAT", vnet, on ? 1 : 0);
    if (on && !reg_flag(vnet, "NAT")) {
        /* VNL_SetVnetUseNAT does not create the NAT subkey for a fresh vnet */
        char path[256];
        snprintf(path, sizeof path, "%s\\%s\\NAT", CFG, vnet);
        reg_set_dword(path, "UseNAT", 1);
    }
}

static void drvinst_install(int n)
{
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
        "\"%s\\drvInst64.exe\" installRootDriver 0 *VMnetAdapter%d"
        " \"%s\\netadapter.inf\" 1", VMWARE_DIR, n, VMWARE_DIR);
    run_hidden(cmd);
}

static void install_adapter_start(const char *vnet)
{
    /* 5-arg signature (vnet, hwnd, flags, p4, int* p5): every trailing arg
       MUST be explicit — p5 is dereferenced unless NULL (stale-register AV). */
    ((F5i)vneed("VNL_InstallNetworkAdapter"))(vlstr(vnet), NULL, 0, 0, NULL);
}

static int install_adapter_finish(const char *vnet, int n)
{
    (void)vnet;   /* presence is detected via the VMnetN device description */
    for (int i = 0; i < 10; i++) {   /* PnP completes asynchronously */
        sleep_ms(3000);
        if (nic_present_vmnet(n)) return 1;
    }
    drvinst_install(n);
    for (int i = 0; i < 4; i++) {
        sleep_ms(3000);
        if (nic_present_vmnet(n)) return 1;
    }
    return 0;
}

static int install_adapter(const char *vnet, int n)
{
    install_adapter_start(vnet);
    return install_adapter_finish(vnet, n);
}

static void pnputil_remove_vmnet(int n)
{
    static const GUID classNet = { 0x4d36e972, 0xe325, 0x11ce,
        { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };
    HDEVINFO set = SetupDiGetClassDevsA(&classNet, NULL, NULL, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return;
    SP_DEVINFO_DATA di = { .cbSize = sizeof di };
    char suffix[24];
    snprintf(suffix, sizeof suffix, "VMnet%d", n);
    for (int i = 0; SetupDiEnumDeviceInfo(set, i, &di); i++) {
        char d[256];
        if (!SetupDiGetDeviceRegistryPropertyA(set, &di, SPDRP_DEVICEDESC,
                NULL, (BYTE *)d, sizeof d, NULL))
            continue;
        if (!ends_with(d, suffix)) continue;
        WCHAR id[320];
        if (SetupDiGetDeviceInstanceIdW(set, &di, id, 320, NULL)) {
            char iid[640];
            w2u8(id, iid, sizeof iid);
            char cmd[900];
            snprintf(cmd, sizeof cmd, "pnputil.exe /remove-device \"%s\"", iid);
            run_hidden(cmd);
        }
        break;
    }
    SetupDiDestroyDeviceInfoList(set);
}

static void uninstall_adapter_start(const char *vnet, int n)
{
    (void)n;
    /* 3-arg signature (vnet, hwnd, int* nR) — nR dereferenced unless passed. */
    int zero = 0;
    F3u un = (F3u)vfn("VNL_UninstallNetworkAdapter");
    if (un) un(vlstr(vnet), NULL, &zero);   /* missing: pnputil fallback covers it */
    char path[256];
    snprintf(path, sizeof path, "%s\\%s\\Adapter", CFG, vnet);
    reg_set_dword(path, "UseAdapter", 0);
}

static int uninstall_adapter_finish(int n)   /* 1 = device gone */
{
    sleep_ms(3000);
    if (nic_present_vmnet(n)) {
        pnputil_remove_vmnet(n);
        sleep_ms(3000);
    }
    return !nic_present_vmnet(n);
}

static void uninstall_adapter(const char *vnet, int n)
{
    uninstall_adapter_start(vnet, n);
    uninstall_adapter_finish(n);
}

/* ---------------- batch context: one wait/restart per command ------------- */
typedef struct {
    int dhcp, nat, bridge;
    int gone[24], ngone;      /* adapter removals kicked */
    int added[24], nadded;    /* adapter installs kicked */
    int vnets[24], nvn;       /* vnets to report features for at the end */
} Batch;

static void batch_new(Batch *b) { memset(b, 0, sizeof *b); }

static int set_has(const int *s, int c, int n)
{
    for (int i = 0; i < c; i++) if (s[i] == n) return 1;
    return 0;
}

/* vmnet segments that currently have an adapter device (one enumeration) */
static int nic_present_set(int *out, int max)
{
    Nic nics[64];
    int n = nic_list(nics, 64), c = 0;
    for (int i = 0; i < n && c < max; i++) {
        char *p = strstr(nics[i].desc, "VMnet");
        if (!p || !p[5]) continue;
        char *e;
        long v = strtol(p + 5, &e, 10);
        if (e != p + 5 && *e == 0 && v >= 0 && v < 1000) out[c++] = (int)v;
    }
    return c;
}

/* ------------------------------------------------------------ arg parsing */
static void subnet_host1(const char *subnet, char *out, int outlen)
{
    snprintf(out, (size_t)outlen, "%s", subnet);
    char *dot = strrchr(out, '.');
    if (dot) snprintf(dot + 1, (size_t)(out + outlen - dot - 1), "1");
    else snprintf(out, (size_t)outlen, "0.0.0.1");
}

static int g_argc;
static char **g_argv;

static const char *opt_str(const char *flag)
{
    for (int i = 1; i < g_argc - 1; i++)
        if (strcmp(g_argv[i], flag) == 0) return g_argv[i + 1];
    return NULL;
}
static int opt_flag(const char *flag)
{
    for (int i = 1; i < g_argc; i++)
        if (strcmp(g_argv[i], flag) == 0) return 1;
    return 0;
}

static int parse_vnet(const char *s)   /* accepts "2" and "vmnet2" */
{
    if (!s) die("this command needs --vnet");
    while (*s && *s != '-' && (*s < '0' || *s > '9')) {
        if ((*s < 'a' || *s > 'z') && (*s < 'A' || *s > 'Z')) break;
        s++;
    }
    if (*s < '0' || *s > '9')
        die("expected a segment number or name (e.g. 2 or vmnet2), got '%s'", s);
    return atoi(s);
}

/* --------------------------------------------------------------- commands */
static void cmd_adapters(void)
{
    Nic nics[64];
    int n = nic_list(nics, 64);
    Pin pins[64];
    int np = pins_get(pins, 64);
    /* sort by guid like the Python tool */
    for (int i = 1; i < n; i++)
        for (int j = i; j > 0 && strcmp(nics[j].guid, nics[j - 1].guid) < 0; j--) {
            Nic t = nics[j];
            nics[j] = nics[j - 1];
            nics[j - 1] = t;
        }
    for (int i = 0; i < n; i++) {
        if (ci_contains(nics[i].desc, "VMware")) continue;
        int v = -1;
        pin_of(pins, np, nics[i].guid, &v);
        char target[16];
        if (v >= 0) snprintf(target, sizeof target, "vmnet%d", v);
        else strcpy(target, "vmnet0 (auto)");
        printf("%-30s %s  -> %s\n", nics[i].name, nics[i].guid, target);
    }
}

static void bits_str(int f, char *out, int outlen)
{
    struct { int bit; const char *name; } B[] = {
        { 0x1, "bridged" }, { 0x100, "hostonly-adapter" },
        { 0x10000, "nat" }, { 0x1000000, "dhcp" } };
    out[0] = 0;
    for (int i = 0; i < 4; i++)
        if (f & B[i].bit) {
            if (out[0]) strncat(out, ", ", (size_t)outlen - strlen(out) - 1);
            strncat(out, B[i].name, (size_t)outlen - strlen(out) - 1);
        }
}

static void cmd_list(void)
{
    Pin pins[64];
    int np = pins_get(pins, 64);
    for (int n = 0; n < vnet_count(); n++) {
        char v[64];
        vnetstr(n, v);
        int f = features(v);
        if (f < 0) f = 0;
        if (!f) {
            /* VNL_GetVNetFeatures can transiently return 0 while PnP or the
               services settle; fall back to registry truth so a configured
               network never vanishes from the list mid-flight. */
            char path[256];
            snprintf(path, sizeof path, "%s\\%s", CFG, v);
            if (reg_exists(path)) {
                if (reg_flag(v, "DHCP"))   f |= 0x1000000;
                if (reg_flag(v, "NAT"))    f |= 0x10000;
                if (reg_flag(v, "Adapter")) f |= 0x100;
                if (!f) f = 1;
            }
            if (vnet_pinned(pins, np, n)) f |= 1;
        }
        if (f <= 0) continue;
        char bits[128], name[256], subnet[64];
        bits_str(f, bits, sizeof bits);
        get_str("VNL_GetVnetDisplayName", v, name, sizeof name);
        get_str("VNL_GetVnetSubnetAddr", v, subnet, sizeof subnet);
        char extra[1024] = "";
        for (int i = 0; i < np; i++)
            if (pins[i].vnet == n) {
                size_t l = strlen(extra);
                if (l + 64 < sizeof extra)   /* bounded; separator keys off
                                                "first for THIS vnet", not index */
                    snprintf(extra + l, sizeof extra - l, "%s%s",
                             l ? "," : " pinned=", pins[i].guid);
            }
        printf("vmnet%-2d %-40s name='%s' subnet=%s%s\n", n, bits, name, subnet, extra);
    }
}

static int pick_vnet(int n)
{
    if (n >= 0) return n;
    Pin pins[64];
    int np = pins_get(pins, 64);
    for (int k = 2; k < 20; k++)
        if (!vnet_pinned(pins, np, k) && !vnet_in_use(k)) return k;
    die("no free vmnet segment (2..19)");
    return -1;
}

static void cmd_add(const char *kind)
{
    int is_nat = strcmp(kind, "nat") == 0;
    const char *name = opt_str("--name");
    if (!name) name = "";
    int want = opt_str("--vnet") ? parse_vnet(opt_str("--vnet")) : -1;
    if (want == 0)
        die("vmnet0 is the built-in bridge segment; it cannot be re-typed "
            "(segment 0 lives in the VMnetBridge driver, not in config)");
    if (want > 0 && vnet_in_use(want))
        die("vmnet%d is already in use; pick another --vnet or remove it first", want);
    int n = pick_vnet(want);
    char v[64];
    vnetstr(n, v);
    const char *subnet = opt_str("--subnet");
    if (subnet) {
        set_str("VNL_SetVnetSubnetAddr", v, subnet);
        set_str("VNL_SetVnetSubnetMask", v, opt_str("--mask") ? opt_str("--mask")
                                                              : "255.255.255.0");
    } else if (v1i("VNL_AssignSubnetAddressToVnet", v, 0) != 1) {
        die("could not auto-assign a free subnet; pass --subnet");
    }
    char sub[64];
    get_str("VNL_GetVnetSubnetAddr", v, sub, sizeof sub);
    const char *dhcp_opt = opt_str("--dhcp");
    int dhcp = is_nat || !dhcp_opt || strcmp(dhcp_opt, "off") != 0;
    printf("* add %s: %s name='%s' subnet=%s dhcp=%s nat=%s\n", kind, v, name,
           sub, dhcp ? "on" : "off", is_nat ? "on" : "off");
    set_str("VNL_SetVnetDisplayName", v, name);
    ensure_nat(v, is_nat);
    v1i("VNL_SetVnetUseDHCP", v, dhcp);
    int ok = install_adapter(v, n);
    printf("  - host adapter device: %s\n",
           ok ? "ok" : "pending/failed (PnP is async)");
    char path[256];
    snprintf(path, sizeof path, "%s\\%s\\Adapter", CFG, v);
    reg_set_dword(path, "UseAdapter", 1);   /* no VNL setter exists */
    char hostip[64];
    subnet_host1(sub, hostip, sizeof hostip);
    v1s("VNL_SetVnetAdapterAddr", v, hostip);
    if (is_nat) regen_nat_conf();
    v1("VNL_UpdateDHCPFromConfig", v);
    ((F1s)vneed("VNL_UpdateAdapterFromConfig"))(NULL);
    restart_services(dhcp, is_nat);
    int need = 0x100 | (is_nat ? 0x10000 : 0) | (dhcp ? 0x1000000 : 0);
    int f = 0;
    for (int t = 0; t < 10; t++) {   /* adapter/NAT bits settle asynchronously */
        f = features(v);
        if (f >= 0 && (f & need) == need) break;
        sleep_ms(2000);
    }
    if (f < 0) f = 0;
    printf("  %s: features=0x%08x\n", (f & need) == need ? "OK" : "WARNING", f);
}

static void cmd_edit(void)
{
    int n = parse_vnet(opt_str("--vnet"));
    char v[64];
    vnetstr(n, v);
    if (n == 0 && opt_str("--type"))
        die("vmnet0 is the built-in bridge segment; it cannot be re-typed");
    if (features(v) < 0) die("%s not readable", v);
    int dhcp_changed = 0, nat_changed = 0, subnet_changed = 0;
    const char *t = opt_str("--type");
    if (t) {
        if (!strcmp(t, "nat")) {
            ensure_nat(v, 1);
            v1i("VNL_SetVnetUseDHCP", v, 1);
            dhcp_changed = nat_changed = 1;
            if (!nic_present_vmnet(n)) {
                install_adapter(v, n);
                char p[256];
                snprintf(p, sizeof p, "%s\\%s\\Adapter", CFG, v);
                reg_set_dword(p, "UseAdapter", 1);
            }
        } else if (!strcmp(t, "hostonly")) {
            ensure_nat(v, 0);
            nat_changed = 1;
            if (!nic_present_vmnet(n)) {
                install_adapter(v, n);
                char p[256];
                snprintf(p, sizeof p, "%s\\%s\\Adapter", CFG, v);
                reg_set_dword(p, "UseAdapter", 1);
            }
        } else {   /* bridged: strip NAT/DHCP/adapter; bind a NIC with `bridged` */
            ensure_nat(v, 0);
            v1i("VNL_SetVnetUseDHCP", v, 0);
            nat_changed = dhcp_changed = 1;
            if (nic_present_vmnet(n) || reg_flag(v, "Adapter"))
                uninstall_adapter(v, n);
        }
        printf("* %s connection type -> %s\n", v, t);
    }
    const char *a = opt_str("--adapter");
    if (a) {
        if (!strcmp(a, "on")) {
            install_adapter(v, n);
            char p[256];
            snprintf(p, sizeof p, "%s\\%s\\Adapter", CFG, v);
            reg_set_dword(p, "UseAdapter", 1);
            char sub[64];
            get_str("VNL_GetVnetSubnetAddr", v, sub, sizeof sub);
            if (sub[0]) {
                char ip[64];
                subnet_host1(sub, ip, sizeof ip);
                v1s("VNL_SetVnetAdapterAddr", v, ip);
            }
        } else {
            uninstall_adapter(v, n);
        }
        printf("* %s host adapter %s\n", v, a);
    }
    const char *nm = opt_str("--name");
    if (nm) {
        set_str("VNL_SetVnetDisplayName", v, nm);
        printf("* %s DisplayName='%s'\n", v, nm);
    }
    const char *sn = opt_str("--subnet"), *mk = opt_str("--mask");
    if (sn || mk) {
        if (sn) set_str("VNL_SetVnetSubnetAddr", v, sn);
        char cur[64];
        set_str("VNL_SetVnetSubnetMask", v,
                mk ? mk : (get_str("VNL_GetVnetSubnetMask", v, cur, sizeof cur), cur));
        subnet_changed = 1;
        char a1[64], a2[64];
        get_str("VNL_GetVnetSubnetAddr", v, a1, sizeof a1);
        get_str("VNL_GetVnetSubnetMask", v, a2, sizeof a2);
        printf("* %s subnet=%s/%s\n", v, a1, a2);
    }
    struct { const char *flag; int pid; const char *label; } DP[] = {
        { "--dhcp-begin", 0x3426, "begin" }, { "--dhcp-end", 0x3427, "end" },
        { "--lease", 0x342a, "default_lease" }, { "--max-lease", 0x342b, "max_lease" } };
    for (int i = 0; i < 4; i++) {
        const char *val = opt_str(DP[i].flag);
        if (!val) continue;
        int rc = set_dhcp_param(v, DP[i].pid, val);
        printf("* %s DHCP %s=%s: %s\n", v, DP[i].label, val,
               rcs(rc));
        dhcp_changed = 1;
    }
    const char *d = opt_str("--dhcp");
    if (d) {
        v1i("VNL_SetVnetUseDHCP", v, !strcmp(d, "on"));
        dhcp_changed = 1;
        printf("* %s UseDHCP=%s\n", v, d);
    }
    const char *nt = opt_str("--nat");
    if (nt) {
        ensure_nat(v, !strcmp(nt, "on"));
        nat_changed = 1;
        printf("* %s UseNAT=%s\n", v, nt);
    }
    if (subnet_changed || dhcp_changed) v1("VNL_UpdateDHCPFromConfig", v);
    if (subnet_changed || nat_changed) regen_nat_conf();
    if (subnet_changed || dhcp_changed || nat_changed)
        restart_services(subnet_changed || dhcp_changed,
                         subnet_changed || nat_changed);
    printf("  features=0x%08x\n", features(v) < 0 ? 0 : features(v));
}

static void cmd_setip(void)
{
    char v[64];
    vnetstr(parse_vnet(opt_str("--vnet")), v);
    const char *addr = opt_str("--addr");
    if (!addr) die("set-ip needs --addr");
    int rc = v1s("VNL_SetVnetAdapterAddr", v, addr);
    printf("* %s adapter IP %s: %s\n", v, addr, rcs(rc));
    v1("VNL_UpdateAdapterFromConfig", v);   /* apply to the live device */
    char cur[64];
    get_str("VNL_GetVnetAdapterAddr", v, cur, sizeof cur);
    printf("  configured adapter addr: '%s'\n", cur);
}

static void enable_privilege(const WCHAR *name)
{
    HANDLE t;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t))
        return;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(t, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(t);
}

#ifndef REG_LITE
#define REG_LITE 1
#endif

/* vnetlib's Export/ImportDatabaseToFile do nothing when called from a native
   x64 process (rc=1, no file — proven live; work only via a ctypes-style
   caller). The database file is a plain hive of VMnetConfig (byte-identical
   to `reg save`), so use the registry APIs directly: same regf format. */
static void cmd_export(void)
{
    const char *f = opt_str("--file");
    if (!f) die("export needs --file");
    enable_privilege(L"SeBackupPrivilege");
    HKEY k;
    if (ropen(CFG, KEY_READ, &k)) die("cannot open HKLM\\%s", CFG);
    WCHAR *w = u82w(f);
    DeleteFileW(w);   /* RegSaveKeyEx refuses existing files */
    LONG rc = RegSaveKeyExW(k, w, NULL, REG_LITE);
    free(w);
    RegCloseKey(k);
    printf("export -> %s: %s\n", f,
           rc == ERROR_SUCCESS ? "ok" : "rc=fail");
    if (rc != ERROR_SUCCESS) fprintf(stderr, "export rc=%ld\n", rc);
}

static void copy_tree(HKEY src, HKEY dst)
{
    for (int j = 0; ; j++) {           /* values at this level */
        WCHAR nm[256];
        DWORD nl = sizeof nm / 2, t, vs = 0;
        if (RegEnumValueW(src, j, nm, &nl, NULL, &t, NULL, &vs)) break;
        BYTE *buf = xmalloc(vs ? vs : 1);
        if (!RegQueryValueExW(src, nm, NULL, &t, buf, &vs))
            RegSetValueExW(dst, nm, 0, t, buf, vs);
        free(buf);
    }
    for (int i = 0; ; i++) {           /* subkeys */
        WCHAR sub[256];
        DWORD sl = sizeof sub / 2;
        if (RegEnumKeyExW(src, i, sub, &sl, NULL, NULL, NULL, NULL)) break;
        HKEY s, d;
        if (RegOpenKeyExW(src, sub, 0, KEY_READ, &s)) continue;
        if (RegCreateKeyExW(dst, sub, 0, NULL, 0, KEY_WRITE, NULL, &d, NULL)) {
            RegCloseKey(s);
            continue;
        }
        copy_tree(s, d);
        RegCloseKey(d);
        RegCloseKey(s);
    }
}

static void cmd_import(void)
{
    const char *f = opt_str("--file");
    if (!f) die("import needs --file");
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");
    WCHAR *w = u82w(f);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp");   /* stale mount */
    LONG rc = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp", w);
    free(w);
    if (rc != ERROR_SUCCESS) {
        printf("import <- %s: rc=fail\n", f);
        fprintf(stderr, "import rc=%ld\n", rc);
        return;
    }
    HKEY src, dst;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"VMnetCliImp", 0, KEY_READ, &src)) {
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp");
        die("import: cannot open loaded hive");
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, CFG, 0, NULL, 0,
            KEY_WRITE | KEY_WOW64_64KEY, NULL, &dst, NULL)) {
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp");
        die("import: cannot open HKLM\\%s", CFG);
    }
    RegDeleteTreeW(dst, NULL);       /* import replaces the database */
    copy_tree(src, dst);
    RegCloseKey(dst);
    RegCloseKey(src);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp");
    printf("import <- %s: ok\n", f);
    v1("VNL_UpdateDHCPFromConfig", "vmnet1");
    regen_nat_conf();
    restart_services(1, 1);
}

static void cmd_bridged(void)
{
    const char *name = opt_str("--name");
    const char *adapter = opt_str("--adapter");
    if (!name || !adapter) die("bridged needs --name and --adapter");
    Nic nics[64];
    int n = nic_list(nics, 64);
    char guid[64] = "";
    char names[64][160];
    int nn = 0;
    for (int i = 0; i < n; i++) {
        if (ci_contains(nics[i].desc, "VMware")) continue;
        if (nn < 64) strcpy(names[nn++], nics[i].name);
        if (!strcmp(nics[i].name, adapter)) strcpy(guid, nics[i].guid);
    }
    if (!guid[0]) {
        for (int i = 1; i < nn; i++)           /* sorted listing */
            for (int j = i; j > 0 && strcmp(names[j], names[j - 1]) < 0; j--) {
                char t[160];
                strcpy(t, names[j]);
                strcpy(names[j], names[j - 1]);
                strcpy(names[j - 1], t);
            }
        char avail[8192] = "";
        for (int i = 0; i < nn; i++) {
            size_t l = strlen(avail);
            if (l + 160 >= sizeof avail) { strncat(avail, ", ...", sizeof avail - l - 1); break; }
            strncat(avail, i ? ", " : "", sizeof avail - l - 1);
            strncat(avail, names[i], sizeof avail - strlen(avail) - 1);
        }
        die("ERROR: no network interface named '%s' on this host. Available: %s",
            adapter, avail);
    }
    int want = opt_str("--vnet") ? parse_vnet(opt_str("--vnet")) : -1;
    int seg;
    if (want >= 0) {
        seg = want;
    } else {
        Pin pins[64];
        int np = pins_get(pins, 64);
        for (seg = 2; seg < 20; seg++)
            if (!vnet_pinned(pins, np, seg) && !vnet_in_use(seg)) break;
        if (seg == 20) die("no free vmnet segment (2..19)");
    }
    char v[64];
    vnetstr(seg, v);
    printf("* %s: %s bridged to interface '%s' (%s)\n", name, v, adapter, guid);
    pins_set(guid, seg);
    set_str("VNL_SetVnetDisplayName", v, name);
    v1i("VNL_SetVnetUseDHCP", v, 0);
    v1i("VNL_SetVnetUseNAT", v, 0);
    cycle_bridge();
    int f = features(v);
    printf("  %s: %s features=0x%08x\n",
           f > 0 && (f & 0x1) ? "OK" : "WARNING: bridged bit not set", v,
           f < 0 ? 0 : f);
}

static void cmd_unpin(void)
{
    int want = parse_vnet(opt_str("--vnet"));
    Pin pins[64];
    int np = pins_get(pins, 64), removed = 0;
    for (int i = 0; i < np; i++)
        if (pins[i].vnet == want) {
            pins_del(pins[i].guid);
            printf("* removed bridge binding %s -> vmnet%d\n", pins[i].guid, want);
            removed = 1;
        }
    if (!removed) printf("* no bridge binding on vmnet%d\n", want);
    if (removed) cycle_bridge();
}

static void cmd_autobridge(int dry_run)
{
    Nic nics[64];
    int n = classify_nics(nics, 64);
    if (!n) {
        printf("* no physical NICs found (every adapter looks virtual/VPN)\n");
        return;
    }
    Pin pins[64];
    int np = pins_get(pins, 64);
    char named_dn[32][64];
    int named_vn[32], nn = 0;
    for (int k = 1; k < vnet_count() && nn < 32; k++) {
        char v[64], dn[64];
        vnetstr(k, v);
        get_str("VNL_GetVnetDisplayName", v, dn, sizeof dn);
        if (dn[0]) {
            int dup = 0;
            for (int j = 0; j < nn; j++) dup |= !strcmp(named_dn[j], dn);
            if (!dup) { strcpy(named_dn[nn], dn); named_vn[nn] = k; nn++; }
        }
    }
    int cnt_eth = 0, cnt_wifi = 0, changed = 0;
    int planned[64], nplanned = 0;
    for (int i = 0; i < n; i++) {
        int pmt = pmt_for_guid(nics[i].guid);
        int wifi = nics[i].iftype == 71 || pmt == 71;
        char want[16];
        snprintf(want, sizeof want, "%s%d", wifi ? "WLAN" : "LAN",
                 wifi ? ++cnt_wifi : ++cnt_eth);
        int seg = -1;
        if (pin_of(pins, np, nics[i].guid, &seg)) {
            char v[64];
            vnetstr(seg, v);
            int f = features(v);
            if (f > 0 && (f & ~0x1)) {
                printf("* %s already pinned to %s with host network config; "
                       "left alone (use unpin/remove to reclaim it)\n",
                       nics[i].name, v);
                continue;
            }
            char cur[64];
            get_str("VNL_GetVnetDisplayName", v, cur, sizeof cur);
            if (strcmp(cur, want)) {
                set_str("VNL_SetVnetDisplayName", v, want);
                changed = 1;
                printf("* %s renamed to %s (%s)\n", v, want, nics[i].name);
            } else {
                printf("* %s already bridges %s as %s\n", v, nics[i].name, want);
            }
            continue;
        }
        for (int j = 0; j < nn; j++)
            if (!strcmp(named_dn[j], want)) {
                int v = named_vn[j], bad = vnet_pinned(pins, np, v);
                for (int q = 0; q < nplanned; q++) bad |= planned[q] == v;
                int f = 0;
                char s[64];
                vnetstr(v, s);
                f = features(s);
                bad |= f > 0 && (f & ~0x1);
                if (!bad) seg = v;
                break;
            }
        if (seg < 0) {
            for (seg = 2; seg < 20; seg++) {
                if (vnet_pinned(pins, np, seg)) continue;
                int taken = 0;
                for (int q = 0; q < nplanned; q++) taken |= planned[q] == seg;
                if (taken || vnet_in_use(seg)) continue;
                break;
            }
            if (seg == 20) {
                printf("ERROR: no free vmnet segment (2..19) for %s\n",
                       nics[i].name);
                continue;
            }
        }
        char v[64];
        vnetstr(seg, v);
        printf("* autobridge %s (%s; %s) -> %s as %s%s\n", nics[i].name,
               nics[i].desc, wifi ? "wifi" : "ethernet", v, want,
               dry_run ? " [dry-run]" : "");
        planned[nplanned++] = seg;
        changed = 1;
        if (!dry_run) {
            pins_set(nics[i].guid, seg);
            if (np < 64) { strcpy(pins[np].guid, nics[i].guid); pins[np++].vnet = seg; }
            set_str("VNL_SetVnetDisplayName", v, want);
            v1i("VNL_SetVnetUseDHCP", v, 0);
            v1i("VNL_SetVnetUseNAT", v, 0);
        }
    }
    if (dry_run) {
        printf("(dry run: nothing changed)\n");
        return;
    }
    if (changed) cycle_bridge();
    for (int i = 1; i < np; i++)        /* sort pins by vnet for stable output */
        for (int j = i; j > 0 && pins[j].vnet < pins[j - 1].vnet; j--) {
            Pin t = pins[j];
            pins[j] = pins[j - 1];
            pins[j - 1] = t;
        }
    for (int i = 0; i < np; i++) {
        char v[64];
        vnetstr(pins[i].vnet, v);
        int f = features(v);
        printf("  %s: vmnet%d pinned to %s features=0x%08x\n",
               f > 0 && (f & 0x1) ? "OK" : "WARNING", pins[i].vnet,
               pins[i].guid, f < 0 ? 0 : f);
    }
}

/* NAT\{TCP,UDP}Forward\<hostPort> = "vmIP:vmPort" — schema proven from
   vmnetcfg.exe's SetNATPortForward call sites + live registry diffs. */
static void cmd_natfw(const char *action)
{
    char v[64];
    int n = parse_vnet(opt_str("--vnet"));
    vnetstr(n, v);
    if (strcmp(action, "list")) {
        if (!opt_str("--proto")) die("natfw add/remove need --proto tcp|udp");
        if (!opt_str("--hport")) die("natfw add/remove need --hport");
    }
    int proto = opt_str("--proto") && !strcmp(opt_str("--proto"), "tcp");
    if (!strcmp(action, "list")) {
        const char *subs[2] = { "TCPForward", "UDPForward" };
        const char *labels[2] = { "tcp", "udp" };
        for (int s = 0; s < 2; s++) {
            char path[256];
            snprintf(path, sizeof path, "%s\\%s\\NAT\\%s", CFG, v, subs[s]);
            HKEY k;
            if (ropen(path, KEY_READ, &k)) continue;
            char names[64][32], vals[64][128];
            int nv = 0;
            for (int i = 0; ; i++) {
                char nm[64], tmp[128];               /* enum into scratch: RegEnumValue
                                                        writes BEFORE any filter check */
                DWORD nl = sizeof nm, t, vl = sizeof tmp;
                if (RegEnumValueA(k, i, nm, &nl, NULL, &t, (BYTE *)tmp, &vl))
                    break;
                if (t == REG_SZ && nv < 64 && !ends_with(nm, "Description")) {
                    nm[sizeof nm - 1] = 0;
                    tmp[vl ? vl - 1 : 0] = 0;
                    snprintf(names[nv], sizeof names[0], "%s", nm);
                    snprintf(vals[nv], sizeof vals[0], "%s", tmp);
                    nv++;
                }
            }
            for (int i = 1; i < nv; i++)     /* sorted by port name */
                for (int j = i; j > 0 && strcmp(names[j], names[j - 1]) < 0; j--) {
                    char t[32], u[128];
                    strcpy(t, names[j]); strcpy(names[j], names[j - 1]); strcpy(names[j - 1], t);
                    strcpy(u, vals[j]); strcpy(vals[j], vals[j - 1]); strcpy(vals[j - 1], u);
                }
            for (int i = 0; i < nv; i++) {
                char dpath[280], dname[80];
                snprintf(dpath, sizeof dpath, "%s\\%s\\NAT\\%s", CFG, v, subs[s]);
                snprintf(dname, sizeof dname, "%sDescription", names[i]);
                char desc[128] = "";
                DWORD dt, dsz = sizeof desc;
                HKEY dk;
                if (!ropen(dpath, KEY_READ, &dk)) {
                    if (RegQueryValueExA(dk, dname, NULL, &dt, (BYTE *)desc, &dsz)
                            == ERROR_SUCCESS && dt == REG_BINARY) {
                        WCHAR w[64];
                        int wn = (int)(dsz / 2);
                        if (wn > 63) wn = 63;
                        memcpy(w, desc, (size_t)wn * 2);
                        w[wn] = 0;
                        w2u8(w, desc, sizeof desc);
                    }
                    RegCloseKey(dk);
                }
                if (desc[0])
                    printf("  %s %s host:%s -> %s (%s)\n", v, labels[s],
                           names[i], vals[i], desc);
                else
                    printf("  %s %s host:%s -> %s\n", v, labels[s], names[i], vals[i]);
            }
            RegCloseKey(k);
        }
        return;
    }
    int hport = atoi(opt_str("--hport"));
    int rc;
    if (!strcmp(action, "add")) {
        const char *vmip = opt_str("--vm-ip"), *d = opt_str("--desc");
        if (!vmip || !opt_str("--vm-port"))
            die("natfw add needs --vm-ip and --vm-port");
        WCHAR *dw = d ? u82w(d) : NULL;
        rc = ((F7pf)vneed("VNL_SetNATPortForward"))(vlstr(v), proto,
               (unsigned short)hport, vlstr(vmip),
               (unsigned short)atoi(opt_str("--vm-port")), dw, 0);
        free(dw);
        printf("* %s map %s host:%d -> %s:%s: %s\n", v,
               opt_str("--proto"), hport, vmip, opt_str("--vm-port"),
               rcs(rc));
    } else {   /* remove: same call with vmIP NULL (GUI-proven delete) */
        rc = ((F7pf)vneed("VNL_SetNATPortForward"))(vlstr(v), proto,
               (unsigned short)hport, NULL, 0, NULL, 0);
        printf("* %s unmap %s host:%d: %s\n", v, opt_str("--proto"), hport,
               rcs(rc));
    }
    /* UpdateNATFromConfig rewrites the WHOLE conf from this vnet — regen the
       target so its forwards/sections are the ones in the file. */
    v1("VNL_UpdateNATFromConfig", v);
    restart_services(0, 1);
}

static void cmd_natcfg(const char *action)
{
    char v[64];
    int n = parse_vnet(opt_str("--vnet"));
    vnetstr(n, v);
    int f = features(v);
    if (!reg_flag(v, "NAT") && !(f > 0 && (f & 0x10000)))
        die("%s is not a NAT network", v);
    char path[256];
    snprintf(path, sizeof path, "%s\\%s\\NAT", CFG, v);
    if (!strcmp(action, "show")) {
        HKEY k;
        if (ropen(path, KEY_READ, &k)) die("no NAT config key for %s", v);
        for (int i = 0; ; i++) {
            char nm[64];
            DWORD nl = sizeof nm, t, vl = 128;
            char val[128];
            if (RegEnumValueA(k, i, nm, &nl, NULL, &t, (BYTE *)val, &vl)) break;
            if (t == REG_DWORD) printf("  %s = %lu\n", nm, *(DWORD *)val);
            else if (t == REG_SZ) printf("  %s = %s\n", nm, val);
        }
        RegCloseKey(k);
        return;
    }
    struct { const char *flag, *rname; int dw; } MAP[] = {
        { "--gateway-ip", "ip", 0 }, { "--host-ip", "hostIp", 0 },
        { "--configport", "ConfigPort", 1 }, { "--udp-timeout", "udpTimeout", 1 },
        { "--dns1", "DNSNameServer1", 0 }, { "--dns2", "DNSNameServer2", 0 },
        { "--dns3", "DNSNameServer3", 0 }, { "--dns-policy", "DNSPolicy", 0 },
        { "--dns-retries", "DNSRetries", 1 }, { "--dns-timeout", "DNSTimeout", 1 },
        { "--nbns-timeout", "NBNSTimeout", 1 },
        { "--ipv6", "natIp6Enable", 2 }, { "--active-ftp", "activeFTP", 2 },
        { "--allow-any-oui", "allowAnyOUI", 2 }, { "--dns-auto", "DNSAutodetect", 2 } };
    int changed = 0;
    for (size_t i = 0; i < sizeof MAP / sizeof *MAP; i++) {
        const char *val = opt_str(MAP[i].flag);
        if (!val) continue;
        if (MAP[i].dw == 1) {
            reg_set_dword(path, MAP[i].rname, (DWORD)atoi(val));
            printf("  %s NAT %s = %s\n", v, MAP[i].rname, val);
        } else if (MAP[i].dw == 2) {
            int on = !strcmp(val, "on");
            reg_set_dword(path, MAP[i].rname, (DWORD)on);
            printf("  %s NAT %s = %d\n", v, MAP[i].rname, on);
        } else {
            reg_set_sz(path, MAP[i].rname, val);
            printf("  %s NAT %s = %s\n", v, MAP[i].rname, val);
        }
        changed = 1;
    }
    if (changed) {
        v1("VNL_UpdateNATFromConfig", v);
        restart_services(0, 1);
    } else {
        printf("nothing to change\n");
    }
}

/* ---------------------------------------------------- remove / restore */
/* Stage the cheap part of a removal: pins, adapter kick, config key, conf
   edits. Expensive waits/restarts are deferred to batch_apply so a command
   touching many networks pays them once, not per network. */
static int remove_stage(int n, Batch *b)
{
    char v[64];
    vnetstr(n, v);
    int f = features(v);
    if (f < 0) f = 0;
    Pin pins[64];
    int np = pins_get(pins, 64), pinned = 0;
    for (int i = 0; i < np; i++) pinned |= pins[i].vnet == n;
    int had_dhcp = (f & 0x1000000) || reg_flag(v, "DHCP");
    int had_nat = (f & 0x10000) || reg_flag(v, "NAT");
    int had_adapter = (f & 0x100) || reg_flag(v, "Adapter");
    char cfgpath[256];
    snprintf(cfgpath, sizeof cfgpath, "%s\\%s", CFG, v);
    int has_config = reg_exists(cfgpath);
    if (!f && !had_dhcp && !had_nat && !had_adapter && !pinned && !has_config) {
        printf("* %s is not configured; nothing to remove\n", v);
        return 0;
    }
    char bits[128];
    bits_str(f, bits, sizeof bits);
    printf("* removing %s%s%s%s\n", v, bits[0] ? " (" : "", bits,
           bits[0] ? ")" : "");
    if (b->nvn < 24) b->vnets[b->nvn++] = n;
    else fprintf(stderr, "warning: batch report capped at 24 networks\n");
    for (int i = 0; i < np; i++)
        if (pins[i].vnet == n) {
            pins_del(pins[i].guid);
            printf("  - unbound %s\n", pins[i].guid);
            b->bridge = 1;
        }
    if (had_adapter) {
        uninstall_adapter_start(v, n);
        if (b->ngone < 24) b->gone[b->ngone++] = n;
        else fprintf(stderr, "warning: adapter wait capped at 24\n");
    }
    LONG dr = reg_delete_tree(cfgpath);
    printf("  - deleted VMnetConfig\\%s%s\n", v, dr ? " (FAILED!)" : "");
    if (had_dhcp) {
        int rc = v1("VNL_UpdateDHCPFromConfig", v);
        printf("  - vmnetdhcp.conf regenerated: %s\n", rcs(rc));
        b->dhcp = 1;
    }
    if (had_nat) b->nat = 1;   /* whole-file rewrite — once at apply */
    return 1;
}

/* One wait for all PnP operations, one NAT conf regen, one service restart,
   one bridge cycle — regardless of batch size. */
static void batch_apply(Batch *b)
{
    if (b->nat) {
        regen_nat_conf();
        printf("  - vmnetnat.conf regenerated\n");
    }
    if (b->ngone) {
        sleep_ms(3000);
        int present[64], np = nic_present_set(present, 64);
        for (int i = 0; i < b->ngone; i++) {
            int n = b->gone[i];
            if (set_has(present, np, n)) {
                pnputil_remove_vmnet(n);
                sleep_ms(3000);
                np = nic_present_set(present, 64);
            }
            printf("  - host adapter device vmnet%d: %s\n", n,
                   set_has(present, np, n) ? "STILL PRESENT" : "gone");
        }
    }
    if (b->nadded) {
        int pend[24], np_ = b->nadded;
        for (int i = 0; i < np_; i++) pend[i] = b->added[i];
        for (int t = 0; t < 10 && np_; t++) {   /* PnP completes async */
            sleep_ms(3000);
            int present[64], np = nic_present_set(present, 64);
            int k = 0;
            for (int i = 0; i < np_; i++)
                if (!set_has(present, np, pend[i])) pend[k++] = pend[i];
            np_ = k;
        }
        for (int i = 0; i < np_; i++) drvinst_install(pend[i]);
        for (int t = 0; t < 4 && np_; t++) {
            sleep_ms(3000);
            int present[64], np = nic_present_set(present, 64);
            int k = 0;
            for (int i = 0; i < np_; i++)
                if (!set_has(present, np, pend[i])) pend[k++] = pend[i];
            np_ = k;
        }
        int present[64], np = nic_present_set(present, 64);
        for (int i = 0; i < b->nadded; i++)
            printf("  - host adapter device vmnet%d: %s\n", b->added[i],
                   set_has(present, np, b->added[i]) ? "ok"
                                                     : "pending/failed (PnP is async)");
    }
    if (b->dhcp || b->nat) restart_services(b->dhcp, b->nat);
    if (b->bridge) cycle_bridge();
    for (int i = 0; i < b->nvn; i++) {
        char v[64];
        vnetstr(b->vnets[i], v);
        int left = features(v);
        printf("  %s: %s features now 0x%08x\n", left == 0 ? "OK" : "WARNING",
               v, left < 0 ? 0 : left);
    }
}

static void cmd_remove(void)
{
    int vn[24], nv = 0;
    for (int i = 1; i < g_argc - 1; i++)
        if (strcmp(g_argv[i], "--vnet") == 0) {
            if (nv < 24) vn[nv++] = parse_vnet(g_argv[++i]);
            else { fprintf(stderr, "warning: only 24 --vnet args honored\n"); i++; }
        }
    if (!nv) die("remove needs --vnet");
    for (int i = 0; i < nv; i++) {         /* validate before touching anything */
        if (vn[i] == 0)
            die("vmnet0 is the built-in bridge segment and cannot be removed");
        if ((vn[i] == 1 || vn[i] == 8) && !opt_flag("--force"))
            die("vmnet%d is a stock Workstation network; pass --force to "
                "remove it anyway", vn[i]);
    }
    Batch b;
    batch_new(&b);
    for (int i = 0; i < nv; i++) remove_stage(vn[i], &b);
    batch_apply(&b);
}

/* Remove EVERY vmnet network — custom AND stock vmnet1/vmnet8. vmnet0 (the
   VMnetBridge driver's auto-bridge segment) is not removable and stays. */
static void cmd_clear(void)
{
    if (!opt_flag("--force"))
        die("clear removes ALL networks including stock vmnet1/vmnet8; "
            "pass --force");
    printf("* clearing all vmnet networks (vmnet0 remains)\n");
    Batch b;
    batch_new(&b);
    for (int n = 1; n < vnet_count(); n++) {
        char v[64], path[256];
        vnetstr(n, v);
        snprintf(path, sizeof path, "%s\\%s", CFG, v);
        int f = features(v);
        Pin pins[64];
        int np = pins_get(pins, 64);
        if (f <= 0 && !reg_exists(path) && !vnet_pinned(pins, np, n))
            continue;                       /* silent segment: nothing to do */
        remove_stage(n, &b);
    }
    batch_apply(&b);
}

static void cmd_restore(void)
{
    if (!opt_flag("--force"))
        die("restore-defaults removes ALL custom networks; pass --force");
    printf("* restoring default networks (vmnet0 auto-bridge, vmnet1 "
           "host-only, vmnet8 NAT)\n");
    Batch b;
    batch_new(&b);
    for (int n = 2; n < vnet_count(); n++) {
        if (n == 1 || n == 8) continue;
        char path[256], v[64];
        vnetstr(n, v);
        snprintf(path, sizeof path, "%s\\%s", CFG, v);
        if (reg_exists(path)) remove_stage(n, &b);
    }
    struct { int n; int is_nat; const char *subnet; } DEF[] = {
        { 1, 0, "192.168.14.0" }, { 8, 1, "192.168.251.0" } };
    for (int i = 0; i < 2; i++) {
        char v[64];
        vnetstr(DEF[i].n, v);
        if (features(v) > 0) continue;
        set_str("VNL_SetVnetSubnetAddr", v, DEF[i].subnet);
        set_str("VNL_SetVnetSubnetMask", v, "255.255.255.0");
        v1i("VNL_SetVnetUseDHCP", v, 1);
        if (DEF[i].is_nat) ensure_nat(v, 1);
        install_adapter_start(v);           /* kicked now, awaited in apply */
        if (b.nadded < 24) b.added[b.nadded++] = DEF[i].n;
        else fprintf(stderr, "warning: adapter wait capped at 24\n");
        char p[256];
        snprintf(p, sizeof p, "%s\\%s\\Adapter", CFG, v);
        reg_set_dword(p, "UseAdapter", 1);
        char ip[64];
        subnet_host1(DEF[i].subnet, ip, sizeof ip);
        v1s("VNL_SetVnetAdapterAddr", v, ip);
        printf("  - recreated %s (%s) %s\n", v,
               DEF[i].is_nat ? "nat" : "hostonly", DEF[i].subnet);
    }
    set_str("VNL_SetVnetDisplayName", "vmnet0", "VMnet0");
    /* UpdateDHCPFromConfig edits each segment's block in place — regen EVERY
       vnet (including 0) so stale conf blocks are purged too. */
    for (int n = 0; n < vnet_count(); n++) {
        char v[64];
        vnetstr(n, v);
        v1("VNL_UpdateDHCPFromConfig", v);
    }
    b.dhcp = b.nat = 1;                     /* one restart for the whole restore */
    batch_apply(&b);
}

/* ------------------------------------------------------------------ main */
int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 2) {
        fprintf(stderr,
            "usage: vmnet-cli <adapters|list|add|bridged|edit|set-ip|natfw|"
            "natcfg|remove|clear|unpin|autobridge|restore-defaults|export|import>\n");
        return 2;
    }
    g_argc = argc;
    g_argv = argv;
    vl_init();
    const char *cmd = argv[1];
    const char *sub = argc > 2 ? argv[2] : NULL;
    if (!strcmp(cmd, "adapters"))            cmd_adapters();
    else if (!strcmp(cmd, "list"))           cmd_list();
    else if (!strcmp(cmd, "add")) {
        if (!sub || (strcmp(sub, "hostonly") && strcmp(sub, "nat")))
            die("add needs a kind: hostonly or nat");
        cmd_add(sub);
    }
    else if (!strcmp(cmd, "bridged"))        cmd_bridged();
    else if (!strcmp(cmd, "edit"))           cmd_edit();
    else if (!strcmp(cmd, "set-ip"))         cmd_setip();
    else if (!strcmp(cmd, "export"))         cmd_export();
    else if (!strcmp(cmd, "import"))         cmd_import();
    else if (!strcmp(cmd, "unpin"))          cmd_unpin();
    else if (!strcmp(cmd, "remove"))         cmd_remove();
    else if (!strcmp(cmd, "clear") || !strcmp(cmd, "flush")) cmd_clear();
    else if (!strcmp(cmd, "restore-defaults")) cmd_restore();
    else if (!strcmp(cmd, "autobridge"))     cmd_autobridge(opt_flag("--dry-run"));
    else if (!strcmp(cmd, "natfw")) {
        if (!sub || (strcmp(sub, "list") && strcmp(sub, "add") && strcmp(sub, "remove")))
            die("natfw needs an action: list, add or remove");
        cmd_natfw(sub);
    }
    else if (!strcmp(cmd, "natcfg")) {
        if (!sub || (strcmp(sub, "show") && strcmp(sub, "set")))
            die("natcfg needs an action: show or set");
        cmd_natcfg(sub);
    }
    else die("unknown command '%s'", cmd);
    return 0;
}