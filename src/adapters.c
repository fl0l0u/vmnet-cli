/* SPDX-License-Identifier: Apache-2.0 */
/* adapters.c - host virtual NIC enumeration, classification and PnP install/remove */
#include "vmnet.h"

int nic_list(Nic *out, int max)
{
    ULONG len = 65536;
    IP_ADAPTER_ADDRESSES *aa = xmalloc(len);
    const IP_ADAPTER_ADDRESSES *p;
    ULONG rc;
    while ((rc = GetAdaptersAddresses(AF_UNSPEC,
                                      GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                          GAA_FLAG_SKIP_DNS_SERVER,
                                      NULL, aa, &len)) == ERROR_BUFFER_OVERFLOW) {
        free(aa);
        aa = xmalloc(len);
    }
    int n = 0;
    if (rc == ERROR_SUCCESS) {
        for (p = aa; p && n < max; p = p->Next) {
            if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            snprintf(out[n].guid, sizeof out[n].guid, "%s", p->AdapterName);
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


int nic_present_vmnet(int n)
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
int pmt_for_guid(const char *guid)
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

void bus_of_desc(const char *desc, char *bus, int buslen)
{
    static const GUID classNet = {
        0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
    };
    bus[0] = 0;
    HDEVINFO set = SetupDiGetClassDevsA(&classNet, NULL, NULL, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return;
    SP_DEVINFO_DATA di = { .cbSize = sizeof di };
    for (int i = 0; SetupDiEnumDeviceInfo(set, i, &di); i++) {
        char d[256];
        if (!SetupDiGetDeviceRegistryPropertyA(set, &di, SPDRP_DEVICEDESC, NULL, (BYTE *)d,
                                               sizeof d, NULL))
            continue;
        if (_stricmp(d, desc) != 0) continue;
        WCHAR id[320];
        if (SetupDiGetDeviceInstanceIdW(set, &di, id, 320, NULL)) {
            w2u8(id, d, sizeof d);
            const char *bs = strchr(d, '\\');
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


static const char *PHYS_BUSES[] = { "PCI",  "VPCI", "USB",      "PCMCIA", "SDIO",
                                    "SDCC", "SD",   "IEEE1394", "MDIO",   "ACPI" };


/* Physical NICs only (Ethernet/Wi-Fi), in ifIndex order. */
int classify_nics(Nic *out, int max)
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
            if (strncmp(bus, PHYS_BUSES[b], strlen(PHYS_BUSES[b])) == 0) ok = 1;
        if (!ok) continue;
        switch (all[i].iftype) {
        case 24:
        case 131:
        case 135:
        case 136:
        case 148:
        case 154:
        case 166:
        case 181:
        case 209:
            continue; /* ppp / tunnels — not LAN/WLAN */
        default:
            break;
        }
        out[c++] = all[i];
    }
    return c;
}


void drvinst_install(int n)
{
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
             "\"%s\\drvInst64.exe\" installRootDriver 0 *VMnetAdapter%d"
             " \"%s\\netadapter.inf\" 1",
             VMWARE_DIR, n, VMWARE_DIR);
    run_hidden(cmd);
}


void install_adapter_start(const char *vnet)
{
    /* 5-arg signature (vnet, hwnd, flags, p4, int* p5): every trailing arg
       MUST be explicit — p5 is dereferenced unless NULL (stale-register AV). */
    ((F5i)vneed("VNL_InstallNetworkAdapter"))(vlstr(vnet), NULL, 0, 0, NULL);
}


int install_adapter_finish(const char *vnet, int n)
{
    (void)vnet; /* presence is detected via the VMnetN device description */
    for (int i = 0; i < 10; i++) { /* PnP completes asynchronously */
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


int install_adapter(const char *vnet, int n)
{
    install_adapter_start(vnet);
    return install_adapter_finish(vnet, n);
}


void pnputil_remove_vmnet(int n)
{
    static const GUID classNet = {
        0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
    };
    HDEVINFO set = SetupDiGetClassDevsA(&classNet, NULL, NULL, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return;
    SP_DEVINFO_DATA di = { .cbSize = sizeof di };
    char suffix[24];
    snprintf(suffix, sizeof suffix, "VMnet%d", n);
    for (int i = 0; SetupDiEnumDeviceInfo(set, i, &di); i++) {
        char d[256];
        if (!SetupDiGetDeviceRegistryPropertyA(set, &di, SPDRP_DEVICEDESC, NULL, (BYTE *)d,
                                               sizeof d, NULL))
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


void uninstall_adapter_start(const char *vnet, int n)
{
    (void)n;
    /* 3-arg signature (vnet, hwnd, int* nR) — nR dereferenced unless passed. */
    int zero = 0;
    F3u un = (F3u)vfn("VNL_UninstallNetworkAdapter");
    if (un) un(vlstr(vnet), NULL, &zero); /* missing: pnputil fallback covers it */
    char path[256];
    snprintf(path, sizeof path, "%s\\%s\\Adapter", CFG, vnet);
    reg_set_dword(path, "UseAdapter", 0);
}


int uninstall_adapter_finish(int n) /* 1 = device gone */
{
    sleep_ms(3000);
    if (nic_present_vmnet(n)) {
        pnputil_remove_vmnet(n);
        sleep_ms(3000);
    }
    return !nic_present_vmnet(n);
}


void uninstall_adapter(const char *vnet, int n)
{
    uninstall_adapter_start(vnet, n);
    uninstall_adapter_finish(n);
}


/* vmnet segments that currently have an adapter device (one enumeration) */
int nic_present_set(int *out, int max)
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
