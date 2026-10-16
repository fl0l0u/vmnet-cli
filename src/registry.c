/* SPDX-License-Identifier: Apache-2.0 */
/* registry.c - HKLM VMnetConfig database + VMnetBridge adapter pin table */
#include "vmnet.h"

/* -------------------------------------------------------------- registry */
LONG ropen(const char *path, ACCESS_MASK acc, HKEY *k)
{
    return RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, acc | KEY_WOW64_64KEY, k);
}


int reg_get_dword(const char *path, const char *name, DWORD *val)
{
    HKEY k;
    if (ropen(path, KEY_READ, &k)) return 0;
    DWORD t, sz = sizeof *val;
    LONG rc = RegQueryValueExA(k, name, NULL, &t, (BYTE *)val, &sz);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS && t == REG_DWORD;
}


int reg_get_sz(const char *path, const char *name, char *buf, DWORD bsz)
{
    HKEY k;
    buf[0] = 0;
    if (ropen(path, KEY_READ, &k)) return 0;
    DWORD t, sz = bsz;
    LONG rc = RegQueryValueExA(k, name, NULL, &t, (BYTE *)buf, &sz);
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS) return 0;
    if (t == REG_SZ || t == REG_MULTI_SZ || t == REG_EXPAND_SZ)
        buf[bsz - 1] = 0; /* MORE_DATA can fill without a NUL */
    else {
        buf[0] = 0;
        return 0;
    }
    return 1;
}


void reg_set_dword(const char *path, const char *name, DWORD val)
{
    HKEY k;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL,
                        &k, NULL))
        die("cannot write HKLM\\%s", path);
    LONG sr = RegSetValueExA(k, name, 0, REG_DWORD, (BYTE *)&val, sizeof val);
    RegCloseKey(k);
    if (sr) die("cannot write HKLM\\%s\\%s (rc=%ld)", path, name, sr);
}


void reg_set_sz(const char *path, const char *name, const char *val)
{
    HKEY k;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL,
                        &k, NULL))
        die("cannot write HKLM\\%s", path);
    LONG sr = RegSetValueExA(k, name, 0, REG_SZ, (BYTE *)val, (DWORD)strlen(val) + 1);
    RegCloseKey(k);
    if (sr) die("cannot write HKLM\\%s\\%s (rc=%ld)", path, name, sr);
}


int reg_exists(const char *path)
{
    HKEY k;
    if (ropen(path, KEY_READ, &k)) return 0;
    RegCloseKey(k);
    return 1;
}


LONG reg_delete_tree(const char *path)
{
    WCHAR *w = u82w(path);
    LONG rc = RegDeleteTreeW(HKEY_LOCAL_MACHINE, w);
    free(w);
    return rc == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : rc; /* absent = no-op */
}


/* True if VMnetConfig\vnet\sub\Use<sub> == 1 (registry is config truth). */
int reg_flag(const char *vnet, const char *sub)
{
    char path[512], valname[64];
    DWORD v = 0;
    snprintf(path, sizeof path, "%s\\%s\\%s", CFG, vnet, sub);
    snprintf(valname, sizeof valname, "Use%s", sub);
    return reg_get_dword(path, valname, &v) && v == 1;
}


int pins_get(Pin *out, int max)
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
            snprintf(out[n].guid, sizeof out[n].guid, "%s", sub);
            upper(out[n].guid);
            out[n].vnet = (int)v;
            n++;
        }
    }
    RegCloseKey(k);
    return n;
}

int pin_of(const Pin *pins, int npins, const char *guid, int *vn)
{
    for (int i = 0; i < npins; i++)
        if (strcmp(pins[i].guid, guid) == 0) {
            *vn = pins[i].vnet;
            return 1;
        }
    return 0;
}

int vnet_pinned(const Pin *pins, int npins, int n)
{
    for (int i = 0; i < npins; i++)
        if (pins[i].vnet == n) return 1;
    return 0;
}

void pins_set(const char *guid, int vnet)
{
    char path[256];
    snprintf(path, sizeof path, "%s\\%s", BRIDGE_TABLE, guid);
    reg_set_dword(path, "VMnet", (DWORD)vnet);
}

void pins_del(const char *guid)
{
    char path[256];
    snprintf(path, sizeof path, "%s\\%s", BRIDGE_TABLE, guid);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, path);
}
