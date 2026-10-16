/* SPDX-License-Identifier: Apache-2.0 */
/* cmds_cfg.c - commands: set-ip, export, import, natfw, natcfg */
#include "vmnet.h"

void cmd_setip(void)
{
    char v[64];
    int n = parse_vnet(opt_str("--vnet"));
    require_vnet(n);
    vnetstr(n, v);
    const char *addr = opt_str("--addr");
    if (!addr) die("set-ip needs --addr");
    int rc = v1s("VNL_SetVnetAdapterAddr", v, addr);
    printf("* %s adapter IP %s: %s\n", v, addr, rcs(rc));
    v1("VNL_UpdateAdapterFromConfig", v); /* apply to the live device */
    char cur[64];
    get_str("VNL_GetVnetAdapterAddr", v, cur, sizeof cur);
    printf("  configured adapter addr: '%s'\n", cur);
}


/* vnetlib's Export/ImportDatabaseToFile do nothing when called from a native
   x64 process (rc=1, no file — proven live; work only via a ctypes-style
   caller). The database file is a plain hive of VMnetConfig (byte-identical
   to `reg save`), so use the registry APIs directly: same regf format. */

int cmd_export(void)
{
    const char *f = opt_str("--file");
    if (!f) die("export needs --file");
    enable_privilege(L"SeBackupPrivilege");
    HKEY k;
    if (ropen(CFG, KEY_READ, &k)) die("cannot open HKLM\\%s", CFG);
    WCHAR *w = u82w(f);
    DeleteFileW(w); /* RegSaveKeyEx refuses existing files */
    LONG rc = RegSaveKeyExW(k, w, NULL, REG_LITE);
    free(w);
    RegCloseKey(k);
    printf("export -> %s: %s\n", f, rc == ERROR_SUCCESS ? "ok" : "rc=fail");
    if (rc != ERROR_SUCCESS) fprintf(stderr, "export rc=%ld\n", rc);
    return rc == ERROR_SUCCESS ? 0 : 1;
}


void copy_tree(HKEY src, HKEY dst)
{
    for (int j = 0;; j++) { /* values at this level */
        WCHAR nm[256];
        DWORD nl = sizeof nm / 2, t, vs = 0;
        if (RegEnumValueW(src, j, nm, &nl, NULL, &t, NULL, &vs)) break;
        BYTE *buf = xmalloc(vs ? vs : 1);
        if (!RegQueryValueExW(src, nm, NULL, &t, buf, &vs)) RegSetValueExW(dst, nm, 0, t, buf, vs);
        free(buf);
    }
    for (int i = 0;; i++) { /* subkeys */
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
    for (int i = 0;;) { /* prune dst children absent from src */
        WCHAR sub[256];
        DWORD sl = sizeof sub / 2;
        LONG er = RegEnumKeyExW(dst, i, sub, &sl, NULL, NULL, NULL, NULL);
        if (er == ERROR_NO_MORE_ITEMS) break;
        if (er) {
            i++;
            continue;
        }
        HKEY t;
        if (RegOpenKeyExW(src, sub, 0, KEY_READ, &t)) {
            if (RegDeleteTreeW(dst, sub)) i++; /* locked: warn, move on */
            else
                fprintf(stderr, "warning: pruned stale key beyond hive\n");
        }
        else {
            RegCloseKey(t);
            i++;
        }
    }
}


int cmd_import(void)
{
    const char *f = opt_str("--file");
    if (!f) die("import needs --file");
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");
    WCHAR *w = u82w(f);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp"); /* stale mount */
    LONG rc = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp", w);
    free(w);
    if (rc != ERROR_SUCCESS) {
        printf("import <- %s: rc=fail\n", f);
        fprintf(stderr, "import rc=%ld\n", rc);
        return 1;
    }
    HKEY src, dst;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"VMnetCliImp", 0, KEY_READ, &src)) {
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp");
        die("import: cannot open loaded hive");
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, CFG, 0, NULL, 0,
                        KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, NULL, &dst, NULL)) {
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp");
        die("import: cannot open HKLM\\%s", CFG);
    }
    /* import REPLACES the database, but merge-first-then-prune: wiping up
       front would leave a half-deleted DB if the wipe hits a locked key
       (RegDeleteTree deletes partially before failing — proven live). */
    copy_tree(src, dst);
    RegCloseKey(dst);
    RegCloseKey(src);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"VMnetCliImp");
    printf("import <- %s: ok\n", f);
    v1("VNL_UpdateDHCPFromConfig", "vmnet1");
    regen_nat_conf();
    restart_services(1, 1);
    return 0;
}


void cmd_natfw(const char *action)
{
    char v[64];
    int n = parse_vnet(opt_str("--vnet"));
    require_vnet(n);
    vnetstr(n, v);
    // cppcheck-suppress ctunullpointer  /* main.c rejects NULL/unknown sub before calling */
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
            for (int i = 0;; i++) {
                char nm[64], tmp[128]; /* enum into scratch: RegEnumValue
                                                        writes BEFORE any filter check */
                DWORD nl = sizeof nm, t, vl = sizeof tmp;
                LONG er = RegEnumValueA(k, i, nm, &nl, NULL, &t, (BYTE *)tmp, &vl);
                if (er == ERROR_NO_MORE_ITEMS) break;
                if (er) continue; /* incl. MORE_DATA: skip, keep going */
                if (t == REG_SZ && nv < 64 && !ends_with(nm, "Description")) {
                    nm[sizeof nm - 1] = 0;
                    tmp[vl ? vl - 1 : 0] = 0;
                    snprintf(names[nv], sizeof names[0], "%s", nm);
                    snprintf(vals[nv], sizeof vals[0], "%s", tmp);
                    nv++;
                }
            }
            for (int i = 1; i < nv; i++) /* sorted by port name */
                for (int j = i; j > 0 && strcmp(names[j], names[j - 1]) < 0; j--) {
                    char t[32], u[128];
                    snprintf(t, sizeof t, "%s", names[j]);
                    snprintf(names[j], sizeof names[j], "%s", names[j - 1]);
                    snprintf(names[j - 1], sizeof names[j - 1], "%s", t);
                    snprintf(u, sizeof u, "%s", vals[j]);
                    snprintf(vals[j], sizeof vals[j], "%s", vals[j - 1]);
                    snprintf(vals[j - 1], sizeof vals[j - 1], "%s", u);
                }
            for (int i = 0; i < nv; i++) {
                char dpath[280], dname[80];
                snprintf(dpath, sizeof dpath, "%s\\%s\\NAT\\%s", CFG, v, subs[s]);
                snprintf(dname, sizeof dname, "%sDescription", names[i]);
                char desc[128] = "";
                DWORD dt, dsz = sizeof desc;
                HKEY dk;
                if (!ropen(dpath, KEY_READ, &dk)) {
                    LONG qr = RegQueryValueExA(dk, dname, NULL, &dt, (BYTE *)desc, &dsz);
                    desc[sizeof desc - 1] = 0; /* MORE_DATA may fill w/o NUL */
                    if (qr == ERROR_SUCCESS && dt == REG_BINARY) {
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
                    printf("  %s %s host:%s -> %s (%s)\n", v, labels[s], names[i], vals[i], desc);
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
        if (!vmip || !opt_str("--vm-port")) die("natfw add needs --vm-ip and --vm-port");
        rc = ((F7pf)vneed("VNL_SetNATPortForward"))(
            vlstr(v), proto, (unsigned short)hport, vlstr(vmip),
            (unsigned short)atoi(opt_str("--vm-port")), d ? vlwide(d) : NULL, 0);
        printf("* %s map %s host:%d -> %s:%s: %s\n", v, opt_str("--proto"), hport, vmip,
               opt_str("--vm-port"), rcs(rc));
    }
    else { /* remove: same call with vmIP NULL (GUI-proven delete) */
        rc = ((F7pf)vneed("VNL_SetNATPortForward"))(vlstr(v), proto, (unsigned short)hport, NULL, 0,
                                                    NULL, 0);
        printf("* %s unmap %s host:%d: %s\n", v, opt_str("--proto"), hport, rcs(rc));
    }
    /* UpdateNATFromConfig rewrites the WHOLE conf from this vnet — regen the
       target so its forwards/sections are the ones in the file. */
    v1("VNL_UpdateNATFromConfig", v);
    restart_services(0, 1);
}


void cmd_natcfg(const char *action)
{
    char v[64];
    int n = parse_vnet(opt_str("--vnet"));
    require_vnet(n);
    vnetstr(n, v);
    int f = features(v);
    if (!reg_flag(v, "NAT") && !(f > 0 && (f & 0x10000))) die("%s is not a NAT network", v);
    char path[256];
    snprintf(path, sizeof path, "%s\\%s\\NAT", CFG, v);
    // cppcheck-suppress ctunullpointer  /* main.c rejects NULL/unknown sub before calling */
    if (!strcmp(action, "show")) {
        HKEY k;
        if (ropen(path, KEY_READ, &k)) die("no NAT config key for %s", v);
        for (int i = 0;; i++) {
            char nm[64];
            DWORD nl = sizeof nm, t, vl = 128;
            char val[128];
            LONG er = RegEnumValueA(k, i, nm, &nl, NULL, &t, (BYTE *)val, &vl);
            if (er == ERROR_NO_MORE_ITEMS) break;
            if (er) continue;
            if (t == REG_DWORD && vl >= 4) printf("  %s = %lu\n", nm, *(DWORD *)val);
            else if (t == REG_SZ) {
                val[sizeof val - 1] = 0;
                printf("  %s = %s\n", nm, val);
            }
        }
        RegCloseKey(k);
        return;
    }
    // clang-format off
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

