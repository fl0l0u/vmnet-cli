/* cmds_topo.c - commands: adapters, list, add, edit, bridged, unpin, autobridge */
#include "vmnet.h"

/* --------------------------------------------------------------- commands */
void cmd_adapters(void)
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
        else
            snprintf(target, sizeof target, "%s", "vmnet0 (auto)");
        printf("%-30s %s  -> %s\n", nics[i].name, nics[i].guid, target);
    }
}


void cmd_list(void)
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
                if (reg_flag(v, "DHCP")) f |= 0x1000000;
                if (reg_flag(v, "NAT")) f |= 0x10000;
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
                if (l + 64 < sizeof extra) /* bounded; separator keys off
                                                "first for THIS vnet", not index */
                    snprintf(extra + l, sizeof extra - l, "%s%.*s",
                             l ? "," : " pinned=", (int)sizeof pins[i].guid - 1, pins[i].guid);
            }
        printf("vmnet%-2d %-40s name='%s' subnet=%s%s\n", n, bits, name, subnet, extra);
    }
}


void cmd_add(const char *kind)
{
    // cppcheck-suppress ctunullpointer  /* main.c rejects NULL/unknown sub before calling */
    int is_nat = strcmp(kind, "nat") == 0;
    const char *name = opt_str("--name");
    if (!name) name = "";
    int want = opt_str("--vnet") ? parse_vnet(opt_str("--vnet")) : -1;
    if (want >= 0) require_vnet(want);
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
        set_str("VNL_SetVnetSubnetMask", v,
                opt_str("--mask") ? opt_str("--mask") : "255.255.255.0");
    }
    else if (v1i("VNL_AssignSubnetAddressToVnet", v, 0) != 1) {
        die("could not auto-assign a free subnet; pass --subnet");
    }
    char sub[64];
    get_str("VNL_GetVnetSubnetAddr", v, sub, sizeof sub);
    const char *dhcp_opt = opt_str("--dhcp");
    int dhcp = is_nat || !dhcp_opt || strcmp(dhcp_opt, "off") != 0;
    printf("* add %s: %s name='%s' subnet=%s dhcp=%s nat=%s\n", kind, v, name, sub,
           dhcp ? "on" : "off", is_nat ? "on" : "off");
    set_str("VNL_SetVnetDisplayName", v, name);
    ensure_nat(v, is_nat);
    v1i("VNL_SetVnetUseDHCP", v, dhcp);
    int ok = install_adapter(v, n);
    printf("  - host adapter device: %s\n", ok ? "ok" : "pending/failed (PnP is async)");
    char path[256];
    snprintf(path, sizeof path, "%s\\%s\\Adapter", CFG, v);
    reg_set_dword(path, "UseAdapter", 1); /* no VNL setter exists */
    char hostip[64];
    subnet_host1(sub, hostip, sizeof hostip);
    v1s("VNL_SetVnetAdapterAddr", v, hostip);
    if (is_nat) regen_nat_conf();
    v1("VNL_UpdateDHCPFromConfig", v);
    ((F1s)vneed("VNL_UpdateAdapterFromConfig"))(NULL);
    restart_services(dhcp, is_nat);
    int need = 0x100 | (is_nat ? 0x10000 : 0) | (dhcp ? 0x1000000 : 0);
    int f = 0;
    for (int t = 0; t < 10; t++) { /* adapter/NAT bits settle asynchronously */
        f = features(v);
        if (f >= 0 && (f & need) == need) break;
        sleep_ms(2000);
    }
    if (f < 0) f = 0;
    printf("  %s: features=0x%08x\n", (f & need) == need ? "OK" : "WARNING", f);
}


void cmd_edit(void)
{
    int n = parse_vnet(opt_str("--vnet"));
    require_vnet(n);
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
        }
        else if (!strcmp(t, "hostonly")) {
            ensure_nat(v, 0);
            nat_changed = 1;
            if (!nic_present_vmnet(n)) {
                install_adapter(v, n);
                char p[256];
                snprintf(p, sizeof p, "%s\\%s\\Adapter", CFG, v);
                reg_set_dword(p, "UseAdapter", 1);
            }
        }
        else { /* bridged: strip NAT/DHCP/adapter; bind a NIC with `bridged` */
            ensure_nat(v, 0);
            v1i("VNL_SetVnetUseDHCP", v, 0);
            nat_changed = dhcp_changed = 1;
            if (nic_present_vmnet(n) || reg_flag(v, "Adapter")) uninstall_adapter(v, n);
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
        }
        else {
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
    // clang-format off
    const struct { const char *flag; int pid; const char *label; } DP[] = {
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
    int f_end = features(v);
    printf("  features=0x%08x\n", f_end < 0 ? 0 : f_end);
}


void cmd_bridged(void)
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
        if (nn < 64) { snprintf(names[nn], sizeof names[0], "%.*s", (int)sizeof nics[i].name - 1, nics[i].name); nn++; }
        if (!strcmp(nics[i].name, adapter)) snprintf(guid, sizeof guid, "%.*s", (int)sizeof nics[i].guid - 1, nics[i].guid);
    }
    if (!guid[0]) {
        for (int i = 1; i < nn; i++)           /* sorted listing */
            for (int j = i; j > 0 && strcmp(names[j], names[j - 1]) < 0; j--) {
                char t[160];
                snprintf(t, sizeof t, "%s", names[j]);
                snprintf(names[j], sizeof names[j], "%s", names[j - 1]);
                snprintf(names[j - 1], sizeof names[j - 1], "%s", t);
            }
        char avail[8192] = "";
        for (int i = 0; i < nn; i++) {
            size_t l = strlen(avail);
            if (l + 160 >= sizeof avail) { strncat(avail, ", ...", sizeof avail - l - 1); break; }  // nosemgrep: c.lang.security.insecure-use-strcat-fn.insecure-use-strcat-fn
            strncat(avail, i ? ", " : "", sizeof avail - l - 1);  // nosemgrep: c.lang.security.insecure-use-strcat-fn.insecure-use-strcat-fn
            strncat(avail, names[i], sizeof avail - strlen(avail) - 1);  // nosemgrep: c.lang.security.insecure-use-strcat-fn.insecure-use-strcat-fn
        }
        die("ERROR: no network interface named '%s' on this host. Available: %s",
            adapter, avail);
    }
    int want = opt_str("--vnet") ? parse_vnet(opt_str("--vnet")) : -1;
    if (want >= 0) require_vnet(want);
    if (want == 0)
        die("vmnet0 is the built-in bridge segment; it cannot be pinned");
    int seg;
    if (want >= 0) {
        seg = want;
    } else {
        Pin pins[64];
        int np = pins_get(pins, 64);
        int c = vnet_count();
        for (seg = 2; seg < c; seg++)
            if (!vnet_pinned(pins, np, seg) && !vnet_in_use(seg)) break;
        if (seg == c) die("no free vmnet segment (2..%d)", c - 1);
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


void cmd_unpin(void)
{
    int want = parse_vnet(opt_str("--vnet"));
    require_vnet(want);
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


void cmd_autobridge(int dry_run)
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
            if (!dup) { snprintf(named_dn[nn], sizeof named_dn[nn], "%s", dn); named_vn[nn] = k; nn++; }
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
            int cmax = vnet_count();
            for (seg = 2; seg < cmax; seg++) {
                if (vnet_pinned(pins, np, seg)) continue;
                int taken = 0;
                for (int q = 0; q < nplanned; q++) taken |= planned[q] == seg;
                if (taken || vnet_in_use(seg)) continue;
                break;
            }
            if (seg == cmax) {
                printf("ERROR: no free vmnet segment (2..%d) for %s\n", cmax - 1,
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
            if (np < 64) { snprintf(pins[np].guid, sizeof pins[np].guid, "%.*s", (int)sizeof nics[i].guid - 1, nics[i].guid); pins[np++].vnet = seg; }
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

