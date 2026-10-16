/* SPDX-License-Identifier: Apache-2.0 */
/* cmds_remove.c - commands: remove, clear/flush, restore-defaults */
#include "vmnet.h"

void cmd_remove(void)
{
    int vn[24], nv = 0;
    for (int i = 1; i < g_argc - 1; i++)
        if (strcmp(g_argv[i], "--vnet") == 0) {
            if (nv < 24) vn[nv++] = parse_vnet(g_argv[++i]);
            else {
                fprintf(stderr, "warning: only 24 --vnet args honored\n");
                i++;
            }
        }
    if (!nv) die("remove needs --vnet");
    for (int i = 0; i < nv; i++) { /* validate before touching anything */
        require_vnet(vn[i]);
        if (vn[i] == 0) die("vmnet0 is the built-in bridge segment and cannot be removed");
        if ((vn[i] == 1 || vn[i] == 8) && !opt_flag("--force"))
            die("vmnet%d is a stock Workstation network; pass --force to "
                "remove it anyway",
                vn[i]);
    }
    Batch b;
    batch_new(&b);
    for (int i = 0; i < nv; i++)
        remove_stage(vn[i], &b);
    batch_apply(&b);
}

/* Remove EVERY vmnet network — custom AND stock vmnet1/vmnet8. vmnet0 (the
   VMnetBridge driver's auto-bridge segment) is not removable and stays. */

void cmd_clear(void)
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
            continue; /* silent segment: nothing to do */
        remove_stage(n, &b);
    }
    batch_apply(&b);
}


void cmd_restore(void)
{
    if (!opt_flag("--force")) die("restore-defaults removes ALL custom networks; pass --force");
    printf("* restoring default networks (vmnet0 auto-bridge, vmnet1 "
           "host-only, vmnet8 NAT)\n");
    Batch b;
    batch_new(&b);
    for (int n = 2; n < vnet_count(); n++) {
        if (n == 8) continue; /* vmnet1 unreachable from n>=2; vmnet8 is a live NAT net */
        char path[256], v[64];
        vnetstr(n, v);
        snprintf(path, sizeof path, "%s\\%s", CFG, v);
        if (reg_exists(path)) remove_stage(n, &b);
    }
    // clang-format off
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


