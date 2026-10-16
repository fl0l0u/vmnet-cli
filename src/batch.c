/* SPDX-License-Identifier: Apache-2.0 */
/* batch.c - stage/apply context: multi-network ops pay every wait ONCE */
#include "vmnet.h"

void batch_new(Batch *b)
{
    memset(b, 0, sizeof *b);
}


int set_has(const int *s, int c, int n)
{
    for (int i = 0; i < c; i++)
        if (s[i] == n) return 1;
    return 0;
}


int remove_stage(int n, Batch *b)
{
    char v[64];
    vnetstr(n, v);
    int f = features(v);
    if (f < 0) f = 0;
    Pin pins[64];
    int np = pins_get(pins, 64), pinned = 0;
    for (int i = 0; i < np; i++)
        pinned |= pins[i].vnet == n;
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
    printf("* removing %s%s%s%s\n", v, bits[0] ? " (" : "", bits, bits[0] ? ")" : "");
    if (b->nvn < 24) b->vnets[b->nvn++] = n;
    else
        fprintf(stderr, "warning: batch report capped at 24 networks\n");
    for (int i = 0; i < np; i++)
        if (pins[i].vnet == n) {
            pins_del(pins[i].guid);
            printf("  - unbound %s\n", pins[i].guid);
            b->bridge = 1;
        }
    if (had_adapter) {
        uninstall_adapter_start(v, n);
        if (b->ngone < 24) b->gone[b->ngone++] = n;
        else
            fprintf(stderr, "warning: adapter wait capped at 24\n");
    }
    LONG dr = reg_delete_tree(cfgpath);
    printf("  - deleted VMnetConfig\\%s%s\n", v, dr ? " (FAILED!)" : "");
    if (had_dhcp) {
        int rc = v1("VNL_UpdateDHCPFromConfig", v);
        printf("  - vmnetdhcp.conf regenerated: %s\n", rcs(rc));
        b->dhcp = 1;
    }
    if (had_nat) b->nat = 1; /* whole-file rewrite — once at apply */
    return 1;
}

/* One wait for all PnP operations, one NAT conf regen, one service restart,
   one bridge cycle — regardless of batch size. */

void batch_apply(Batch *b)
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
        for (int i = 0; i < np_; i++)
            pend[i] = b->added[i];
        for (int t = 0; t < 10 && np_; t++) { /* PnP completes async */
            sleep_ms(3000);
            int present[64], np = nic_present_set(present, 64);
            int k = 0;
            for (int i = 0; i < np_; i++)
                if (!set_has(present, np, pend[i])) pend[k++] = pend[i];
            np_ = k;
        }
        for (int i = 0; i < np_; i++)
            drvinst_install(pend[i]);
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
                   set_has(present, np, b->added[i]) ? "ok" : "pending/failed (PnP is async)");
    }
    if (b->dhcp || b->nat) restart_services(b->dhcp, b->nat);
    if (b->bridge) cycle_bridge();
    for (int i = 0; i < b->nvn; i++) {
        char v[64];
        vnetstr(b->vnets[i], v);
        int left = features(v);
        printf("  %s: %s features now 0x%08x\n", left == 0 ? "OK" : "WARNING", v,
               left < 0 ? 0 : left);
    }
}
