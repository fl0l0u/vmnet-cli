/* SPDX-License-Identifier: Apache-2.0 */
/* vmnet.h - VMware virtual-network CLI, internal interface.
 *
 * Reverse-engineered surface: vnetlib.dll's VNL_* exports (see RECON.md).
 * Two invariants every module must honor:
 *   - every string passed to VNL_* goes through vlstr() (>=512-byte zeroed
 *     scratch): vnetlib zero-pads fixed-width string args IN PLACE.
 *   - most VNL calls return rc=1 for success; getters may write past their
 *     out-buffer's length field — out buffers must be big and pre-zeroed.
 */
#ifndef VMNET_H
#define VMNET_H

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#ifndef REG_LITE /* RegSaveKeyEx flag, absent from MinGW headers */
#define REG_LITE 1
#endif
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
#include <errno.h>

/* ---- shared constants (defined in util.c) ---- */
extern const char *VL_PATH;
extern const char *VMWARE_DIR;
extern const char *BRIDGE_TABLE;
extern const char *CFG;
extern const char *NET_CLASS;

/* ---- shared types ---- */
typedef int (*F0)(void);
typedef int (*F1s)(const char *);
typedef int (*F1si)(const char *, int);
typedef int (*F1ss)(const char *, const char *);
typedef int (*F1sip)(const char *, int *);
typedef int (*F3s)(const char *, char *, int *);
typedef int (*F4)(const char *, int, const char *, int);
typedef int (*F5i)(const char *, void *, int, int, int *);
typedef int (*F3u)(const char *, void *, int *);
typedef int (*F7pf)(const char *, int, unsigned short, const char *, unsigned short, const WCHAR *,
                    int);
/* bridge pins: {guid: vnet} from the driver's Adapters subkeys */
// clang-format off
typedef struct { char guid[64]; int vnet; } Pin;
// clang-format on
/* ------------------------------------------------------ adapter inventory */
typedef struct {
    char guid[64]; /* connection GUID, uppercased (= bridge pin key) */
    char name[160]; /* FriendlyName */
    char desc[192]; /* InterfaceDescription */
    int ifindex;
    int iftype;
} Nic;
/* ---------------- batch context: one wait/restart per command ------------- */
typedef struct {
    int dhcp, nat, bridge;
    int gone[24], ngone; /* adapter removals kicked */
    int added[24], nadded; /* adapter installs kicked */
    int vnets[24], nvn; /* vnets to report features for at the end */
} Batch;

/* ---- module interfaces ---- */
/* util.c */
_Noreturn void die(const char *fmt, ...);
const char *rcs(int rc);
void *xmalloc(size_t n);
void upper(char *s);
int ci_contains(const char *hay, const char *needle);
int ends_with(const char *s, const char *suffix);
void w2u8(const WCHAR *w, char *out, int outlen);
WCHAR *u82w(const char *s);
void sleep_ms(int ms);
int run_hidden(const char *cmdline);
void vl_init(void);
void *vfn(const char *name);
void *vneed(const char *name);
char *vlstr(const char *s);
WCHAR *vlwide(const char *s);
int v0(const char *fn);
int v1(const char *fn, const char *v);
int v1i(const char *fn, const char *v, int i);
int v1s(const char *fn, const char *v, const char *s);
int vfeat(const char *v, int *f);
int vgs(const char *fn, const char *v, char *buf, int len);
int features(const char *vnet) /* -1 when unreadable */;
void get_str(const char *fn, const char *vnet, char *out, int outlen);
int set_str(const char *fn, const char *vnet, const char *val);
int set_dhcp_param(const char *vnet, int pid, const char *val);
LONG ropen(const char *path, ACCESS_MASK acc, HKEY *k);
int reg_get_dword(const char *path, const char *name, DWORD *val);
int reg_get_sz(const char *path, const char *name, char *buf, DWORD bsz);
void reg_set_dword(const char *path, const char *name, DWORD val);
void reg_set_sz(const char *path, const char *name, const char *val);
int reg_exists(const char *path);
LONG reg_delete_tree(const char *path);
int reg_flag(const char *vnet, const char *sub);
int pins_get(Pin *out, int max);
int pin_of(const Pin *pins, int npins, const char *guid, int *vn);
int vnet_pinned(const Pin *pins, int npins, int n);
void pins_set(const char *guid, int vnet);
void pins_del(const char *guid);
void svc_wait(SC_HANDLE s, DWORD want, int seconds);
void svc_action(const WCHAR *name, int start);
void svc_stop_start(const WCHAR *name);
void cycle_bridge(void);
void restart_services(int dhcp, int nat);
int nic_list(Nic *out, int max);
int nic_present_vmnet(int n);
int pmt_for_guid(const char *guid);
void bus_of_desc(const char *desc, char *bus, int buslen);
int classify_nics(Nic *out, int max);
int vnet_count(void);
void require_vnet(int n);
void vnetstr(int n, char *out);
int vnet_in_use(int n);
void regen_nat_conf(void);
void ensure_nat(const char *vnet, int on);
void drvinst_install(int n);
void install_adapter_start(const char *vnet);
int install_adapter_finish(const char *vnet, int n);
int install_adapter(const char *vnet, int n);
void pnputil_remove_vmnet(int n);
void uninstall_adapter_start(const char *vnet, int n);
int uninstall_adapter_finish(int n) /* 1 = device gone */;
void uninstall_adapter(const char *vnet, int n);
void batch_new(Batch *b);
int set_has(const int *s, int c, int n);
int nic_present_set(int *out, int max);
void subnet_host1(const char *subnet, char *out, int outlen);
const char *opt_str(const char *flag);
int opt_flag(const char *flag);
int parse_vnet(const char *s) /* accepts "2" and "vmnet2" */;
void cmd_adapters(void);
void bits_str(int f, char *out, int outlen);
void cmd_list(void);
int pick_vnet(int n);
void cmd_add(const char *kind);
void cmd_edit(void);
void cmd_setip(void);
void enable_privilege(const WCHAR *name);
void require_elevated(void);
int cmd_export(void);
void copy_tree(HKEY src, HKEY dst);
int cmd_import(void);
void cmd_bridged(void);
void cmd_unpin(void);
void cmd_autobridge(int dry_run);
void cmd_natfw(const char *action);
void cmd_natcfg(const char *action);
int remove_stage(int n, Batch *b);
void batch_apply(Batch *b);
void cmd_remove(void);
void cmd_clear(void);
void cmd_restore(void);
int main(int argc, char **argv);

extern int g_argc;
extern char **g_argv;

#endif /* VMNET_H */
