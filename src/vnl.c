/* vnl.c - vnetlib.dll loading + the VNL_* calling layer (vlstr discipline lives here) */
#include "vmnet.h"

/* --------------------------------------------------------------- vnetlib */
static HMODULE g_vl;


void vl_init(void)
{
    g_vl = LoadLibraryA(VL_PATH);
    if (!g_vl) {
        /* fall back to the registered install path */
        char dir[MAX_PATH] = "";
        DWORD sz = sizeof(dir);
        HKEY k;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Workstation", 0,
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


void *vfn(const char *name)
{
    return (void *)GetProcAddress(g_vl, name); /* NULL = not exported */
}

void *vneed(const char *name)
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

WCHAR *vlwide(const char *s) /* wide scratch: VNL WCHAR* args get padded
                                  in place like the char* ones (RECON §9) */
{
    static WCHAR scratch[4][512];
    static int si;
    WCHAR *b = scratch[(si++) & 3];
    memset(b, 0, sizeof scratch[0]);
    if (s) MultiByteToWideChar(CP_ACP, 0, s, -1, b, 511);
    return b;
}

char *vlstr(const char *s)
{
    char *b = VL_SCRATCH[(vl_si++) & 7];
    memset(b, 0, 512);
    // nosemgrep: c.lang.security.insecure-use-string-copy-fn.insecure-use-string-copy-fn
    if (s) strncpy(b, s, 511);
    return b;
}


int v0(const char *fn)
{
    F0 f = (F0)vfn(fn);
    return f ? f() : 2; /* 2 = "not implemented here" -> callers fall back */
}

int v1(const char *fn, const char *v)
{
    F1s f = (F1s)vfn(fn);
    if (!f) die("vnetlib: missing export %s", fn);
    return f(vlstr(v));
}

int v1i(const char *fn, const char *v, int i)
{
    F1si f = (F1si)vfn(fn);
    if (!f) die("vnetlib: missing export %s", fn);
    return f(vlstr(v), i);
}

int v1s(const char *fn, const char *v, const char *s)
{
    F1ss f = (F1ss)vfn(fn);
    if (!f) die("vnetlib: missing export %s", fn);
    return f(vlstr(v), s ? vlstr(s) : NULL);
}

int vfeat(const char *v, int *f)
{
    return ((F1sip)vneed("VNL_GetVNetFeatures"))(vlstr(v), f);
}

int vgs(const char *fn, const char *v, char *buf, int len)
{
    static char out[512]; /* vnetlib may normalize past len, like
                                      the vnet arg — use a big scratch out */
    if (len <= 0) return 0;
    int l = 512;
    memset(out, 0, sizeof out); /* vnetlib may not write at all: never leak */
    int rc = ((F3s)vneed(fn))(vlstr(v), out, &l);
    buf[0] = 0;
    if (rc == 0 || rc == 1) {
        out[511] = 0;
        // nosemgrep: c.lang.security.insecure-use-string-copy-fn.insecure-use-string-copy-fn
        strncpy(buf, out, (size_t)len - 1);
        buf[len - 1] = 0;
    }
    return (int)strlen(buf);
}

int features(const char *vnet) /* -1 when unreadable */
{
    int f = 0;
    return vfeat(vnet, &f) == 1 ? f : -1;
}

void get_str(const char *fn, const char *vnet, char *out, int outlen)
{
    out[0] = 0;
    if (outlen > 512) outlen = 512;
    vgs(fn, vnet, out, outlen);
}

int set_str(const char *fn, const char *vnet, const char *val)
{
    return v1s(fn, vnet, val);
}

int set_dhcp_param(const char *vnet, int pid, const char *val)
{
    return ((F4)vneed("VNL_SetDHCPParam"))(vlstr(vnet), pid, val ? vlstr(val) : NULL,
                                           val ? (int)strlen(val) : 0);
}


/* ------------------------------------------------------- high-level ops */
int vnet_count(void)
{
    return v0("VNL_GetNumberOfVnets");
}

/* VNL resolves out-of-range names by clamping (reads return another
   segment's features; setters validate), so every command that targets a
   specific --vnet must range-check before touching anything. */
void require_vnet(int n)
{
    int c = vnet_count();
    if (n < 0 || n >= c) die("vmnet%d is not a valid segment (0..%d)", n, c - 1);
}


void vnetstr(int n, char *out)
{
    snprintf(out, 64, "vmnet%d", n);
}


int vnet_in_use(int n)
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


/* does vmnetnat.conf currently render `device = <vnet>`? */
static int conf_device_is(const char *vnet)
{
    FILE *f = fopen("C:\\ProgramData\\VMware\\vmnetnat.conf", "r");
    if (!f) return 0;
    char line[256], dev[64] = "";
    while (fgets(line, sizeof line, f))
        sscanf(line, " device = %63s", dev);
    fclose(f);
    return !strcmp(dev, vnet);
}


void regen_nat_conf(void)
{
    char v[64];
    int cnt = vnet_count();
    if (cnt < 0 || cnt > 256) cnt = 256; /* never trust a wild bound mid-loop */
    int last = -1;
    for (int n = 2; n < cnt; n++) {
        vnetstr(n, v);
        int f = features(v);
        if (reg_flag(v, "NAT") || (f > 0 && (f & 0x10000))) {
            v1("VNL_UpdateNATFromConfig", v);
            last = n;
        }
    }
    /* UpdateNATFromConfig rewrites the WHOLE file: the last vnet processed
       wins, but vnetlib intermittently no-ops the call (internal-lock
       serialization, rc ignored) and leaves the conf rendering a removed
       vnet — proven live. Verify the final render; retry it if stale. */
    if (last >= 0) {
        vnetstr(last, v);
        for (int t = 0; t < 3 && !conf_device_is(v); t++) {
            sleep_ms(1000);
            v1("VNL_UpdateNATFromConfig", v);
        }
        if (!conf_device_is(v)) fprintf(stderr, "warning: vmnetnat.conf stale after regen\n");
    }
}


void ensure_nat(const char *vnet, int on)
{
    v1i("VNL_SetVnetUseNAT", vnet, on ? 1 : 0);
    if (on && !reg_flag(vnet, "NAT")) {
        /* VNL_SetVnetUseNAT does not create the NAT subkey for a fresh vnet */
        char path[256];
        snprintf(path, sizeof path, "%s\\%s\\NAT", CFG, vnet);
        reg_set_dword(path, "UseNAT", 1);
    }
}


void bits_str(int f, char *out, int outlen)
{
    // clang-format off
    const struct { int bit; const char *name; } B[] = {
        { 0x1, "bridged" }, { 0x100, "hostonly-adapter" },
        { 0x10000, "nat" }, { 0x1000000, "dhcp" } };
    out[0] = 0;
    for (int i = 0; i < 4; i++)
        if (f & B[i].bit) {
            size_t l = strlen(out);
            if (l + 24 >= (size_t)outlen) break;   /* full: stop, never wrap */
            if (l) { out[l++] = ','; out[l++] = ' '; out[l] = 0; }
            strncat(out, B[i].name, (size_t)outlen - l - 1);  // nosemgrep: c.lang.security.insecure-use-strcat-fn.insecure-use-strcat-fn
        }
}


int pick_vnet(int n)
{
    if (n >= 0) return n;
    Pin pins[64];
    int np = pins_get(pins, 64);
    int c = vnet_count();
    for (int k = 2; k < c; k++)
        if (!vnet_pinned(pins, np, k) && !vnet_in_use(k)) return k;
    die("no free vmnet segment (2..%d)", c - 1);
    return -1;
}


