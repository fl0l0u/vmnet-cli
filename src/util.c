/* SPDX-License-Identifier: Apache-2.0 */
/* util.c - small shared helpers: fatal error, string/file/locale glue, subprocess */
#include "vmnet.h"

const char *VL_PATH = "C:\\Program Files\\VMware\\VMware Workstation\\vnetlib.dll";

const char *VMWARE_DIR = "C:\\Program Files\\VMware\\VMware Workstation";

const char *BRIDGE_TABLE = "SYSTEM\\CurrentControlSet\\Services\\VMnetBridge\\Parameters\\Adapters";

const char *CFG = "SOFTWARE\\VMware, Inc.\\VMnetLib\\VMnetConfig";

const char *NET_CLASS = "SYSTEM\\CurrentControlSet\\Control\\Class"
                        "\\{4d36e972-e325-11ce-bfc1-08002be10318}";


/* ------------------------------------------------------------------ utils */
_Noreturn void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}


/* "ok" for rc==1, else the actual rc for diagnostics. */
const char *rcs(int rc)
{
    static char b[16];
    if (rc == 1) return "ok";
    snprintf(b, sizeof b, "rc=%d", rc);
    return b;
}


void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p) die("out of memory");
    return p;
}


void upper(char *s)
{
    for (; *s; s++)
        if (*s >= 'a' && *s <= 'z') *s -= 32;
}


int ci_contains(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (size_t i = 0; hay[i]; i++)
        if (_strnicmp(hay + i, needle, n) == 0) return 1;
    return 0;
}


int ends_with(const char *s, const char *suffix)
{
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}


void w2u8(const WCHAR *w, char *out, int outlen)
{
    out[0] = 0; /* WideCharToMultiByte writes NOTHING on failure — never
                      leave the caller's buffer unterminated */
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outlen, NULL, NULL)) out[outlen - 1] = 0;
}


WCHAR *u82w(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    WCHAR *w = xmalloc(((size_t)n + 64) * sizeof(WCHAR));
    memset(w, 0, ((size_t)n + 64) * sizeof(WCHAR)); /* fixed-field slack */
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}


void sleep_ms(int ms)
{
    Sleep((DWORD)ms);
}


/* Run a command line synchronously (hidden window), return exit code or -1. */
int run_hidden(const char *cmdline)
{
    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessA(NULL, (char *)cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si,
                        &pi))
        return -1;
    if (WaitForSingleObject(pi.hProcess, 120000) == WAIT_TIMEOUT)
        TerminateProcess(pi.hProcess, 1); /* never leave a child running */
    DWORD code = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
}


/* ------------------------------------------------------------ arg parsing */
void subnet_host1(const char *subnet, char *out, int outlen)
{
    snprintf(out, (size_t)outlen, "%s", subnet);
    char *dot = strrchr(out, '.');
    if (dot) snprintf(dot + 1, (size_t)(out + outlen - dot - 1), "1");
    else
        snprintf(out, (size_t)outlen, "0.0.0.1");
}


void enable_privilege(const WCHAR *name)
{
    HANDLE t;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) return;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(t, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(t);
}

/* Same test vmnetcfg.exe applies (CheckTokenMembership on the
 * Administrators alias): true only for a full elevated admin token.
 * SYSTEM is NOT required; Network Configuration Operators is NOT enough
 * (no service start/stop, no HKLM writes, no SeLoadDriverPrivilege enabled). */
void require_elevated(void)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID adm;
    BOOL is = FALSE;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0,
                                 0, 0, 0, 0, &adm)) {
        CheckTokenMembership(NULL, adm, &is);
        FreeSid(adm);
    }
    if (!is)
        die("must run elevated as an Administrator (elevated prompt or "
            "Run as administrator); SYSTEM not required");
}
