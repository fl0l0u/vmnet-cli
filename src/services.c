/* SPDX-License-Identifier: Apache-2.0 */
/* services.c - VMnetDHCP / VMnetNAT / VMnetBridge service control via the SCM */
#include "vmnet.h"

/* --------------------------------------------------------------- services */
void svc_wait(SC_HANDLE s, DWORD want, int seconds)
{
    SERVICE_STATUS st;
    for (int i = 0; i < seconds * 4; i++) {
        if (!QueryServiceStatus(s, &st)) return;
        if (st.dwCurrentState == want) return;
        sleep_ms(250);
    }
}


void svc_action(const WCHAR *name, int start)
{
    SC_HANDLE m = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!m) return;
    SC_HANDLE s = OpenServiceW(m, name, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (s) {
        SERVICE_STATUS st;
        if (start) {
            StartServiceW(s, 0, NULL); /* already running = ok */
            svc_wait(s, SERVICE_RUNNING, 30);
        }
        else {
            ControlService(s, SERVICE_CONTROL_STOP, &st);
            svc_wait(s, SERVICE_STOPPED, 20);
        }
        CloseServiceHandle(s);
    }
    CloseServiceHandle(m);
}


void svc_stop_start(const WCHAR *name)
{
    svc_action(name, 0);
    sleep_ms(2000);
    svc_action(name, 1);
    sleep_ms(3000);
}


/* Reload the bridge driver so it re-reads Parameters\\Adapters bindings. */
void cycle_bridge(void)
{
    svc_stop_start(L"VMnetBridge");
}


/* VNL_Stop/Start* like vmnetcfg.exe does; SCM fallback on failure.
   rc semantics: 1 = success, 0 = genuine failure, 2 = export absent ->
   anything but 1 must fall through to the SCM. */
void restart_services(int dhcp, int nat)
{
    if (dhcp) {
        int rc = v0("VNL_StopDHCP");
        if (rc != 1) svc_action(L"VMnetDHCP", 0);
        sleep_ms(2000);
        rc = v0("VNL_StartDHCP");
        if (rc != 1) svc_action(L"VMnetDHCP", 1);
        sleep_ms(3000);
    }
    if (nat) {
        int rc = v0("VNL_StopNAT");
        if (rc != 1) svc_action(L"VMware NAT Service", 0);
        sleep_ms(2000);
        rc = v0("VNL_StartNAT");
        if (rc != 1) svc_action(L"VMware NAT Service", 1);
        sleep_ms(3000);
    }
}
