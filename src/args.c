/* SPDX-License-Identifier: Apache-2.0 */
/* args.c - argv accessors shared by the command implementations */
#include "vmnet.h"

int g_argc;

char **g_argv;


const char *opt_str(const char *flag)
{
    for (int i = 1; i < g_argc; i++)
        if (strcmp(g_argv[i], flag) == 0) {
            if (i + 1 >= g_argc) die("%s requires a value", flag);
            return g_argv[i + 1];
        }
    return NULL;
}

int opt_flag(const char *flag)
{
    for (int i = 1; i < g_argc; i++)
        if (strcmp(g_argv[i], flag) == 0) return 1;
    return 0;
}


int parse_vnet(const char *s) /* accepts "2" and "vmnet2", nothing else */
{
    if (!s) die("this command needs --vnet");
    const char *orig = s;
    while (*s && *s != '-' && (*s < '0' || *s > '9')) {
        if ((*s < 'a' || *s > 'z') && (*s < 'A' || *s > 'Z')) break;
        s++;
    }
    if (*s < '0' || *s > '9')
        die("expected a segment number or name (e.g. 2 or vmnet2), got '%s'", orig);
    errno = 0;
    char *end;
    long v = strtol(s, &end, 10);
    if (*end || errno == ERANGE || v < 0 || v > 1000000)
        die("expected a segment number or name (e.g. 2 or vmnet2), got '%s'", orig);
    return (int)v;
}
