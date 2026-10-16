/* SPDX-License-Identifier: Apache-2.0 */
/* main.c - entry point: command dispatch */
#include "vmnet.h"

/* ------------------------------------------------------------------ main */
int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 2) {
        fprintf(stderr, "usage: vmnet-cli <adapters|list|add|bridged|edit|set-ip|natfw|"
                        "natcfg|remove|clear|unpin|autobridge|restore-defaults|export|import>\n");
        return 2;
    }
    g_argc = argc;
    g_argv = argv;
    require_elevated();
    vl_init();
    const char *cmd = argv[1];
    const char *sub = argc > 2 ? argv[2] : NULL;
    // clang-format off
    if (!strcmp(cmd, "adapters"))            cmd_adapters();
    else if (!strcmp(cmd, "list"))           cmd_list();
    else if (!strcmp(cmd, "add")) {
        if (!sub || (strcmp(sub, "hostonly") && strcmp(sub, "nat")))
            die("add needs a kind: hostonly or nat");
        cmd_add(sub);
    }
    else if (!strcmp(cmd, "bridged"))        cmd_bridged();
    else if (!strcmp(cmd, "edit"))           cmd_edit();
    else if (!strcmp(cmd, "set-ip"))         cmd_setip();
    else if (!strcmp(cmd, "export"))         return cmd_export();
    else if (!strcmp(cmd, "import"))         return cmd_import();
    else if (!strcmp(cmd, "unpin"))          cmd_unpin();
    else if (!strcmp(cmd, "remove"))         cmd_remove();
    else if (!strcmp(cmd, "clear") || !strcmp(cmd, "flush")) cmd_clear();
    else if (!strcmp(cmd, "restore-defaults")) cmd_restore();
    else if (!strcmp(cmd, "autobridge"))     cmd_autobridge(opt_flag("--dry-run"));
    else if (!strcmp(cmd, "natfw")) {
        if (!sub || (strcmp(sub, "list") && strcmp(sub, "add") && strcmp(sub, "remove")))
            die("natfw needs an action: list, add or remove");
        cmd_natfw(sub);
    }
    else if (!strcmp(cmd, "natcfg")) {
        if (!sub || (strcmp(sub, "show") && strcmp(sub, "set")))
            die("natcfg needs an action: show or set");
        cmd_natcfg(sub);
    }
    else die("unknown command '%s'", cmd);
    // clang-format on
    return 0;
}
