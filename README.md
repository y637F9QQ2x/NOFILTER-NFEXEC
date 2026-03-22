# NOFILTER-NFEXEC

> Havoc C2 BOF — WFP kernel-space SYSTEM escalation + command execution with indirect syscalls, patchless AMSI/ETW bypass, and return address spoofing

## Usage

```bash
# Step 1: Escalate to SYSTEM
nofilter                              # auto-detect SYSTEM process
nofilter -p <pid>                     # specify target PID
token getuid                          # verify: NT AUTHORITY\SYSTEM (Admin)

# Step 2: Run commands as SYSTEM
nfexec whoami                         # auto → exec mode
nfexec whoami /priv                   # auto → exec mode
nfexec ipconfig /all                  # auto → exec mode
nfexec Get-Process lsass              # auto → PS mode
nfexec dir C:\Windows                 # auto → PS mode
nfexec -exec C:\tools\tool.exe        # force exec mode
nfexec -ps [Environment]::UserName    # force PS mode

# Revert
token revert                          # drop back to original context
```

nfexec auto-detects ~100 native commands (whoami, ipconfig, net, sc, reg, ...) and routes them to exec mode. Everything else goes to PS mode. Use `-ps` or `-exec` to override.

## Demo

![NOFILTER-NFEXEC_DEMO](https://github.com/user-attachments/assets/76efa4a3-a337-4314-bac5-6847e84f1a92)

## OPSEC

### NOFILTER

| Property | Detail |
|---|---|
| Token duplication | Kernel-space via tcpip.sys IOCTLs (user-mode hooks not triggered) |
| Syscalls | All Nt* via Havoc NtApi[] indirect syscall |
| Static signatures | XOR-encoded strings (WfpAle, lsass, services, BFE, File, Token) |
| Symbol table | 20 symbols sanitized via objcopy |
| Error messages | Opaque codes only ([!] E01–E11, [+] S1–S9) |
| Memory scrubbing | Decoded strings zeroed on stack after use |
| KERNEL32 imports | Zero |

### NFEXEC

| Property | Detail |
|---|---|
| AMSI | HWBP DR0 + VEH: result=CLEAN, RAX=S_OK (patchless) |
| ETW | HWBP DR1 + VEH: RAX=0 (patchless) |
| Memory modification | None |
| Indirect syscall | PEB walk + Halo's Gate SSN + syscall;ret gadget in ntdll |
| Return address spoofing | Stack frame points to ntdll ret gadget, not BOF memory |
| Function resolution | FNV-1a hash — no function name strings in binary |
| ADVAPI32 imports | Zero (CreateProcessWithTokenW resolved via PEB walk) |
| KERNEL32 imports | 5 only (pipe I/O + string conversion, irreplaceable) |
| Static signatures | XOR-encoded function names, zero IOC strings in .rdata |
| Symbol table | 34 symbols sanitized via objcopy |
| Error messages | Opaque codes only ([!] E00–E19) |
| Memory scrubbing | ScScrub zeros ntdll base/gadget/SSN; STARTUPINFO + cmdline zeroed |
| CLM bypass | Custom Runspace = FullLanguage |
| AppDomain | Random name per execution |

## Install

```bash
cp -r NOFILTER/ /usr/share/havoc/data/extensions/NOFILTER/
# Load nofilter.py and nfexec.py in Havoc Script Manager
```

## Build

```bash
make
```

## How It Works

### NOFILTER

<!-- TODO: Replace with GitHub image URL after upload -->
![nofilter-flow](https://github.com/y637F9QQ2x/NOFILTER-NFEXEC/blob/main/nofilter-flow.svg)

### NFEXEC

<!-- TODO: Replace with GitHub image URL after upload -->
![nfexec-flow](https://github.com/y637F9QQ2x/NOFILTER-NFEXEC/blob/main/nfexec-flow.svg)

## OPSEC Details

### NOFILTER

<!-- TODO: Replace with GitHub image URL after upload -->
![nofilter-opsec](https://github.com/y637F9QQ2x/NOFILTER-NFEXEC/blob/main/nofilter-opsec.svg)

### NFEXEC

<!-- TODO: Replace with GitHub image URL after upload -->
![nfexec-opsec](https://github.com/y637F9QQ2x/NOFILTER-NFEXEC/blob/main/nfexec-opsec.svg)

## Acknowledgments

The NOFILTER privilege escalation technique was discovered and presented by **Ron Ben-Yizhak** ([@RonB_Y](https://twitter.com/RonB_Y)), Security Researcher at **Deep Instinct**, at [DEF CON 31](https://defcon.org/html/defcon-31/dc-31-speakers.html) (August 2023). This implementation would not exist without his outstanding research into the Windows Filtering Platform internals.

- **DEF CON 31 talk**: [#NoFilter: Abusing Windows Filtering Platform for Privilege Escalation](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Ron%20Ben-Yizhak%20-%20NoFilter%20Abusing%20Windows%20Filtering%20Platform%20for%20privilege%20escalation.pdf)
- **Deep Instinct blog**: [NoFilter — Abusing Windows Filtering Platform for Privilege Escalation](https://www.deepinstinct.com/blog/nofilter-abusing-windows-filtering-platform-for-privilege-escalation)
- **Original tool**: [deepinstinct/NoFilter](https://github.com/deepinstinct/NoFilter)

Microsoft MSRC was notified and classified this behavior as by-design.

## Third-Party

PowershellRunner.h contains a .NET assembly from [HavocFramework/Modules](https://github.com/HavocFramework/Modules) (PowerPick), licensed under GPLv3. See LICENSE for details.

## License

MIT (see LICENSE for third-party components)

## Disclaimer

For **authorized penetration testing and red team operations only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal.
