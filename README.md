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

## Layout

```
src/     C sources, headers, objcopy symbol maps
havoc/   Havoc Script Manager scripts
bin/     build output (not tracked in git -- run `make` to produce it)
```

## Build

Requires the MinGW-w64 cross compiler:

```bash
apt install gcc-mingw-w64-x86-64
```

```bash
make
```

`make` compiles both BOFs into `bin/` and then verifies each object: valid
x86-64 COFF, `go()` entry point exported, empty `.bss`, no plaintext strings,
no leftover symbol names, no `BeaconFormat*` references. Any failed check
fails the build.

## Install

Build first -- `bin/` is not tracked in git, so a fresh clone has no objects.

```bash
make
cp -r NOFILTER-NFEXEC/ /usr/share/havoc/data/extensions/NOFILTER-NFEXEC/
# Load havoc/nofilter.py and havoc/nfexec.py in Havoc Script Manager
```

`BOF_DIR` at the top of each script points at the installed `bin/` directory;
edit it if you install somewhere else.

## Acknowledgments

The NOFILTER privilege escalation technique was discovered and presented by **Ron Ben-Yizhak** ([@RonB_Y](https://twitter.com/RonB_Y)), Security Researcher at **Deep Instinct**, at DEF CON 31 (August 2023). This implementation would not exist without his outstanding research into the Windows Filtering Platform internals.

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
