#include "safeToolhelp.h"
#include "safeApi.h"
#include <winternl.h>
#include <iostream>

typedef struct _UNICODE_STRING_T {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_T;

typedef struct _SYSTEM_PROCESS_INFORMATION_T {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING_T ImageName;
    ULONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    // 更多字段略
} SYSTEM_PROCESS_INFORMATION_T;

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

static BYTE* g_processSnapshot = nullptr;
static SYSTEM_PROCESS_INFORMATION_T* g_currProc = nullptr;

BOOL SafeCreateProcessSnapshot() {
    if (g_processSnapshot) {
        delete[] g_processSnapshot;
        g_processSnapshot = nullptr;
    }

    _NtQuerySystemInformation NtQuerySystemInformation =
        (_NtQuerySystemInformation)SafeGetProcAddress(L"ntdll.dll", "NtQuerySystemInformation");

    ULONG bufferSize = 0x100000;
    g_processSnapshot = new BYTE[bufferSize];
    if (!g_processSnapshot) return FALSE;

    NTSTATUS status = NtQuerySystemInformation(5 /*SystemProcessInformation*/, g_processSnapshot, bufferSize, NULL);
    if (status < 0) {
        delete[] g_processSnapshot;
        g_processSnapshot = nullptr;
        return FALSE;
    }

    g_currProc = (SYSTEM_PROCESS_INFORMATION_T*)g_processSnapshot;
    return TRUE;
}

BOOL SafeProcess32First(SAFE_PROCESSENTRY32* entry) {
    if (!g_currProc || !entry) return FALSE;
    entry->pid = (DWORD)(ULONG_PTR)g_currProc->UniqueProcessId;
    entry->parentPid = (DWORD)(ULONG_PTR)g_currProc->InheritedFromUniqueProcessId;
    if (g_currProc->ImageName.Buffer) {
        wcsncpy_s(entry->imageName, g_currProc->ImageName.Buffer, _TRUNCATE);
    }
    else {
        wcscpy_s(entry->imageName, L"System Idle Process");
    }
    return TRUE;
}

BOOL SafeProcess32Next(SAFE_PROCESSENTRY32* entry) {
    if (!g_currProc || g_currProc->NextEntryOffset == 0) return FALSE;
    g_currProc = (SYSTEM_PROCESS_INFORMATION_T*)((BYTE*)g_currProc + g_currProc->NextEntryOffset);
    return SafeProcess32First(entry);
}

// Module32 系列（基于目标进程 PEB）
typedef struct _SAFE_MODULE_CONTEXT {
    HANDLE hProcess;
    LIST_ENTRY* head;
    LIST_ENTRY* current;
} SAFE_MODULE_CONTEXT;

static SAFE_MODULE_CONTEXT g_modCtx = { 0 };

BOOL ReadRemotePEBList(DWORD pid) {
    memset(&g_modCtx, 0, sizeof(g_modCtx));

    g_modCtx.hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!g_modCtx.hProcess) return FALSE;

#ifdef _M_X64
    ULONGLONG pebAddress = 0;
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen;
    typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    _NtQueryInformationProcess NtQueryInformationProcess =
        (_NtQueryInformationProcess)SafeGetProcAddress(L"ntdll.dll", "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) return FALSE;
    if (NtQueryInformationProcess(g_modCtx.hProcess, 0, &pbi, sizeof(pbi), &retLen) < 0) return FALSE;

    pebAddress = (ULONGLONG)pbi.PebBaseAddress;

    // 读取 PEB->Ldr
    ULONGLONG ldrAddr = 0;
    if (!ReadProcessMemory(g_modCtx.hProcess, (BYTE*)pebAddress + 0x18, &ldrAddr, sizeof(ldrAddr), NULL)) return FALSE;

    // 读取 Ldr->InMemoryOrderModuleList
    ULONGLONG listAddr = 0;
    if (!ReadProcessMemory(g_modCtx.hProcess, (BYTE*)ldrAddr + 0x20, &listAddr, sizeof(listAddr), NULL)) return FALSE;

    g_modCtx.head = (LIST_ENTRY*)listAddr;
    g_modCtx.current = g_modCtx.head->Flink;

    return TRUE;
#else
    return FALSE; // 略（可补全 32 位结构）
#endif
}

BOOL SafeModule32First(DWORD pid, SAFE_MODULEENTRY32* entry) {
    if (!ReadRemotePEBList(pid)) return FALSE;
    return SafeModule32Next(entry);
}

BOOL SafeModule32Next(SAFE_MODULEENTRY32* entry) {
    if (!g_modCtx.hProcess || !g_modCtx.current || g_modCtx.current == g_modCtx.head)
        return FALSE;

    // 读取 LDR_DATA_TABLE_ENTRY 基本信息
    ULONGLONG modEntryAddr = (ULONGLONG)g_modCtx.current - 0x10;
    BYTE buffer[512] = {};
    if (!ReadProcessMemory(g_modCtx.hProcess, (LPCVOID)modEntryAddr, buffer, sizeof(buffer), NULL)) return FALSE;

    LPVOID base = *(LPVOID*)(buffer + 0x30);
    DWORD size = *(DWORD*)(buffer + 0x40);
    UNICODE_STRING* name = (UNICODE_STRING*)(buffer + 0x58);

    entry->baseAddress = base;
    entry->size = size;
    if (name->Buffer && name->Length > 0) {
        ReadProcessMemory(g_modCtx.hProcess, name->Buffer, entry->moduleName, name->Length, NULL);
        entry->moduleName[name->Length / 2] = 0;
    }

    // 移动下一个
    ULONGLONG next = 0;
    ReadProcessMemory(g_modCtx.hProcess, (BYTE*)g_modCtx.current, &next, sizeof(next), NULL);
    g_modCtx.current = (LIST_ENTRY*)next;
    return TRUE;
}
