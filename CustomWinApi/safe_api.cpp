#include "safe_api.h"
#include <winternl.h>

#ifdef _MSC_VER
#pragma comment(lib, "ntdll.lib")
#endif
#include <cwchar>


HMODULE GetModuleByPEB(const wchar_t* targetName) {
#ifdef _M_X64
    PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
    PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA pLdr = pPEB->Ldr;
    PLIST_ENTRY moduleList = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pStartListEntry = moduleList->Flink;

    for (PLIST_ENTRY pListEntry = pStartListEntry; pListEntry != moduleList; pListEntry = pListEntry->Flink) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        wchar_t* dllName = pEntry->FullDllName.Buffer;
        const wchar_t* currentFileName = wcsrchr(dllName, L'\\');
        if (currentFileName) {
            currentFileName++;
        }
        else {
            currentFileName = dllName;
        }
        if (currentFileName) {
            if (_wcsnicmp(currentFileName, targetName, wcslen(targetName)) == 0) {
                return (HMODULE)pEntry->DllBase;
            }
        }
    }
    return NULL;
}


FARPROC ParseExportByName(HMODULE hModule, LPCSTR lpProcName) {
    if (!hModule || !lpProcName)
        return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA) return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);

    
    if ((ULONG_PTR)lpProcName <= 0xFFFF) {
        WORD ordinal = (WORD)(ULONG_PTR)lpProcName;
        WORD baseOrdinal = (WORD)exportDir->Base;
        if (ordinal < baseOrdinal || ordinal >= baseOrdinal + exportDir->NumberOfFunctions) {
            return NULL; 
        }
        return (FARPROC)((BYTE*)hModule + functions[ordinal - baseOrdinal]);
    }

    
    DWORD* nameRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* nameOrdinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* funcName = (const char*)hModule + nameRVAs[i];
        if (strcmp(funcName, lpProcName) == 0) {
            WORD ordinal = nameOrdinals[i];
            return (FARPROC)((BYTE*)hModule + functions[ordinal]);
        }
    }

    return NULL;
}


FARPROC SafeGetProcAddress(const wchar_t* moduleName, LPCSTR apiName) {
    HMODULE hMod = GetModuleByPEB(moduleName);
    if (!hMod) return NULL;
    return ParseExportByName(hMod, apiName);
}
