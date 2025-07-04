#pragma once
#include <windows.h>

typedef struct _SAFE_PROCESSENTRY32 {
    DWORD pid;
    DWORD parentPid;
    WCHAR imageName[260];
} SAFE_PROCESSENTRY32;

typedef struct _SAFE_MODULEENTRY32 {
    LPVOID baseAddress;
    DWORD size;
    WCHAR moduleName[260];
} SAFE_MODULEENTRY32;

BOOL SafeCreateProcessSnapshot();
BOOL SafeProcess32First(SAFE_PROCESSENTRY32* entry);
BOOL SafeProcess32Next(SAFE_PROCESSENTRY32* entry);

BOOL SafeModule32First(DWORD pid, SAFE_MODULEENTRY32* entry);
BOOL SafeModule32Next(SAFE_MODULEENTRY32* entry);
#pragma once
