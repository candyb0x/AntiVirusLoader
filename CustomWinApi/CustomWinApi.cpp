// CustomWinApi.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include "safe_api.h"

int main()
{
    std::cout << SafeGetProcAddress(L"kernel32.dll", "VirtualAlloc") << std::endl;
    HMODULE alpc = GetModuleHandleA("KERNEL32.dll");
    std::cout << GetProcAddress(alpc, "VirtualAlloc") << std::endl;
    std::cout << "Hello World!\n";
}
