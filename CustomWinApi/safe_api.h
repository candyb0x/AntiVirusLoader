#pragma once
#include <windows.h>

FARPROC SafeGetProcAddress(const wchar_t* moduleName, LPCSTR apiName);
