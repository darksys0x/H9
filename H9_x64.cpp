#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <winternl.h>
#include <dbghelp.h>
#include <map>
#include <string>
#include "x64Structs.h"

//#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Shlwapi.lib")
//#pragma comment(lib, "Ntdll.dll")
//#pragma comment(lib, "Dbghelp.dll")


#define MAX_FUNC_NAME_SIZE 100 // maximum size of the each element/string in the array
#define MAX_BLACKLISTED_FUNCS 25 // maximum number of elements/strings in the array


extern char* blackListedFunctionNames;

typedef NTSTATUS(__stdcall* NtQueryInfoType)
	(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
    );

typedef NTSTATUS(__stdcall* ReadVMem64Type)
(
	HANDLE hProcess,
	uint64_t lpBaseAddress,
	LPVOID lpBuffer,
	uint64_t nSize,
	uint64_t* lpNumberOfBytesRead
	);

NtQueryInfoType NtWow64QueryInformationProcess64 = NULL;
ReadVMem64Type NtWow64ReadVirtualMemory64 = NULL; // read process memory for the 32


void Initialisex64Functions() {
	HMODULE ntDllBaseAddress = GetModuleHandle(L"ntdll.dll");//?hmodule
    NtWow64QueryInformationProcess64 = (NtQueryInfoType)GetProcAddress(ntDllBaseAddress, "NtWow64QueryInformationProcess64");
	NtWow64ReadVirtualMemory64 = (ReadVMem64Type)GetProcAddress(ntDllBaseAddress, "NtWow64ReadVirtualMemory64");
	

}
//1.2 call NtQueryInformationProcess to get PROCESS_BASIC_INFORMATION
uint64_t GetBaseAddressx64(HANDLE oP) {
	_PROCESS_BASIC_INFORMATIONx64 basic_infox64;
	DWORD adding;


	NTSTATUS status = NtWow64QueryInformationProcess64(oP, ProcessBasicInformation, &basic_infox64,sizeof(basic_infox64), &adding);
#define	STATUS_SUCCESS 0x0 
	if (status != STATUS_SUCCESS) {
		printf("GetFunctionAddressOfInsideNtllsx64 is failed\n");

	}
	 
	//pebx64 part
	_PEBx64 peb_x64;
	if (NtWow64ReadVirtualMemory64(oP, (uint64_t)basic_infox64.PebBaseAddress, &peb_x64, sizeof(peb_x64), NULL) != STATUS_SUCCESS) {
		printf("Get PEB_x64 PebBaseAddress is failed");

	}
	
	uint64_t getBaseAddressx64 = peb_x64.ImageBaseAddress;
	return getBaseAddressx64;


}



void DetectSuspiciousFunctionAProcessx64(uint64_t getBaseAddressx64, HANDLE handleProcess) {
	//IMAGE_Dos
	_IMAGE_DOS_HEADER dos;
	if (NtWow64ReadVirtualMemory64(handleProcess, (uint64_t)getBaseAddressx64, &dos, sizeof(dos), NULL) != STATUS_SUCCESS) {
		printf("Get DOSx64  is failed");

	}
	//ntHeader
	uint64_t NTbaseAddress_x64 = getBaseAddressx64 + dos.e_lfanew;

	IMAGE_NT_HEADERS64 ntHeader_x64;
	if (NtWow64ReadVirtualMemory64(handleProcess, (uint64_t)NTbaseAddress_x64, &ntHeader_x64, sizeof(ntHeader_x64), NULL) != STATUS_SUCCESS) {
		printf("Get ntHeader_x64  is failed");

	}


	//discriptor 
	uint64_t discriptor_64 = ntHeader_x64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + getBaseAddressx64;
	IMAGE_IMPORT_DESCRIPTOR imageDescriptor_x64;
	for (; discriptor_64;) {
		if (NtWow64ReadVirtualMemory64(handleProcess, (uint64_t)discriptor_64, &imageDescriptor_x64, sizeof(imageDescriptor_x64), NULL) != STATUS_SUCCESS) {
			printf("Get imageDescriptor_x64  is failed\n");
			return;
		}
		if (!imageDescriptor_x64.Name) {
			printf("the discriptor is done\n");
			break;
		}
		uint64_t orginalThunk_64 = imageDescriptor_x64.OriginalFirstThunk + getBaseAddressx64;
		IMAGE_THUNK_DATA thunk_x64;
		char nameFunction[100];
		while (orginalThunk_64) {
			if (NtWow64ReadVirtualMemory64(handleProcess, (uint64_t)orginalThunk_64, &thunk_x64, sizeof(thunk_x64), NULL) != STATUS_SUCCESS) {
				printf("Get thunk_x64  is failed\n");
				return;
			}
			if (thunk_x64.u1.Function == 0) {
				break;
			}

			uint64_t functionNameAddress_64 = thunk_x64.u1.Function + getBaseAddressx64 + sizeof(WORD);
			if (NtWow64ReadVirtualMemory64(handleProcess, (uint64_t)functionNameAddress_64, &nameFunction, 100, NULL) != STATUS_SUCCESS) {
				printf("Get nameFunction_64 is failed\n");
				return;
				
			}
			printf("the name of funcation %s\n", nameFunction);

			for (int i = 0; i < MAX_BLACKLISTED_FUNCS; i++)
			{
				char* blacklistedFunctionName = blackListedFunctionNames + i * MAX_FUNC_NAME_SIZE;
				if (*blacklistedFunctionName != '\0') {
					if (strcmp(nameFunction, blacklistedFunctionName) == 0) {
						printf("\n! %s is blacklisted\n\n", nameFunction);

					}
				}
			}
			orginalThunk_64 += sizeof(thunk_x64);
		
		}
		discriptor_64 += sizeof(imageDescriptor_x64);
	}



}

























