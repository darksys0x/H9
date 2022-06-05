#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <winternl.h>
#pragma comment( lib, "Kernel32.lib" )


typedef struct _PEB_LDR_DATA88
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;

} PEB_LDR_DATA88, * PPEB_LDR_DATA88;


typedef struct _PEB88 {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
} PEB88, * PPEB88;


typedef NTSTATUS(__stdcall* NtQueryInformationProcess)
(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);


DWORD getBaseAddressOfprocess(void* Dedct) {
	HMODULE ntdllBaseAddress = GetModuleHandle(L"ntdll.dll");
	NtQueryInformationProcess hamadProcessbaseAddress = (NtQueryInformationProcess)GetProcAddress(ntdllBaseAddress, "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION baseAddressh;

	const int i = sizeof(PEB_LDR_DATA88);

}



void DetectSuspiciousFunction(DWORD processId) {
	HANDLE hpOpenProcess = OpenProcess(0x0010 | 0x0020, FALSE, processId);
	

}


//1. Loop Through all processes via snapshot

void LoopThroughAllMemoryProcesses() {
	HANDLE allprocess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	DWORD processCpount = 0;
	BOOL p = Process32First(allprocess, &pe);

	while (p) {
		
		printf("the process Name %d\n", pe.th32ProcessID);
		processCpount += 1;
		DetectSuspiciousFunction(pe.th32ProcessID);
		p = Process32Next(allprocess, &pe);
	}
	printf("there are %d process are running in memory\n", processCpount);
	CloseHandle(allprocess);
	
}



int main() {
	LoopThroughAllMemoryProcesses();




	return 0;
}