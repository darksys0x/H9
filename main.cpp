#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <winternl.h>
#include <dbghelp.h>
#include <map>
#include <string>

#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ntdll.dll")
#pragma comment(lib, "Dbghelp.dll")




char blackFunction[][32] = {
	"URLDownloadToFile", "SetWindowsHookExA", "CreateFIleA","VirtualProtect "
};


typedef NTSTATUS(__stdcall* NtQueryInfoType)
(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);
typedef NTSTATUS(__stdcall* ImageDirectoryEntryToData)(
	PVOID   Base,
	BOOLEAN MappedAsImage,
	USHORT  DirectoryEntry,
	PULONG  Size
	);




//typedef struct tagTHREADENTRY32
//{
//    DWORD   dwSize;
//    DWORD   cntUsage;
//    DWORD   th32ThreadID;       // this thread
//    DWORD   th32OwnerProcessID; // Process this thread is associated with
//    LONG    tpBasePri;
//    LONG    tpDeltaPri;
//    DWORD   dwFlags;
//} THREADENTRY32;

//#define TH32CS_SNAPHEAPLIST 0x00000001
//#define TH32CS_SNAPPROCESS  0x00000002
//#define TH32CS_SNAPTHREAD   0x00000004
//#define TH32CS_SNAPMODULE   0x00000008
//#define TH32CS_SNAPMODULE32 0x00000010
//#define TH32CS_SNAPALL      (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
//#define TH32CS_INHERIT      0x80000000
//




// std::string = C++ ascii
// std::wstring = C++ wide string (unicode)

static std::map<std::wstring, bool> modulePathsMap;

void readDLll(DWORD th32ProcessID) {
	HANDLE DLL = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, th32ProcessID);
	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);
	BOOL m = Module32First(DLL, &me);
	DWORD numOfmodule = 0;


	while (m == TRUE)
	{
		numOfmodule++;
		printf("Module: %d | Module Id = %d | %ws\n", numOfmodule, me.th32ModuleID, me.szExePath);
		m = Module32Next(DLL, &me);
		//std::wstring path(me.szExePath);
		//if (modulePathsMap.find(path) == modulePathsMap.end()) { // if not found
		//	modulePathsMap[path] = true; // insert the path into map


	}
	printf("there are %d modules of this process.\n", numOfmodule);
	CloseHandle(readDLll);
}





DWORD getProcessIDByName(PCTSTR Pname) {
	HANDLE readProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	BOOL p = Process32First(readProcess, &pe);
	DWORD proceeID;
	while (p == TRUE) // when can i used the == true or not and why>

	{
		if (StrStrIW(pe.szExeFile, Pname)) {
			printf("the process ID = %d | %ws\n", pe.th32ProcessID, pe.szExeFile);
			proceeID = pe.th32ProcessID;
			readDLll(pe.th32ProcessID);
			break;
		}
		//printf("the process ID = %d | %ws\n", pe.th32ProcessID, pe.szExeFile);

		p = Process32Next(readProcess, &pe);

	}
	return proceeID;
}

DWORD GetBaseAddress(PCTSTR Pname, HANDLE* handleProcess) {
	DWORD spesificProcess = getProcessIDByName(Pname);
	HANDLE oP = OpenProcess(PROCESS_ALL_ACCESS, FALSE, spesificProcess);
	*handleProcess = oP;
	HMODULE ntDllBaseAddress = GetModuleHandle(L"ntdll.dll");//?hmodule
	NtQueryInfoType GetFunctionAddressOfInsideNtlls = (NtQueryInfoType)GetProcAddress(ntDllBaseAddress, "NtQueryInformationProcess");

	PROCESS_BASIC_INFORMATION processBasicInfo;

	/*NTDLL.DLL              kernelbase.dll or kernel32.dll
	______________________________________________________________
	NtWriteVirtualMemory    = WriteProcessMemory
	NtReadVirtualMemory    = ReadProcessMemory
	NtProtectVirtualMemory = VirtualProtect*/


	/*typedef struct _PROCESS_BASIC_INFORMATION {
		PVOID Reserved1;
		PPEB PebBaseAddress;
		PVOID Reserved2[2];
		ULONG_PTR UniqueProcessId;
		PVOID Reserved3;
	} PROCESS_BASIC_INFORMATION*/
	DWORD returnValue;
	NTSTATUS status = GetFunctionAddressOfInsideNtlls(oP, ProcessBasicInformation, &processBasicInfo, sizeof(processBasicInfo), &returnValue);//?nts

#define	STATUS_SUCCESS 0x0
	if (status != STATUS_SUCCESS) {
		printf("GetFunctionAddressOfInsideNtlls is failed\n");

	}

	PEB peb;
	if (!ReadProcessMemory(oP, (PVOID)processBasicInfo.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		printf("processBasicInfo.PebBaseAddress is failed\n");
		return 0;
	}
	DWORD baseAddessOfExe = (DWORD)peb.Reserved3[1];

	return baseAddessOfExe;



}
//why don't use here a "&"  withe hamdleprocess?
void DetectSuspiciousFunctionAProcess(DWORD baseAddessOfExe, HANDLE handleProcess) {
	//IMAGE_Dos
	IMAGE_DOS_HEADER DosHeader;
	if (!ReadProcessMemory(handleProcess, (PVOID)baseAddessOfExe, &DosHeader, sizeof(DosHeader), NULL)) {
		printf("the dosheader failed\n");
		return;
	}
	//ntHeader
	DWORD NTbaseAddress = baseAddessOfExe + DosHeader.e_lfanew;
	IMAGE_NT_HEADERS ntHeader;
	if (!ReadProcessMemory(handleProcess, (PVOID)NTbaseAddress, &ntHeader, sizeof(ntHeader), NULL)) {
		printf("the ntHeader failed \n");
		return;

	}

	//discriptor 

	DWORD discriptorAddress = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + baseAddessOfExe;
	IMAGE_IMPORT_DESCRIPTOR imageDewscriptor;
	for (; discriptorAddress;) {
		if (!ReadProcessMemory(handleProcess, (PVOID)discriptorAddress, &imageDewscriptor, sizeof(imageDewscriptor), NULL)) {
			printf("discriptorAddress falied\n");
			return;

			if (!imageDewscriptor.Name) {
				printf("the discriptor is done\n");
				break;
			}
			DWORD originalThunkAddress = baseAddessOfExe + imageDewscriptor.OriginalFirstThunk;
			IMAGE_THUNK_DATA originalThunk;
			char nameOfFunction[250];
			while (originalThunkAddress) {
				if (!ReadProcessMemory(handleProcess, (PVOID)originalThunkAddress, &originalThunk, sizeof(originalThunk), NULL)) {
					printf("originalThunkAddress failed\n");

					return;
				}
				if (!originalThunk.u1.Function) {
					break;//done
				}

				IMAGE_IMPORT_BY_NAME;

				DWORD importByNameAddress = baseAddessOfExe + originalThunk.u1.Function; // IMAGE_IMPORT_BY_NAME object address
				DWORD nameAddress = importByNameAddress + 2;//must use base address to get name of function 

				ReadProcessMemory(handleProcess, (PVOID)nameAddress, &nameOfFunction, sizeof(nameOfFunction), NULL);



				originalThunkAddress += sizeof(originalThunk);

				printf("the name of function = %s", nameOfFunction);

			}

		}
		discriptorAddress += sizeof(imageDewscriptor);
	}

}

int main() {
	HANDLE handleProcess = NULL;
	DWORD baseAddressofTaregetProcess = GetBaseAddress(L"Zoom.exe", &handleProcess);
	printf("the process ID has selected = %d", baseAddressofTaregetProcess);


	getchar();
	return 0;
}