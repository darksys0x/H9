#include<stdio.h>
#include<Windows.h>
#include<tlhelp32.h>
#include<shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")//pragma 



//get process from users 
//CreateToolhelp32Snapshot(
//	DWORD dwFlags,
//	DWORD th32ProcessID
//);

//
// The th32ProcessID argument is only used if TH32CS_SNAPHEAPLIST or
// TH32CS_SNAPMODULE is specified. th32ProcessID == 0 means the current
// process.
//
// NOTE that all of the snapshots are global except for the heap and module
//      lists which are process specific. To enumerate the heap or module
//      state for all WIN32 processes call with TH32CS_SNAPALL and the
//      current process. Then for each process in the TH32CS_SNAPPROCESS
//      list that isn't the current process, do a call with just
//      TH32CS_SNAPHEAPLIST and/or TH32CS_SNAPMODULE.
//
// dwFlags
//
//#define TH32CS_SNAPHEAPLIST 0x00000001
//#define TH32CS_SNAPPROCESS  0x00000002
//#define TH32CS_SNAPTHREAD   0x00000004
//#define TH32CS_SNAPMODULE   0x00000008
//#define TH32CS_SNAPMODULE32 0x00000010
//#define TH32CS_SNAPALL      (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
//#define TH32CS_INHERIT      0x80000000
//


void printProcessMoudle(DWORD th32ProcessID);





void printProcessMoudle(DWORD th32ProcessID) {
	HANDLE getModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, th32ProcessID);
	if (getModule == INVALID_HANDLE_VALUE) {
		printf("TH32CS_SNAPMODULE32: ERROR handle is invalied\n");
		return;
	}
	MODULEENTRY32 m;
	m.dwSize = sizeof(MODULEENTRY32);
	BOOL im = Module32First(getModule, &m);
	while (im == TRUE) {
		printf("the SNAP MODULE32 ID = %d | %ws\n", m.th32ModuleID, m.szExePath);
		im = Module32Next(getModule, &m);
	}
	CloseHandle(getModule);
}


void DetectSuspiciousThingsAboutProcess(DWORD processId)
{
	printProcessMoudle(processId);

	//Get the DOS & NT header of target process

}

int main() {
	HANDLE creatSnapShoot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (creatSnapShoot == INVALID_HANDLE_VALUE) {
		printf("TH32CS_SNAPALL: handle is invalied\n");
		return 0;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	BOOL i = Process32First(creatSnapShoot, &pe);

	while (i == TRUE) {
		printf("The Process ID is = %d | %ws | the Moudle %d \n", pe.th32ProcessID, pe.szExeFile, pe.th32ModuleID);
	
		DetectSuspiciousThingsAboutProcess(pe.th32ProcessID);

		i = Process32Next(creatSnapShoot, &pe);
	}
	CloseHandle(creatSnapShoot);
	

	getchar();
	return 0;
}