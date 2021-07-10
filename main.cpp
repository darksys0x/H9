#include<stdio.h>
#include<Windows.h>
#include<tlhelp32.h>
#include<shlwapi.h>
#include<libloaderapi.h>
#include<winternl.h>
#include <map>
#include <string>
#pragma comment(lib, "Shlwapi.lib")//pragma
#pragma comment(lib, "Kernel32.lib")



typedef NTSTATUS(__stdcall* NtQueryInfoType)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
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
DWORD counter = 0; // numbers of modules in the memory  

//get all Modules in memory affiliated each process 
void printModules(DWORD th32ProcessID) {
    HANDLE moduleOfprocess = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, th32ProcessID);
    MODULEENTRY32 m;
    m.dwSize = sizeof(MODULEENTRY32);
    BOOL n = Module32First(moduleOfprocess, &m);
    while (n == TRUE) {
        printf("module ID = %d | %ws\n", m.th32ModuleID, m.szExePath);

        n = Module32Next(moduleOfprocess, &m);

        std::wstring path(m.szExePath);
        if (modulePathsMap.find(path) == modulePathsMap.end()) { // if not found
            modulePathsMap[path] = true; // insert the path into map
            counter++; // this counter is only incremented if path is not found already to avoid duplicates
        }

    }


    CloseHandle(moduleOfprocess);

}

//  get snap process is residing in the system
DWORD PrintProcessModules(PCTSTR pName) {
    HANDLE snapProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapProcess == INVALID_HANDLE_VALUE)
    {
        MessageBox(NULL, L"Error: unable to create toolhelp snapshot", L"Loader", NULL);
        return FALSE;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    BOOL i = Process32First(snapProcess, &pe);
    DWORD processID = 0;
    DWORD numberOfProcess = 0;

    while (i == TRUE) {
        printf("processNumber = %d process = %d | %ws\n", numberOfProcess, pe.th32ProcessID, pe.szExeFile);
        if (StrStrIW(pe.szExeFile, pName)) {
            processID = pe.th32ProcessID;
            printf("found process id in loop\n");
        }
        printModules(pe.th32ProcessID);
        i = Process32Next(snapProcess, &pe);
        numberOfProcess++;

    }
    printf("the number of process is residing system = %d  | Total Modules = %d (without duplicates)\n\n\n", numberOfProcess, counter);
    CloseHandle(snapProcess);
}


DWORD GetTargetProcessId(PCTSTR pName)
{
    HANDLE snapProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapProcess == INVALID_HANDLE_VALUE)
    {
        MessageBox(NULL, L"Error: unable to create toolhelp snapshot", L"Loader", NULL);
        return FALSE;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    BOOL i = Process32First(snapProcess, &pe);
    DWORD processID = 0;


    while (i == TRUE) {
        if (StrStrIW(pe.szExeFile, pName)) {
            processID = pe.th32ProcessID;
            break;
        }
        i = Process32Next(snapProcess, &pe);

    }
    CloseHandle(snapProcess);
    return processID;
}



void DetectSuspiciousThingsAboutProcess(PCTSTR pName)
{
    DWORD processId = GetTargetProcessId(pName);
    if (!processId) {
        printf("failed to get target process id\n");
        return;
    }
    //Get the DOS & NT header of target process
    HANDLE oP = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId); //open process

    NtQueryInfoType NtQInfoFunction = (NtQueryInfoType)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");  //exported function from DLL
    if (!NtQInfoFunction) {
        printf("failed to get NtQueryInformationProcess address\n");
        CloseHandle(oP);
        return;
    }

    /*NTDLL.DLL              kernelbase.dll or kernel32.dll
    ______________________________________________________________
    NtWriteVirtualMemory    = WriteProcessMemory
    NtReadVirtualMemory    = ReadProcessMemory
    NtProtectVirtualMemory = VirtualProtect*/

    /*  typedef struct _PROCESS_BASIC_INFORMATION {
          PVOID Reserved1;
          PPEB PebBaseAddress;
          PVOID Reserved2[2];
          ULONG_PTR UniqueProcessId;
          PVOID Reserved3;
      } PROCESS_BASIC_INFORMATION;*/

    PROCESS_BASIC_INFORMATION processBasicInfo;
    DWORD ReturnLength;

    /*_kernel_entry NTSTATUS NtQueryInformationProcess(
        HANDLE           ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID            ProcessInformation,
        ULONG            ProcessInformationLength,
        PULONG           ReturnLength
    );*/
    NtQInfoFunction(oP, ProcessBasicInformation, &processBasicInfo, sizeof(processBasicInfo), &ReturnLength);
    //part of PEB 
    PEB peb;
    /*typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PPEB PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;*/
    ReadProcessMemory(oP, (PVOID)processBasicInfo.PebBaseAddress, &peb, sizeof(peb), NULL);
    DWORD beasAddressExe = (DWORD)peb.Reserved3[1];
    // part of pe header NT & DOS 
    IMAGE_DOS_HEADER dsheader;
    ReadProcessMemory(oP, (PVOID)beasAddressExe, &dsheader, sizeof(dsheader), NULL);
    DWORD baseNTheader = beasAddressExe + dsheader.e_lfanew;
    IMAGE_NT_HEADERS ntheader;
    ReadProcessMemory(oP, (PVOID)baseNTheader, &ntheader, sizeof(ntheader), NULL);
    
    //******************************************
    //discriptor part


    DWORD discriptAddress = ntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + beasAddressExe;
    


    //typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    //    union {
    //        DWORD   Characteristics;            // 0 for terminating null import descriptor
    //        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    //    } DUMMYUNIONNAME;
    //    DWORD   TimeDateStamp;                  // 0 if not bound,
    //                                            // -1 if bound, and real date\time stamp
    //                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    //                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    //    DWORD   ForwarderChain;                 // -1 if no forwarders
    //    DWORD   Name;
    //    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
    //} IMAGE_IMPORT_DESCRIPTOR;


    IMAGE_IMPORT_DESCRIPTOR importDescriptor;
    
    
    while (discriptorAddress) {
        ReadProcessMemory(oP, (PVOID)discriptorAddress, &importDescriptor, sizeof(importDescriptor), NULL);
        if (!importDescriptor.Name) {
            printf("the imports name are done\n");

            break;
        }

    }



}


static int mymain() {

    // DWORD processID = PrintProcessModules(L"sublime_text.exe"); // To get particular process
    //printf("process id found = %d\n", processID);

   

     getchar();
     return 0;
}




