#include<stdio.h>
#include<Windows.h>
#include<tlhelp32.h>
#include<shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")//pragma




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

DWORD modulesNuber = 0;
DWORD counter = 0;
void printModules(DWORD th32ProcessID) {
    HANDLE moduleOfprocess = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, th32ProcessID);
    MODULEENTRY32 m;
    m.dwSize = sizeof(MODULEENTRY32);
    BOOL n = Module32First(moduleOfprocess, &m);
    while (n == TRUE) {
        printf("module ID = %d | %ws\n", m.th32ModuleID, m.szExePath);

        n = Module32Next(moduleOfprocess, &m);
        modulesNuber++;

    }
    counter += modulesNuber;

    CloseHandle(moduleOfprocess);

}
DWORD GetTargetProcessIDName(PCTSTR pName) {
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
    printf("the number of process is residing system = %d  | Module = %d\n\n\n", numberOfProcess, counter);
    CloseHandle(snapProcess);
}

void DetectSuspiciousThingsAboutProcess(DWORD processId)
{
    /*printProcessMoudle(processId);*/

    //Get the DOS & NT header of target process



}


DWORD main() {

    DWORD processID = GetTargetProcessIDName(L"sublime_text.exe");
    printf("process id found = %d\n", processID);



    getchar();
    return 0;
}