#pragma once
#include <stdint.h>
#include <Windows.h>

//typedef struct _PEB {
//    BYTE Reserved1[2];
//    BYTE BeingDebugged;
//    BYTE Reserved2[1];
//    PVOID Reserved3[2];
//    PPEB_LDR_DATA Ldr;
//    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

typedef struct _PEBx64 {
    union {
        struct {
            BYTE flag1; // 0
            BYTE flag2; // 1
            BYTE flag3; // 2
            BYTE flg4; // 3
        };
        uint64_t flags; // 0
    };
    uint64_t Mutant; // 8
    uint64_t ImageBaseAddress; // 16
   
   // uint64_t Reserved3[2]; // Reserved3[1] will give you image base address
} PEBx64, * PPEBx64;

typedef struct _PROCESS_BASIC_INFORMATIONx64 {
    uint64_t Reserved1;
    uint64_t PebBaseAddress;
    uint64_t Reserved2[2];
    uint64_t UniqueProcessId;
    uint64_t Reserved3;
} PROCESS_BASIC_INFORMATIONx64;
typedef PROCESS_BASIC_INFORMATIONx64* PPROCESS_BASIC_INFORMATIONx64;









//
//
//typedef struct _IMAGE_IMPORT_DESCRIPTOR {
//    union {
//        DWORD   Characteristics;            // 0 for terminating null import descriptor
//        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
//    } DUMMYUNIONNAME;
//    DWORD   TimeDateStamp;                  // 0 if not bound,
//                                            // -1 if bound, and real date\time stamp
//                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
//                                            // O.W. date/time stamp of DLL bound to (Old BIND)
//
//    DWORD   ForwarderChain;                 // -1 if no forwarders
//    DWORD   Name;
//    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
//} IMAGE_IMPORT_DESCRIPTOR;
//typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED* PIMAGE_IMPORT_DESCRIPTOR;