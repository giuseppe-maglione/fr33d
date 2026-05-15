#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>

// receives input buffer containing shellcode and executes in a new thread
bool execute_payload(char* payload_buffer, SIZE_T payload_size);

#endif