#ifndef NETWORK_H
#define NETWORK_H

#include <windows.h>
#include <wininet.h>
#include <stddef.h>

// download a payload and save in memory
// return pointer to memory location or null if fails
char* download_payload(const char* url, SIZE_T* payload_size);

#endif