import random
import argparse

def generate_stack_macro(key_str, macro_name="LOAD_GLOBAL_KEY"):
    print(f"// Macro generated for key: '{key_str}'")
    print(f"#define {macro_name}(key_var, len_var) \\")
    print(f"    char key_var[{len(key_str) + 1}]; \\")
    
    for i, char in enumerate(key_str):
        # generate random byte to use as obfuscator
        obfuscator = random.randint(1, 255)
        encrypted_char = ord(char) ^ obfuscator
        
        print(f"    key_var[{i}] = 0x{encrypted_char:02X} ^ 0x{obfuscator:02X}; \\")
        
    print(f"    key_var[{len(key_str)}] = 0x00; \\")
    print(f"    size_t len_var = {len(key_str)};\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate C Macro for Stack String with XOR.")
    parser.add_argument("-k", "--key", required=True, help="Secret key to obfuscate (ex. secret)")
    
    args = parser.parse_args()
    
    print("--- Paste this code inside config.h ---\n")
    generate_stack_macro(args.key)