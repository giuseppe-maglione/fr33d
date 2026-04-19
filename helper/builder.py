import sys
import argparse

def generate_c_array(plaintext, key):
    
    # add null terminator automatically
    plaintext_with_null = plaintext + '\0'

    plaintext_bytes = plaintext_with_null.encode('utf-8')
    key_bytes = key.encode('utf-8')
    
    encrypted_bytes = []
    
    # apply xor
    for i in range(len(plaintext_bytes)):
        enc_byte = plaintext_bytes[i] ^ key_bytes[i % len(key_bytes)]
        encrypted_bytes.append(enc_byte)
    
    # formatting output for C (es: 0x68, 0x74, 0x74...)
    c_array_elements = ", ".join([f"0x{b:02x}" for b in encrypted_bytes])
    
    print(f"// Plain text: {plaintext}")
    print(f"// Key: {key}")
    print(f"char encrypted_string[] = {{ {c_array_elements} }};\n")

# usage example
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Builder to XOR encode strings in C.")
    parser.add_argument("-d", "--data", required=True, help="Plain text to cypher (ex. VirtualAlloc)")
    parser.add_argument("-k", "--key", default="secret", help="Cypher key (default: 'secret')")
    
    args = parser.parse_args()

    # secret string that MUST NOT compare in .c file
    url_segreto = args.data
    chiave_segreta = args.key
    
    print("--- Print this string in your C code ---")
    generate_c_array(url_segreto, chiave_segreta)