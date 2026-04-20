import sys
import argparse

def djb2_hash(string):
    hash_value = 5381
    for char in string:
        # hash * 33 + c
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        # force result on 32 bit
        hash_value &= 0xFFFFFFFF
    return hash_value

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate djb2 hash for API Hashing.")
    parser.add_argument("-a", "--api", required=True, help="API name (ex. VirtualAlloc)")
    
    args = parser.parse_args()
    
    api_name = args.api
    calculated_hash = djb2_hash(api_name)
    
    print(f"// Hash per: {api_name}")
    print(f"DWORD hash_{api_name} = 0x{calculated_hash:08X};")