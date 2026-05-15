# fr33d - C-Based Dropper & Injector (PoC)

This project is a **Proof of Concept (PoC)** of a modular dropper written in C, designed for educational purposes and for the study of advanced evasion and code injection techniques in Windows environments. The implant is structured to evade static and dynamic analysis by Windows Defender.

> ⚠️ **Disclaimer**: For educational purposes only. The use of this code for malicious or illegal purposes is strictly prohibited. The developer assumes no responsibility for the misuse of this material. Test only in isolated, authorized, and controlled environments (Sandbox/Lab).

---

## 🚀 Advanced Features

### 1. Static Evasion and Obfuscation
- **API Hashing (DJB2)**: No direct calls to Windows APIs in the Import Address Table (IAT). Functions are resolved at runtime via string name hashing.
- **XOR String Encryption**: All sensitive strings (DLL names, target processes, registry keys) are encrypted via XOR with a dynamic key and decrypted only in the stack right before use.
- **OPSEC**: All sensitive strings are re-encrypted immediately after use to prevent memory scraping.
- **Binary Stripping**: The executable is stripped of debug symbols and metadata during compilation.

### 2. Dynamic Evasion (Anti-Analysis)
- **Anti-Debugging**: Runtime detection of possible attached debuggers.
- **Anti-VM**: Direct querying of the processor via the `__cpuid` instruction to detect hypervisors.
- **Anti-Sandboxing**: Verifies system uptime as a common indicator of a dynamically spun-up sandbox environment.
- **Smart Delay**: A "smart" calculation loop to bypass sandbox wait times without using the `Sleep()` function.
- **Resource Checking**: Hardware resource checks to detect constrained analysis environments.
- **Polymorphism**: The Python weaponization script generates a unique SHA-256 hash for each build by appending random bytes in the overlay at the end of the file.

### 3. Persistence and Control
- **Identifying Mutex**: Checks for the presence of a unique (encrypted) Mutex to prevent multiple redundant executions on the same host.
- **Auto-Persistence**: Copies itself into the `%APPDATA%` folder with a legitimate-looking name (`OneDrive_Updater.exe`) and ensures startup at boot via Windows registry.

### 4. Process Injection & Networking
- **Modular Downloader**: Uses WinINet to download the encrypted shellcode/payload from a remote C2 server.
- **Stealth Injection**: Injects shellcode into system processes (`svchost.exe`).

### 5. Automated C2 Infrastructure
- **One-Click Deployment**: A dedicated Bash script (`start_c2.sh`) automates the full attacker infrastructure setup.

---

## 🛠️ Project Architecture

```text
.
├── src/
│   ├── main.c           # Entry point and core logic
│   ├── evasion.c        # Anti-VM, Hashing, XOR, Mutex
│   ├── network.c        # Payload download manager
│   ├── injection.c      # Injection logic (Remote Thread)
│   ├── persistence.c    # Persistence installation and registry
│   ├── config.h         # Definitions and constants
│   └── ...              # Header files
├── tools/
│   ├── malware_mutator.py      # Polymorphic builder and stripping
│   ├── stack_string.py         # C Macro generator for Stack String with XOR
│   ├── string_encryptor.py     # Strings encryptor based on secret key
│   └── hasher.py               # DJB2 hash generator for APIs
├── attacker/
│   ├── www/
│   │   └── ...           # Web Server Folder
│   └── start_c2.sh       # Launch Automated C2 Infrastructure
├── payloads/
│    └── calc.c          # Light testing shellcode
├── build/
│    └── malware.exe     # Final executable
├── docs/
│    └── ...             # Documentation
└── README.md
```

---

## 🔨 Configuration and Deployment

The project requires the `mingw-w64` cross-compiler on Linux. 

**⚠️ Configuration Requirement:** Before building, you must update the Attacker IP and Port in the following two files to match your local setup:
1. `src/config.h` (C2 URL for the dropper)
2. `attacker/start_c2.sh` (LHOST and LPORT for payload generation and listener)

> **Ethical Note:** For testing and educational purposes, the project currently relies on a default hardcoded XOR key provided in `config.h`. Full instructions for generating and implementing custom encryption keys are intentionally omitted from this PoC. *Hint: Try playing around with the files in the `/tools` folder*

### Deployment Steps

**1. Compile and Weaponize:**
Run the automated builder to compile the C code, strip metadata, and apply polymorphism. 
```bash
# Build default (OneDrive_Updater.exe)
python3 tools/builder.py

# Build with a custom name
python3 tools/builder.py --name "CustomName.exe"

# Build in debug mode (shows terminal and verbose logging)
python3 tools/builder.py --debug
```
The generated payload will be saved in the `build/` directory.

**2. Launch C2 Infrastructure:**
Start the automated script to generate the raw shellcode, host it via a background Python web server, and launch the Metasploit listener.
```bash
chmod +x ./attacker/start_c2.sh
./attacker/start_c2.sh
```

**3. Transfer the Payload:**
Transfer the generated executable from your `build/` folder to the target Windows machine (e.g., by hosting it on a web server or transferring it via USB for lab testing).

**4. Execute:**
Run the dropper on the target machine. Once the sandbox checks and smart delays are bypassed, the payload will be downloaded and injected, returning a reverse shell/beacon to your active Metasploit handler.

---

## 🔬 Testing

The implant was successfully tested on **Windows 11 (23H2)**, bypassing standard Windows Defender signatures for loading Meterpreter (HTTP) shellcode injected into suspended `svchost.exe` processes.
