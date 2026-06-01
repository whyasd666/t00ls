#!/usr/bin/env bash
# whyasdscan installer

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; W='\033[1;37m'; RST='\033[0m'

echo -e "${C}[*]${RST} Installing whyasdscan dependencies..."

# Try methods in order
install_scapy() {
  # 1. apt
  if command -v apt &>/dev/null; then
    echo -e "${C}[*]${RST} Trying apt..."
    sudo apt install -y python3-scapy 2>/dev/null && echo -e "${G}[+]${RST} Installed via apt" && return 0
  fi

  # 2. pip --break-system-packages
  echo -e "${C}[*]${RST} Trying pip --break-system-packages..."
  pip install scapy --break-system-packages 2>/dev/null && echo -e "${G}[+]${RST} Installed via pip" && return 0

  # 3. pipx
  if command -v pipx &>/dev/null; then
    echo -e "${C}[*]${RST} Trying pipx..."
    pipx install scapy 2>/dev/null && return 0
  fi

  # 4. venv (fallback)
  echo -e "${Y}[!]${RST} Creating venv at ~/.whyasdscan-venv ..."
  python3 -m venv ~/.whyasdscan-venv
  ~/.whyasdscan-venv/bin/pip install scapy -q

  # Patch launcher to use venv python
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cat > "$SCRIPT_DIR/whyasdscan.sh" << LAUNCHER
#!/usr/bin/env bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
exec ~/.whyasdscan-venv/bin/python3 "\$SCRIPT_DIR/whyasdscan.py" "\$@"
LAUNCHER
  chmod +x "$SCRIPT_DIR/whyasdscan.sh"
  echo -e "${G}[+]${RST} Installed in venv, launcher updated"
  return 0
}

install_scapy

echo ""
echo -e "${G}[+]${RST} Done! Run: ${W}sudo ./whyasdscan.sh 192.168.1.1${RST}"
echo -e "${C}[*]${RST} Root = SYN scan + UDP + OS detection"
echo -e "${C}[*]${RST} No root = TCP connect scan only"
