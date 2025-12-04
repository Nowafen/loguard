#!/bin/bash
# Loguard Installer
# Real-time Linux login alerts to Telegram
# https://github.com/Nowafen/loguard

set -e

REPO="Nowafen/loguard"
BRANCH="main"

INSTALL_DIR="/opt/loguard"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/loguard"
LOG_DIR="/var/log/loguard"

SCRIPT_URL="https://raw.githubusercontent.com/$REPO/$BRANCH/setting/login-alert.sh"
BINARY_URL="https://raw.githubusercontent.com/$REPO/$BRANCH/setting/loguard"
CONFIG_URL="https://raw.githubusercontent.com/$REPO/$BRANCH/config/config.toml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    cat <<'EOF'

██▓     ▒█████    ▄████  █    ██  ▄▄▄       ██▀███  ▓█████▄ 
▓██▒    ▒██▒  ██▒ ██▒ ▀█▒ ██  ▓██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌
▒██░    ▒██░  ██▒▒██░▄▄▄░▓██  ▒██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌
▒██░    ▒██   ██░░▓█  ██▓▓▓█  ░██░░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌
░██████▒░ ████▓▒░░▒▓███▀▒▒▒█████▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▓ 
░ ▒░▓  ░░ ▒░▒░▒░  ░▒   ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒ 
░ ░ ▒  ░  ░ ▒ ▒░   ░   ░ ░░▒░ ░ ░   ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒ 
  ░ ░   ░ ░ ░ ▒  ░ ░   ░  ░░░ ░ ░   ░   ▒     ░░   ░  ░ ░  ░ 
    ░  ░    ░ ░        ░    ░           ░  ░   ░        ░    
                                                      ░      

               Real-time Linux Login Alert to Telegram
EOF
    echo -e "${NC}"
    echo "========================================================"
}

check_root() {
    [[ $EUID -eq 0 ]] || { echo -e "${RED}Error: This installer must be run as root (use sudo)${NC}"; exit 1; }
}

detect_os() {
    if [[ -f /etc/debian_version ]] || [[ -f /etc/lsb-release ]]; then OS="debian"
    elif [[ -f /etc/arch-release ]]; then OS="arch"
    elif [[ -f /etc/almalinux-release ]] || [[ -f /etc/rocky-release ]] || [[ -f /etc/fedora-release ]] || [[ -f /etc/redhat-release ]]; then OS="rhel"
    else echo -e "${RED}Unsupported operating system${NC}"; exit 1; fi
}

install_dependencies() {
    echo -e "${YELLOW}Installing required packages...${NC}"
    case "$OS" in
        debian) apt update -qq >/dev/null; apt install -y curl jq >/dev/null ;;
        rhel) command -v dnf >/dev/null && dnf install -y curl jq >/dev/null 2>&1 || yum install -y curl jq >/dev/null 2>&1 ;;
        arch) pacman -Sy --noconfirm curl jq >/dev/null ;;
    esac
}

create_directories() { mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$BIN_DIR"; }

download_components() {
    echo -e "${YELLOW}Downloading Loguard components...${NC}"
    curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/loguard" && chmod +x "$INSTALL_DIR/loguard"
    curl -fsSL "$SCRIPT_URL" -o "$INSTALL_DIR/login-alert.sh" && chmod +x "$INSTALL_DIR/login-alert.sh"
    curl -fsSL "$CONFIG_URL" -o "$CONFIG_DIR/config.toml"
    ln -sf "$INSTALL_DIR/loguard" "$BIN_DIR/loguard"
}

finish_message() {
    echo
    echo -e "${GREEN}Loguard installed successfully!${NC}"
    echo
    echo -e "${YELLOW}Important: Monitoring is currently DISABLED${NC}"
    echo
    echo "Next steps:"
    echo "   1. Configure Telegram settings:"
    echo "      sudo loguard edit"
    echo "   2. Test connection:"
    echo "      sudo loguard test"
    echo "   3. Enable real-time alerts:"
    echo "      sudo loguard enable"
    echo
    echo "To disable later: sudo loguard disable"
    echo "To remove completely: sudo loguard uninstall"
    echo
    echo -e "${CYAN}Thank you for using Loguard!${NC}"
}

# Main execution
banner
check_root
detect_os
install_dependencies
create_directories
download_components
finish_message