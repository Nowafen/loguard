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

SCRIPT_URL="https://raw.githubusercontent.com/Nowafen/loguard/refs/heads/main/setting/login-alert.sh"
BINARY_URL="https://raw.githubusercontent.com/Nowafen/loguard/refs/heads/main/setting/loguard"
CONFIG_URL="https://raw.githubusercontent.com/Nowafen/loguard/refs/heads/main/config/config.toml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m'

start_time=$(date +%s.%N)

banner() {
    clear
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
    echo -e "${BOLD}=======================================================${NC}"
    echo
}

step() {
    echo -e "[${YELLOW}•${NC}] $1"
}

success() {
    echo -e "   ${GREEN}Success${NC} $1"
}

download_file() {
    local url="$1"
    local dest="$2"
    local name="$3"
    echo -n "   [${YELLOW}Download${NC}] $name... "
    local start=$(date +%s.%N)
    if curl -fsSL "$url" -o "$dest" --silent; then
        local size=$(du -h "$dest" 2>/dev/null | cut -f1 || echo "?")
        local elapsed=$(printf "%.1f" "$(echo "$(date +%s.%N) - $start" | bc -l 2>/dev/null || echo "0.0")")
        echo -e "${GREEN}Success${NC} ${GRAY}($size, ${elapsed}s)${NC}"
    else
        echo -e "${RED}Failed${NC}"
        exit 1
    fi
}

check_root() {
    step "Checking root privileges..."
    [[ $EUID -eq 0 ]] || { echo -e "   ${RED}Failed${NC} This installer must be run as root (use sudo)"; exit 1; }
    success "OK"
}

detect_os() {
    step "Detecting operating system..."
    if [[ -f /etc/debian_version ]] || [[ -f /etc/lsb-release ]]; then
        OS="debian"
        OS_NAME=$(lsb_release -ds 2>/dev/null || echo "Debian-based")
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
        OS_NAME="Arch Linux"
    elif [[ -f /etc/almalinux-release ]]; then OS="rhel"; OS_NAME="AlmaLinux"
    elif [[ -f /etc/rocky-release ]]; then OS="rhel"; OS_NAME="Rocky Linux"
    elif [[ -f /etc/fedora-release ]]; then OS="rhel"; OS_NAME="Fedora"
    else
        echo -e "   ${RED}Failed${NC} Unsupported operating system"
        exit 1
    fi
    success "$OS_NAME ($OS)"
}

install_dependencies() {
    step "Installing required packages (curl, jq)..."
    case "$OS" in
        debian) apt update -qq >/dev/null && apt install -y curl jq -qq >/dev/null && success "done" ;;
        rhel) (command -v dnf >/dev/null && dnf install -y curl jq -q >/dev/null) || (yum install -y curl jq -q >/dev/null 2>&1) && success "done" ;;
        arch) pacman -Sy --noconfirm curl jq >/dev/null 2>&1 && success "done" ;;
    esac
}

create_directories() {
    step "Creating directories..."
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$BIN_DIR" 2>/dev/null || true
    echo "      → $INSTALL_DIR"
    echo "      → $CONFIG_DIR"
    echo "      → $LOG_DIR"
    success "created"
}

download_components() {
    step "Downloading Loguard components..."
    download_file "$BINARY_URL" "$INSTALL_DIR/loguard" "Loguard manager"
    download_file "$SCRIPT_URL" "$INSTALL_DIR/login-alert.sh" "Alert script"
    download_file "$CONFIG_URL" "$CONFIG_DIR/config.toml" "Default configuration"

    step "Setting executable permissions..."
    chmod +x "$INSTALL_DIR/loguard" "$INSTALL_DIR/login-alert.sh"
    success "done"

    step "Creating global command symlink..."
    ln -sf "$INSTALL_DIR/loguard" "$BIN_DIR/loguard" 2>/dev/null || true
    success "/usr/local/bin/loguard → $INSTALL_DIR/loguard"
}

finish_message() {
    local total_time=$(printf "%.1f" "$(echo "$(date +%s.%N) - $start_time" | bc -l)")
    echo
    echo -e "   [${GREEN}Success${NC}] Installation completed in ${BOLD}${total_time}s${NC}"
    echo
    echo -e "${GREEN}${BOLD}Loguard installed successfully!${NC}"
    echo
    echo -e "${YELLOW}Important: Real-time monitoring is currently DISABLED${NC}"
    echo
    echo -e "${BOLD}Next steps:${NC}"
    echo "   1. Configure Telegram settings:"
    echo "      ${CYAN}sudo loguard edit${NC}"
    echo "   2. Test connection:"
    echo "      ${CYAN}sudo loguard test${NC}"
    echo "   3. Enable real-time alerts:"
    echo "      ${CYAN}sudo loguard enable${NC}"
    echo
    echo -e "   To disable later: ${GRAY}sudo loguard disable${NC}"
    echo -e "   To remove completely: ${GRAY}sudo loguard uninstallmelden "

    echo
    echo -e "${CYAN}${BOLD}Thank you for using Loguard!${NC}"
    echo
}

# Main execution
banner
check_root
detect_os
install_dependencies
create_directories
download_components
finish_message