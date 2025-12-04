#!/bin/bash
# Loguard Installer
# Real-time Linux login alerts to Telegram
# https://github.com/Nowafen/loguard

set -e

REPO="mirage-x/loguard"
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
    cat assets/banner.txt 2>/dev/null || cat <<'EOF'

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
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This installer must be run as root (use sudo)${NC}"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/debian_version ]] || [[ -f /etc/lsb-release ]]; then
        OS="debian"
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
    elif [[ -f /etc/almalinux-release ]] || [[ -f /etc/rocky-release ]] || [[ -f /etc/fedora-release ]] || [[ -f /etc/redhat-release ]]; then
        OS="rhel"
    else
        echo -e "${RED}Unsupported operating system${NC}"
        exit 1
    fi
}

install_dependencies() {
    echo -e "${YELLOW}Installing required packages...${NC}"
    case "$OS" in
        debian)
            apt update -qq >/dev/null
            apt install -y curl jq pamtester >/dev/null
            ;;
        rhel)
            if command -v dnf >/dev/null; then
                dnf install -y curl jq pamtester >/dev/null 2>&1
            else
                yum install -y curl jq pamtester >/dev/null 2>&1
            fi
            ;;
        arch)
            pacman -Sy --noconfirm curl jq >/dev/null
            ;;
    esac
}

create_directories() {
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$BIN_DIR"
}

download_components() {
    echo -e "${YELLOW}Downloading Loguard components...${NC}"

    echo "Downloading manager (loguard)..."
    curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/loguard"
    chmod +x "$INSTALL_DIR/loguard"

    echo "Downloading alert script..."
    curl -fsSL "$SCRIPT_URL" -o "$INSTALL_DIR/login-alert.sh"
    chmod +x "$INSTALL_DIR/login-alert.sh"

    echo "Downloading default configuration..."
    curl -fsSL "$CONFIG_URL" -o "$CONFIG_DIR/config.toml"

    # Global symlink
    ln -sf "$INSTALL_DIR/loguard" "$BIN_DIR/loguard"
}

configure_pam() {
    echo -e "${YELLOW}Configuring PAM authentication...${NC}"
    local pam_line="session optional pam_exec.so stdout $INSTALL_DIR/login-alert.sh"

    for pam_file in common-session common-session-noninteractive; do
        local target="/etc/pam.d/$pam_file"
        [[ -f "$target" ]] || continue

        # Remove old Loguard lines if exist
        sed -i '/loguard\|login-alert\.sh/d' "$target" 2>/dev/null || true

        # Add new ones
        echo "# Loguard - Real-time login alerts" >> "$target"
        echo "$pam_line" >> "$target"
    done
}

finish_message() {
    echo
    echo -e "${GREEN}Loguard installed successfully!${NC}"
    echo
    echo "Next steps:"
    echo "   1. Edit the config file:"
    echo "      sudo nano $CONFIG_DIR/config.toml"
    echo "   2. Add your Telegram Bot Token and Chat ID"
    echo "   3. Test the connection:"
    echo "      sudo loguard test"
    echo "   4. Enable monitoring:"
    echo "      sudo loguard enable"
    echo
    echo "Available commands:"
    echo "   loguard status | enable | disable | test | logs | queue | edit | uninstall"
    echo
    echo "Thank you for using Loguard!"
}

# Main execution
banner
check_root
detect_os
install_dependencies
create_directories
download_components
configure_pam
finish_message