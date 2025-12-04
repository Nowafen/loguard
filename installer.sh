#!/bin/bash
set -e

REPO="mirage-x/loguard"  # <-- اینجا یوزرنیم خودت رو بزن
BRANCH="main"
INSTALL_DIR="/opt/loguard"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/loguard"
LOG_DIR="/var/log/loguard"
SCRIPT_URL="https://raw.githubusercontent.com/$REPO/$BRANCH/setting/login-alert.sh"
BINARY_URL="https://github.com/$REPO/releases/latest/download/loguard"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
    cat assets/banner.txt 2>/dev/null || echo -e "${YELLOW}Loguard - Real-time Login Alert to Telegram${NC}"
    echo "========================================================"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This installer must be run as root${NC}"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/debian_version ]]; then
        OS="debian"
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
    elif [[ -f /etc/almalinux-release || -f /etc/rocky-release || -f /etc/fedora-release ]]; then
        OS="rhel"
    else
        echo -e "${RED}Unsupported OS${NC}"
        exit 1
    fi
}

install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    if [[ $OS == "debian" ]]; then
        apt update -qq && apt install -y curl jq pamtester > /dev/null
    elif [[ $OS == "rhel" ]]; then
        dnf install -y curl jq pamtester > /dev/null 2>&1 || yum install -y curl jq pamtester > /dev/null 2>&1
    elif [[ $OS == "arch" ]]; then
        pacman -Sy --noconfirm curl jq > /dev/null
    fi
}

download_files() {
    echo -e "${YELLOW}Downloading Loguard components...${NC}"
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$BIN_DIR"

    # Download main binary
    echo "Downloading loguard binary..."
    curl -L -o "$INSTALL_DIR/loguard" "$BINARY_URL"
    chmod +x "$INSTALL_DIR/loguard"

    # Create symlink
    ln -sf "$INSTALL_DIR/loguard" "$BIN_DIR/loguard"

    # Download alert script
    curl -L -o "$INSTALL_DIR/login-alert.sh" "$SCRIPT_URL"
    chmod +x "$INSTALL_DIR/login-alert.sh"

    # Copy example config
    curl -L -o "$CONFIG_DIR/config.toml" "https://raw.githubusercontent.com/$REPO/$BRANCH/config/config.toml.example"
}

setup_pam() {
    echo -e "${YELLOW}Configuring PAM...${NC}"
    PAM_LINE="session optional pam_exec.so stdout $INSTALL_DIR/login-alert.sh"

    for file in common-session common-session-noninteractive; do
        if ! grep -q "loguard" "/etc/pam.d/$file" 2>/dev/null; then
            echo "# Loguard Login Alert" >> "/etc/pam.d/$file"
            echo "$PAM_LINE" >> "/etc/pam.d/$file"
        fi
    done
}

finish() {
    echo
    echo -e "${GREEN}Loguard installed successfully!${NC}"
    echo
    echo "Next steps:"
    echo "   1. Edit config: sudo nano $CONFIG_DIR/config.toml"
    echo "   2. Set your Telegram Bot Token and Chat ID"
    echo "   3. Test: sudo loguard test"
    echo "   4. Enable at boot: sudo loguard enable"
    echo
    echo "Commands: loguard [install|uninstall|enable|disable|status|logs|test|restart]"
    echo
}

banner
check_root
detect_os
install_dependencies
download_files
setup_pam
finish
