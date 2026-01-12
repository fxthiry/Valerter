#!/bin/bash
set -euo pipefail

# Resolve script directory for portable path resolution
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check root
if [[ $EUID -ne 0 ]]; then
   printf "${RED}Error: This script must be run as root${NC}\n"
   exit 1
fi

# Variables
BINARY_PATH="/usr/local/bin/valerter"
CONFIG_DIR="/etc/valerter"
SYSTEMD_DIR="/etc/systemd/system"
USER="valerter"
GROUP="valerter"

printf "${GREEN}Installing valerter...${NC}\n"

# 1. Create system group and user
if ! getent group "$GROUP" &>/dev/null; then
    echo "Creating system group '$GROUP'..."
    groupadd --system "$GROUP"
fi

if ! id "$USER" &>/dev/null; then
    echo "Creating system user '$USER'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$GROUP" "$USER"
fi

# 2. Copy binary
echo "Installing binary to $BINARY_PATH..."
# Check multiple locations: release archive (same dir), or cargo build outputs
if [[ -f "$SCRIPT_DIR/valerter" ]]; then
    # Release archive: binary is in same directory as install.sh
    cp "$SCRIPT_DIR/valerter" "$BINARY_PATH"
elif [[ -f "$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/valerter" ]]; then
    # Musl build from cargo
    cp "$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/valerter" "$BINARY_PATH"
elif [[ -f "$PROJECT_DIR/target/release/valerter" ]]; then
    # Standard release build from cargo
    cp "$PROJECT_DIR/target/release/valerter" "$BINARY_PATH"
else
    printf "${RED}Error: Binary not found. Run 'cargo build --release' first.${NC}\n"
    exit 1
fi
chmod 755 "$BINARY_PATH"

# 3. Create config directory
echo "Creating config directory $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"
chown "$USER:$GROUP" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# 4. Copy example config if needed
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    # Check multiple locations: release archive (same dir), or project structure
    if [[ -f "$SCRIPT_DIR/config.example.yaml" ]]; then
        # Release archive: config is in same directory as install.sh
        echo "Copying example configuration..."
        cp "$SCRIPT_DIR/config.example.yaml" "$CONFIG_DIR/config.yaml"
        chown "$USER:$GROUP" "$CONFIG_DIR/config.yaml"
        chmod 600 "$CONFIG_DIR/config.yaml"
    elif [[ -f "$PROJECT_DIR/config/config.example.yaml" ]]; then
        # Development: config is in project config/ directory
        echo "Copying example configuration..."
        cp "$PROJECT_DIR/config/config.example.yaml" "$CONFIG_DIR/config.yaml"
        chown "$USER:$GROUP" "$CONFIG_DIR/config.yaml"
        chmod 600 "$CONFIG_DIR/config.yaml"
    else
        printf "${YELLOW}Warning: config.example.yaml not found, skipping config copy${NC}\n"
    fi
fi

# 5. Install systemd unit
echo "Installing systemd unit..."
# Check multiple locations: release archive (same dir), or project structure
if [[ -f "$SCRIPT_DIR/valerter.service" ]]; then
    cp "$SCRIPT_DIR/valerter.service" "$SYSTEMD_DIR/"
elif [[ -f "$PROJECT_DIR/systemd/valerter.service" ]]; then
    cp "$PROJECT_DIR/systemd/valerter.service" "$SYSTEMD_DIR/"
else
    printf "${RED}Error: valerter.service not found${NC}\n"
    exit 1
fi
systemctl daemon-reload

# 6. Enable service
echo "Enabling valerter service..."
systemctl enable valerter

echo ""
printf "${GREEN}Installation complete!${NC}\n"
echo ""
printf "${YELLOW}Post-installation steps:${NC}\n"
echo "1. Edit /etc/valerter/config.yaml with your VictoriaLogs URL, notifiers, and alert rules"
echo "2. Start the service: systemctl start valerter"
echo "3. Check status: systemctl status valerter"
echo "4. View logs: journalctl -u valerter -f"
