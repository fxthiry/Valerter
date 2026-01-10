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
if [[ -f "$PROJECT_DIR/target/release/valerter" ]]; then
    cp "$PROJECT_DIR/target/release/valerter" "$BINARY_PATH"
elif [[ -f "$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/valerter" ]]; then
    cp "$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/valerter" "$BINARY_PATH"
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
    if [[ -f "$PROJECT_DIR/config/config.example.yaml" ]]; then
        echo "Copying example configuration..."
        cp "$PROJECT_DIR/config/config.example.yaml" "$CONFIG_DIR/config.yaml"
        chown "$USER:$GROUP" "$CONFIG_DIR/config.yaml"
        chmod 640 "$CONFIG_DIR/config.yaml"
    else
        printf "${YELLOW}Warning: config.example.yaml not found, skipping config copy${NC}\n"
    fi
fi

# 5. Create environment file template
if [[ ! -f "$CONFIG_DIR/environment" ]]; then
    echo "Creating environment file template..."
    cat > "$CONFIG_DIR/environment" <<EOF
# Valerter environment variables
# Set your Mattermost webhook URL here (required)
MATTERMOST_WEBHOOK=

# Optional: VictoriaLogs auth token
# VL_AUTH_TOKEN=

# Log level (debug, info, warn, error)
# RUST_LOG=info

# Log format (text, json)
# LOG_FORMAT=text
EOF
    chown "$USER:$GROUP" "$CONFIG_DIR/environment"
    chmod 600 "$CONFIG_DIR/environment"
fi

# 6. Install systemd unit
echo "Installing systemd unit..."
cp "$PROJECT_DIR/systemd/valerter.service" "$SYSTEMD_DIR/"
systemctl daemon-reload

# 7. Enable service
echo "Enabling valerter service..."
systemctl enable valerter

echo ""
printf "${GREEN}Installation complete!${NC}\n"
echo ""
printf "${YELLOW}Post-installation steps:${NC}\n"
echo "1. Edit /etc/valerter/config.yaml with your VictoriaLogs URL and alert rules"
echo "2. Edit /etc/valerter/environment and set MATTERMOST_WEBHOOK"
echo "3. Start the service: systemctl start valerter"
echo "4. Check status: systemctl status valerter"
echo "5. View logs: journalctl -u valerter -f"
