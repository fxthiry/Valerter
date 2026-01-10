#!/bin/bash
set -euo pipefail

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

USER="valerter"
GROUP="valerter"

printf "${YELLOW}Uninstalling valerter...${NC}\n"

# 1. Stop service if running
if systemctl is-active --quiet valerter 2>/dev/null; then
    echo "Stopping valerter service..."
    systemctl stop valerter
fi

# 2. Disable service
if systemctl is-enabled --quiet valerter 2>/dev/null; then
    echo "Disabling valerter service..."
    systemctl disable valerter
fi

# 3. Remove systemd unit
if [[ -f "/etc/systemd/system/valerter.service" ]]; then
    echo "Removing systemd unit..."
    rm /etc/systemd/system/valerter.service
    systemctl daemon-reload
fi

# 4. Remove binary
if [[ -f "/usr/local/bin/valerter" ]]; then
    echo "Removing binary..."
    rm /usr/local/bin/valerter
fi

# 5. Remove user
if id "$USER" &>/dev/null; then
    echo "Removing system user '$USER'..."
    userdel "$USER"
fi

# 6. Remove group (if no other members)
if getent group "$GROUP" &>/dev/null; then
    echo "Removing system group '$GROUP'..."
    groupdel "$GROUP" 2>/dev/null || true
fi

echo ""
printf "${GREEN}Uninstallation complete!${NC}\n"
echo ""
printf "${YELLOW}Note: Configuration files in /etc/valerter/ were NOT removed.${NC}\n"
echo "Remove manually if no longer needed: rm -rf /etc/valerter/"
