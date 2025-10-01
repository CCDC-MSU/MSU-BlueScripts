#!/bin/bash
# Splunk Enterprise Installer

set -e

# Configuration
SPLUNK_PACKAGE="splunk-9.3.2-d8bb32809498-Linux-x86_64.tgz"
INSTALL_DIR="/opt/splunk"
ADMIN_USER="admin"
ADMIN_PASS="ChangeMe123!"
RECEIVER_PORT="9997"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== Splunk Enterprise Installer ===${NC}"

# Check if package exists
if [ ! -f "$SPLUNK_PACKAGE" ]; then
    echo -e "${RED}Error: $SPLUNK_PACKAGE not found!${NC}"
    echo -e "${YELLOW}Please download it first with: ./splunkEnterprise.sh${NC}"
    exit 1
fi

# Check if already installed
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Splunk already installed at $INSTALL_DIR${NC}"
    read -p "Remove and reinstall? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Stopping and removing existing installation...${NC}"
        sudo $INSTALL_DIR/bin/splunk stop 2>/dev/null || true
        sudo rm -rf $INSTALL_DIR
    else
        exit 0
    fi
fi

# Extract Splunk
echo -e "${BLUE}Extracting Splunk Enterprise...${NC}"
sudo tar -xzf "$SPLUNK_PACKAGE" -C /opt/

# Set ownership
echo -e "${BLUE}Setting ownership...${NC}"
sudo chown -R $(whoami):$(whoami) $INSTALL_DIR

# Set admin password (before first start)
echo -e "${BLUE}Setting admin credentials...${NC}"
sudo mkdir -p $INSTALL_DIR/etc/system/local
sudo bash -c "cat > $INSTALL_DIR/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = $ADMIN_USER
PASSWORD = $ADMIN_PASS
EOF

# Start Splunk
echo -e "${BLUE}Starting Splunk Enterprise (this may take a minute)...${NC}"
sudo $INSTALL_DIR/bin/splunk start --accept-license --answer-yes --no-prompt

# Enable boot start
echo -e "${BLUE}Enabling boot-start...${NC}"
sudo $INSTALL_DIR/bin/splunk enable boot-start -user $(whoami)

# Enable receiving on port 9997 (for forwarders)
echo -e "${BLUE}Enabling receiver on port ${RECEIVER_PORT}...${NC}"
sudo $INSTALL_DIR/bin/splunk enable listen $RECEIVER_PORT -auth $ADMIN_USER:$ADMIN_PASS

# Get IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Splunk Enterprise Installation Complete!   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📊 Splunk Web Interface:${NC} http://${SERVER_IP}:8000"
echo -e "${GREEN}👤 Username:${NC} ${ADMIN_USER}"
echo -e "${GREEN}🔑 Password:${NC} ${ADMIN_PASS}"
echo -e "${GREEN}📡 Receiver Port:${NC} ${RECEIVER_PORT}"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Change the default password!${NC}"
echo -e "${BLUE}Access Splunk at: http://localhost:8000${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Open browser to http://localhost:8000"
echo -e "  2. Login with credentials above"
echo -e "  3. Change the admin password"
echo -e "  4. Configure forwarders to send data to ${SERVER_IP}:${RECEIVER_PORT}"
