#!/bin/bash
# Splunk Universal Forwarder Installer for Linux
# Interactive version with credential prompts

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m'

# Configuration
SPLUNK_VERSION="9.4.0"
SPLUNK_BUILD="6b4ebe426ca6"
Splunk_Package_TGZ="splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-amd64.tgz"
Splunk_Download_URL="https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/linux/${Splunk_Package_TGZ}"
Install_DIR="/opt/splunkforwarder"
Receiver_Port="9997"

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Splunk Universal Forwarder Installer - Linux    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo $0${NC}"
    exit 1
fi

# Prompt for Splunk Enterprise server IP
echo -e "${YELLOW}Enter your Splunk Enterprise server IP address:${NC}"
read -p "Indexer IP: " INDEXER

if [ -z "$INDEXER" ]; then
    echo -e "${RED}Error: Indexer IP cannot be empty!${NC}"
    exit 1
fi

# Validate IP format (basic check)
if ! [[ $INDEXER =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${YELLOW}Warning: IP format may be incorrect. Continue anyway? (y/N)${NC}"
    read -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Prompt for admin username
echo -e "${YELLOW}Enter Splunk admin username (default: admin):${NC}"
read -p "Username: " USERNAME
USERNAME=${USERNAME:-admin}

# Prompt for admin password (hidden input)
echo -e "${YELLOW}Enter Splunk admin password:${NC}"
read -s -p "Password: " PASS
echo

if [ -z "$PASS" ]; then
    echo -e "${RED}Error: Password cannot be empty!${NC}"
    exit 1
fi

# Confirm password
echo -e "${YELLOW}Confirm password:${NC}"
read -s -p "Password: " PASS_CONFIRM
echo

if [ "$PASS" != "$PASS_CONFIRM" ]; then
    echo -e "${RED}Error: Passwords do not match!${NC}"
    exit 1
fi

# Summary
echo ""
echo -e "${BLUE}Configuration Summary:${NC}"
echo -e "  Indexer IP:    ${GREEN}${INDEXER}${NC}"
echo -e "  Receiver Port: ${GREEN}${Receiver_Port}${NC}"
echo -e "  Username:      ${GREEN}${USERNAME}${NC}"
echo -e "  Install Dir:   ${GREEN}${Install_DIR}${NC}"
echo ""
read -p "Proceed with installation? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Installation cancelled.${NC}"
    exit 0
fi

# Check if already installed
if [ -d "$Install_DIR" ]; then
    echo -e "${YELLOW}Splunk Forwarder already installed at $Install_DIR${NC}"
    read -p "Remove and reinstall? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Stopping and removing existing installation...${NC}"
        $Install_DIR/bin/splunk stop 2>/dev/null || true
        pkill -9 splunk 2>/dev/null || true
        rm -rf $Install_DIR
    else
        exit 0
    fi
fi

# Install function
install_splunk() {
    echo -e "${BLUE}Downloading Splunk Universal Forwarder...${NC}"
    
    if [ -f "$Splunk_Package_TGZ" ]; then
        echo -e "${GREEN}Package already exists, skipping download${NC}"
    else
        ( wget --no-check-certificate -O $Splunk_Package_TGZ $Splunk_Download_URL || \
          curl -k -o $Splunk_Package_TGZ $Splunk_Download_URL || \
          fetch -o $Splunk_Package_TGZ $Splunk_Download_URL )
        
        if [ ! -f "$Splunk_Package_TGZ" ]; then
            echo -e "${RED}Download failed!${NC}"
            exit 1
        fi
    fi

    echo -e "${BLUE}Extracting Splunk Forwarder tarball...${NC}"
    tar -xzf $Splunk_Package_TGZ -C /opt
    
    echo -e "${GREEN}Extraction complete.${NC}"
}

# Set admin credentials
set_admin() {
    echo -e "${BLUE}Setting Splunk admin credentials...${NC}"
    User_Seed_File="$Install_DIR/etc/system/local/user-seed.conf"
    mkdir -p "$Install_DIR/etc/system/local"
    
    cat > $User_Seed_File <<EOF
[user_info]
USERNAME = $USERNAME
PASSWORD = $PASS
EOF
    
    chown root:root $User_Seed_File
    chmod 600 $User_Seed_File
    echo -e "${GREEN}Credentials configured.${NC}"
}

# Setup monitors
setup_monitors() {
    echo -e "${BLUE}Setting up log monitors...${NC}"
    Monitor_Config="$Install_DIR/etc/system/local/inputs.conf"

    OS_Monitors="
[monitor:///var/log/secure]
index = main
sourcetype = linux:secure

[monitor:///var/log/auth.log]
index = main
sourcetype = linux:auth

[monitor:///var/log/syslog]
index = main
sourcetype = syslog

[monitor:///var/log/messages]
index = main
sourcetype = syslog
"
    cat > $Monitor_Config <<EOL
$OS_Monitors
EOL
    
    chown root:root $Monitor_Config
    echo -e "${GREEN}Log monitors configured.${NC}"
}

# Configure forwarder
configure_forwarder() {
    echo -e "${BLUE}Configuring forwarder to send logs to ${INDEXER}:${Receiver_Port}...${NC}"
    $Install_DIR/bin/splunk add forward-server $INDEXER:$Receiver_Port -auth $USERNAME:$PASS
    echo -e "${GREEN}Forwarder configured.${NC}"
}

# Restart with retry logic
restart_splunk() {
    local max_attempts=3
    local attempt=1
    local timeout=30

    echo -e "${BLUE}Restarting Splunk Forwarder...${NC}"

    while [ $attempt -le $max_attempts ]; do
        $Install_DIR/bin/splunk restart &>/dev/null &
        local splunk_pid=$!

        sleep $timeout

        if $Install_DIR/bin/splunk status | grep -q "running"; then
            echo -e "${GREEN}Splunk Forwarder restarted successfully.${NC}"
            return 0
        fi

        echo -e "${RED}Attempt $attempt: Failed to restart. Retrying...${NC}"
        attempt=$((attempt + 1))
        sleep 5
    done

    echo -e "${RED}Failed to restart after $max_attempts attempts.${NC}"
    echo -e "${YELLOW}Check logs: tail -50 $Install_DIR/var/log/splunk/splunkd.log${NC}"
    return 1
}

# Main installation
install_splunk

set_admin

if [ -d "$Install_DIR/bin" ]; then
    echo -e "${BLUE}Starting Splunk Forwarder...${NC}"
    $Install_DIR/bin/splunk start --accept-license --answer-yes --no-prompt
    $Install_DIR/bin/splunk enable boot-start

    setup_monitors

    configure_forwarder

    if ! restart_splunk; then
        echo -e "${RED}Installation incomplete.${NC}"
        exit 1
    fi

    # Get forwarder version
    echo ""
    echo -e "${BLUE}Installed version:${NC}"
    $Install_DIR/bin/splunk version

    # Verify connection
    echo ""
    echo -e "${BLUE}Forward server configuration:${NC}"
    $Install_DIR/bin/splunk list forward-server -auth $USERNAME:$PASS

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Installation Complete!                    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Forwarding to:${NC} ${INDEXER}:${Receiver_Port}"
    echo -e "${GREEN}Install location:${NC} ${Install_DIR}"
    echo ""
    echo -e "${BLUE}Useful commands:${NC}"
    echo "  sudo $Install_DIR/bin/splunk status"
    echo "  sudo $Install_DIR/bin/splunk restart"
    echo "  sudo $Install_DIR/bin/splunk list forward-server"
    echo "  sudo tail -f $Install_DIR/var/log/splunk/splunkd.log"
    echo ""
    echo -e "${YELLOW}Verify data in Splunk Enterprise:${NC}"
    echo "  index=main host=$(hostname) | head 100"
    echo ""
else
    echo -e "${RED}Installation directory not found. Something went wrong.${NC}"
    exit 1
fi

exit 0
