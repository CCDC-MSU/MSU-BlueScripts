#!/bin/bash
# CCDC Bootstrap Script - Sets up fabric deployment framework on jump server
set -e

echo "=========================================="
echo "CCDC Fabric Deploy Bootstrap"
echo "=========================================="

# Navigate to home directory and create workspace
cd ~
echo "[+] Creating workspace directory..."
rm -rf ccdc-scripts 2>/dev/null || true
mkdir -p ccdc-workspace
cd ccdc-workspace

# Update system packages
echo "[+] Updating system packages..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv git curl
elif command -v yum >/dev/null 2>&1; then
    sudo yum update -y
    sudo yum install -y python3 python3-pip git curl
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf update -y
    sudo dnf install -y python3 python3-pip git curl
else
    echo "[!] Unsupported package manager. Please install python3, pip, and git manually."
    exit 1
fi

# Verify Python installation
echo "[+] Verifying Python installation..."
python3 --version
pip3 --version

# Clone the repository
echo "[+] Cloning CCDC scripts repository..."
# TODO: Replace with actual repository URL
REPO_URL="https://github.com/your-org/ccdc-scripts.git"
echo "[!] Please update REPO_URL in this script with your actual repository"
# Uncomment the following line once you set the correct repository URL:
git clone "$REPO_URL" ccdc-scripts

# For now, create the directory structure manually
mkdir -p ccdc-scripts/fabric_deploy
cd ccdc-scripts/fabric_deploy

# Create Python virtual environment
echo "[+] Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "[+] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[+] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[+] Installing Python dependencies..."
# Create requirements.txt if it doesn't exist
cat > requirements.txt << EOF
fabric>=3.2.2
invoke>=2.2.0
paramiko>=3.4.0
pyyaml>=6.0
EOF

pip install -r requirements.txt

# Create basic configuration files
echo "[+] Creating initial configuration..."

# Create config.yaml if it doesn't exist
if [ ! -f config.yaml ]; then
    cat > config.yaml << 'EOF'
# CCDC Hardening Deployment Configuration

# Default connection settings
connection:
  timeout: 30
  connect_timeout: 10
  user: "root"
  password: "CHANGE_ME_BEFORE_USE"  # IMPORTANT: Change this!

# Logging configuration
logging:
  level: "INFO"
  file: "ccdc_deployment.log"

# Script deployment mapping based on OS type
deployment_profiles:
  debian_ubuntu:
    priority_scripts:
      - "scripts/linux/01-initial-hardening.sh"
      - "scripts/linux/02-change-passwords.sh" 
      - "scripts/linux/03-ssh-hardening.sh"
      - "scripts/linux/04-firewall-setup.sh"
    
  centos_rhel:
    priority_scripts:
      - "scripts/linux/01-initial-hardening.sh"
      - "scripts/linux/02-change-passwords.sh"
      - "scripts/linux/03-ssh-hardening.sh"
      - "scripts/linux/04-firewall-setup.sh"

# Script categories for selective deployment
script_categories:
  critical:
    - "scripts/linux/02-change-passwords.sh"
    - "scripts/linux/03-ssh-hardening.sh"
  firewall:
    - "scripts/linux/04-firewall-setup.sh"
  monitoring:
    - "scripts/linux/05-monitoring-setup.sh"
EOF
fi

# Create hosts.txt template
if [ ! -f hosts.txt ]; then
    cat > hosts.txt << 'EOF'
# CCDC Target Hosts with Credentials
# Supported formats:
# 1. host                          (uses config.yaml defaults)
# 2. host:user:password            (password authentication)
# 3. host:user:keyfile             (SSH key authentication)
# 4. host:user:password:port       (custom port)

# Examples:
# 192.168.1.10                     # Uses defaults from config.yaml
# 192.168.1.11:root:changeme123    # Password auth
# 192.168.1.12:admin:newpass       # Different user/password
# 192.168.1.13:root:~/.ssh/id_rsa  # SSH key auth
# 192.168.1.14:root:mypass:2222    # Custom SSH port

# Add your target hosts below:
# 10.0.1.100:root:your-password-here
EOF
fi

# Create scripts directory structure
echo "[+] Creating scripts directory structure..."
mkdir -p scripts/linux scripts/windows

# Set up SSH key if it doesn't exist
echo "[+] Setting up SSH keys..."
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "[!] No SSH key found. Generating new SSH key..."
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
    echo "[+] SSH key generated at ~/.ssh/id_rsa"
    echo "[!] Remember to copy your public key to target hosts:"
    echo "    ssh-copy-id user@target-host"
fi

# Create activation script for convenience
cat > activate.sh << 'EOF'
#!/bin/bash
# Convenience script to activate the virtual environment
source venv/bin/activate
echo "Virtual environment activated. You can now run fabric commands:"
echo "  fab test-connection --host TARGET_IP"
echo "  fab discover --host TARGET_IP"
echo "  fab harden"
echo ""
echo "Don't forget to:"
echo "1. Update config.yaml with your default password"
echo "2. Add target hosts to hosts.txt"
echo "3. Copy SSH keys to target hosts if using key auth"
EOF
chmod +x activate.sh

echo ""
echo "=========================================="
echo "Bootstrap Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Update the REPO_URL in this script and re-run to clone actual repository"
echo "2. Edit config.yaml and change the default password"
echo "3. Add your target hosts to hosts.txt"
echo "4. Activate the environment: source activate.sh"
echo "5. Test connectivity: fab test-connection --host TARGET_IP"
echo "6. Run discovery: fab harden"
echo ""
echo "Current location: $(pwd)"
echo "Activate with: source activate.sh"
