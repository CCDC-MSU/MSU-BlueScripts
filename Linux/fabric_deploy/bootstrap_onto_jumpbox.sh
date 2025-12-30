#!/bin/bash
# CCDC Bootstrap Script - Sets up fabric deployment framework on jump server
# Assumes it is run from the Linux/fabric_deploy directory of the repo
set -e

echo "=========================================="
echo "CCDC Fabric Deploy Bootstrap"
echo "=========================================="

# Check execution context
if [ ! -f "fabfile.py" ]; then
    echo "[!] Error: fabfile.py not found!"
    echo "    Please run this script from the Linux/fabric_deploy directory."
    echo "    Example: cd Linux/fabric_deploy && ./bootstrap_onto_jumpbox.sh"
    exit 1
fi

echo "[+] Execution context verified."

# Update system packages and install dependencies
echo "[+] Updating system packages and installing dependencies..."
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
    echo "[!] Unsupported package manager. Please install python3, pip, python3-venv, git, and curl manually."
    exit 1
fi

# Create Python virtual environment
echo "[+] Creating Python virtual environment..."
if [ -d "venv" ]; then
    echo "    venv already exists, skipping creation."
else
    python3 -m venv venv
fi

# Activate virtual environment
echo "[+] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[+] Upgrading pip..."
pip install --upgrade pip

# Install dependencies from requirements.txt
if [ -f "requirements.txt" ]; then
    echo "[+] Installing Python dependencies from requirements.txt..."
    pip install -r requirements.txt
else
    echo "[!] Warning: requirements.txt not found! Creating default..."
    cat > requirements.txt << EOF
fabric>=3.2.2
invoke>=2.2.0
paramiko>=3.4.0
pyyaml>=6.0
EOF
    pip install -r requirements.txt
fi

# Configuration Checks
echo "[+] Checking configuration files..."

if [ ! -f "config.yaml" ]; then
    echo "[!] config.yaml missing! (This should be in the repo)"
    echo "    Creating default template..."
    # (Insert default config.yaml creation logic here if needed, but assuming repo has it)
    # For now, just warn as it should be there.
fi

if [ ! -f "users.json" ]; then
    echo "[!] users.json missing! Please create it from templates or docs."
fi

if [ ! -f "hosts.txt" ]; then
    echo "[!] hosts.txt missing! Please create it."
    # Create template if missing
    cat > hosts.txt << 'EOF'
# CCDC Target Hosts with Credentials
# Supported formats:
# 1. host                          (uses config.yaml defaults)
# 2. host:user:password            (password authentication)
# 3. host:user:keyfile             (SSH key authentication)
# 4. host:user:password:port       (custom port)
# 5. host:user:password:name       (friendly name)

# Example:
# 192.168.1.10:root:password:Web-Server
EOF
    echo "    Created hosts.txt template."
fi

# Check for SSH Keys
if [ ! -d "keys" ]; then
    mkdir keys
fi

if [ ! -f "keys/test-root-key.private" ]; then
    echo "[!] Warning: keys/test-root-key.private missing."
    echo "    This key is needed for root persistence."
    echo "    Please generate it: ssh-keygen -f keys/test-root-key.private -N ''"
fi

# Create activation script for convenience
echo "[+] Creating activate.sh helper..."
cat > activate.sh << 'EOF'
#!/bin/bash
# Convenience script to activate the virtual environment
source venv/bin/activate
echo "Virtual environment activated. You can now run fabric commands:"
echo "  fab test-connection --host <host>"
echo "  fab discover-all"
echo "  fab harden"
echo ""
EOF
chmod +x activate.sh

echo ""
echo "=========================================="
echo "Bootstrap Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Activate the environment: source activate.sh"
echo "2. Edit config.yaml and hosts.txt if needed."
echo "3. Run 'fab harden' to start protecting your systems."
echo ""
