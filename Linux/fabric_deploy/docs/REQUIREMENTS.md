# System Requirements and Setup

Quick reference for setting up the CCDC Hardening Framework with Ansible integration.

## Control Node Requirements

### Required Software

**1. Python 3.8 or higher**
```bash
python3 --version
# Expected: Python 3.8.x or higher
```

**2. uv (Python package manager)**
```bash
uv --version
# Expected: uv 0.x.x

# If not installed:
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**3. Ansible 2.14 or higher** ✨ **NEW REQUIREMENT**
```bash
ansible --version
# Expected: ansible [core 2.14.x] or higher

# If not installed (choose one):
# Option 1: System package manager (recommended)
sudo apt install ansible          # Debian/Ubuntu
sudo dnf install ansible          # RHEL/CentOS/Fedora
brew install ansible              # macOS

# Option 2: Python pip
pip install ansible
```

**4. Git**
```bash
git --version
```

**5. SSH Client**
```bash
ssh -V
# OpenSSH 7.0 or higher recommended
```

### Optional Software

- **tmux/screen**: For persistent sessions during competition
- **vim/nano**: For editing configuration files
- **jq**: For parsing JSON logs

---

## Target Host Requirements

**Minimal requirements** - the system is designed to work with locked-down hosts:

### Required
- ✅ SSH server running (port 22 or custom)
- ✅ Valid credentials (user/password or SSH key)
- ✅ Root or sudo access

### NOT Required
- ❌ Python (Ansible can bootstrap if needed)
- ❌ Ansible
- ❌ Specific shell (works with sh, bash, csh, etc.)
- ❌ Specific package manager (auto-detected)

---

## Pre-Competition Setup Checklist

### ⏰ T-30 Minutes (Before Competition Starts)

- [ ] **1. Clone the repository**
  ```bash
  git clone <repo-url>
  cd Linux/fabric_deploy
  ```

- [ ] **2. Verify Ansible is installed**
  ```bash
  ansible --version
  # Should show version 2.14 or higher
  ```

- [ ] **3. Test the Python environment**
  ```bash
  uv run fab --version
  # Should show Fabric version
  ```

- [ ] **4. Prepare configuration files**
  ```bash
  # hosts.txt - Target inventory
  # Format: IP:User:Password:Port:FriendlyName
  vim hosts.txt

  # users.json - User definitions
  vim users.json

  # Verify SSH keys exist
  ls -l keys/
  ```

- [ ] **5. Test connectivity** (if you have test environment)
  ```bash
  # Test SSH manually
  ssh root@<test-host>

  # Test Fabric connectivity
  uv run fab discover-all

  # Test Ansible connectivity
  uv run fab ansible-ping
  ```

- [ ] **6. Test a single module** (dry run)
  ```bash
  uv run fab test-module --module=logging_setup
  ```

### ⏰ T-0 (Competition Starts)

- [ ] **1. Update hosts.txt with real IPs**
  ```bash
  vim hosts.txt
  # Get IPs from competition packet
  ```

- [ ] **2. Update users.json with team users**
  ```bash
  vim users.json
  # Add your team members
  ```

- [ ] **3. Verify credentials work**
  ```bash
  # Quick SSH test to one host
  ssh root@<first-host>
  ```

- [ ] **4. Run discovery** (reconnaissance - no changes)
  ```bash
  uv run fab discover-all
  # Review: reports/<hostname>/<timestamp>.md
  ```

- [ ] **5. Launch full hardening**
  ```bash
  uv run fab harden
  ```

- [ ] **6. Monitor progress**
  ```bash
  # In another terminal/tmux pane:
  tail -f logs/harden/*/$(ls -t logs/harden/*/ | head -1)
  ```

---

## Verification Commands

### Check Control Node Setup

```bash
# All-in-one verification script
cat << 'EOF' > /tmp/verify-setup.sh
#!/bin/bash
echo "=== Control Node Setup Verification ==="
echo

echo "[1/5] Python version:"
python3 --version || echo "❌ Python not found"

echo "[2/5] uv version:"
uv --version || echo "❌ uv not installed"

echo "[3/5] Ansible version:"
ansible --version | head -1 || echo "❌ Ansible not installed"

echo "[4/5] Fabric test:"
cd /root/Desktop/MSU-BlueScripts/Linux/fabric_deploy
uv run fab --version || echo "❌ Fabric environment broken"

echo "[5/5] Ansible config:"
ls ansible/ansible.cfg && echo "✅ Ansible config found" || echo "❌ Ansible config missing"

echo
echo "=== Status Summary ==="
if command -v ansible >/dev/null && command -v uv >/dev/null && command -v python3 >/dev/null; then
    echo "✅ All requirements met!"
else
    echo "❌ Missing requirements - see above"
fi
EOF

bash /tmp/verify-setup.sh
```

### Check Ansible Integration

```bash
# Test Ansible can reach hosts
cd /root/Desktop/MSU-BlueScripts/Linux/fabric_deploy
uv run fab ansible-ping

# Expected output:
# ✓ host1 | SUCCESS
# ✓ host2 | SUCCESS
# ...
```

### Check Configuration Files

```bash
# Verify all required files exist
cd /root/Desktop/MSU-BlueScripts/Linux/fabric_deploy

echo "hosts.txt:"
wc -l hosts.txt

echo "users.json:"
cat users.json | jq '.regular_users | length'

echo "SSH key:"
ls -lh keys/root-key.pub

echo "Ansible inventory (auto-generated):"
ls -lh ansible/inventory/hosts.yaml
```

---

## Common Setup Issues

### Issue: Ansible not found

**Symptoms:**
```
ansible-playbook: command not found
```

**Fix:**
```bash
# Install Ansible
sudo apt install ansible     # Debian/Ubuntu
sudo dnf install ansible     # RHEL/Fedora
pip install ansible          # Any OS

# Verify
ansible --version
```

---

### Issue: uv not found

**Symptoms:**
```
uv: command not found
```

**Fix:**
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add to PATH (if needed)
export PATH="$HOME/.cargo/bin:$PATH"
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc

# Verify
uv --version
```

---

### Issue: Python version too old

**Symptoms:**
```
Python 3.6.x
ERROR: Requires Python 3.8+
```

**Fix:**
```bash
# Ubuntu/Debian
sudo apt install python3.9

# RHEL/CentOS
sudo dnf install python39

# Update alternatives
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1
```

---

### Issue: Ansible inventory not generated

**Symptoms:**
```
ERROR: Inventory file not found: ansible/inventory/hosts.yaml
```

**Fix:**
```bash
# Manually trigger inventory generation
uv run fab ansible-sync

# Or regenerate directly
cd ansible
python3 generate_configs.py

# Verify
ls -lh inventory/hosts.yaml
```

---

## Environment Variables

### Optional Environment Variables

```bash
# Increase Ansible timeout (for slow networks)
export ANSIBLE_TIMEOUT=60

# Disable host key checking (for new hosts)
export ANSIBLE_HOST_KEY_CHECKING=False

# Enable Ansible debug mode
export ANSIBLE_DEBUG=True

# Set custom SSH key
export ANSIBLE_PRIVATE_KEY_FILE=~/.ssh/id_rsa
```

### Fabric Environment

```bash
# Increase Fabric timeout
export FABRIC_TIMEOUT=300

# Custom SSH config
export SSH_CONFIG_FILE=~/.ssh/config
```

---

## Quick Start (TL;DR)

```bash
# 1. Install requirements
sudo apt install ansible   # or: pip install ansible
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Clone and setup
git clone <repo>
cd Linux/fabric_deploy

# 3. Configure
vim hosts.txt     # Add your targets
vim users.json    # Add your users

# 4. Test
uv run fab ansible-ping
uv run fab discover-all

# 5. Harden
uv run fab harden

# 6. Monitor
tail -f logs/harden/*/*.log
```

---

## Resources

- **Main Documentation**: `docs/workflow_guide.md`
- **Ansible Integration**: `docs/ANSIBLE_INTEGRATION.md`
- **Logging Module**: `docs/README_logging_setup.md`
- **Ansible Docs**: https://docs.ansible.com/
- **Fabric Docs**: https://www.fabfile.org/
- **uv Docs**: https://github.com/astral-sh/uv

---

## Support Matrix

| Component | Minimum Version | Recommended | Tested |
|-----------|----------------|-------------|---------|
| Python | 3.8 | 3.10+ | 3.12 |
| Ansible | 2.14 | 2.16+ | 2.16.3 |
| uv | 0.1.0 | Latest | 0.5+ |
| Fabric | 3.0 | 3.2+ | 3.2.2 |
| Paramiko | 2.7 | 3.0+ | 3.4+ |

---

**Last Updated**: 2026-01-06 (Ansible integration added)
