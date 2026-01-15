#!/bin/sh
# Bootstrap Python 3.12 using uv

echo "Bootstrapping Python 3.12 on $(hostname)..."

# 1. Install uv
if ! command -v uv >/dev/null 2>&1; then
    echo "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    
    # Source the env to get uv in path immediately for this session
    if [ -f "$HOME/.cargo/env" ]; then
        . "$HOME/.cargo/env"
    fi
else
    echo "uv already installed"
fi

UV_BIN="$HOME/.local/bin/uv"
# Fallback if installed elsewhere
if [ ! -f "$UV_BIN" ]; then
    if command -v uv >/dev/null 2>&1; then
        UV_BIN=$(command -v uv)
    else
        echo "Failed to find uv binary"
        exit 1
    fi
fi

echo "Using uv at: $UV_BIN"

# 2. Prepare directories
mkdir -p /root/python /root/python/bin

# 3. Install Python 3.12
echo "Installing Python 3.12..."
export UV_PYTHON_INSTALL_DIR=/root/python
export UV_PYTHON_BIN_DIR=/root/python/bin

# Use --force to ensure it installs even if it thinks it's there, or just run it
"$UV_BIN" python install 3.12 

# 4. Verify installation
PYTHON_BIN="/root/python/bin/python3.12"
if [ -f "$PYTHON_BIN" ]; then
    echo "Python 3.12 installed successfully at $PYTHON_BIN"
    "$PYTHON_BIN" --version
else
    echo "Failed to install Python 3.12"
    exit 1
fi
