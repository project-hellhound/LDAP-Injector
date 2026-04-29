#!/bin/bash
# install.sh — Setup for DNwatch v1.0 [HELLHOUND-class]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[*] Starting DNwatch installation...${NC}"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is required but not installed. Aborting.${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${BLUE}[*] Creating virtual environment (.venv)...${NC}"
rm -rf .venv
python3 -m venv .venv 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] 'python3-venv' might be missing. Attempting to install...${NC}"
    sudo apt-get update && sudo apt-get install -y python3-venv
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Failed to create virtual environment. Please install 'python3-venv' manually.${NC}"
        exit 1
    fi
fi

# Define pip and python from venv
VENV_PIP="./.venv/bin/pip"
VENV_PYTHON="./.venv/bin/python3"

echo -e "${BLUE}[*] Installing dependencies in venv...${NC}"
$VENV_PIP install --upgrade pip
$VENV_PIP install requests beautifulsoup4 rich

# Setup CLI command via wrapper
echo -e "${BLUE}[*] Creating dnwatch wrapper...${NC}"
cat <<EOF > dnwatch
#!/bin/bash
REAL_PATH=\$(dirname "\$(readlink -f "\$0")")
"\$REAL_PATH/.venv/bin/python3" "\$REAL_PATH/dnwatch.py" "\$@"
EOF
chmod +x dnwatch

# Install the package in editable mode within venv
echo -e "${BLUE}[*] Finalizing setup...${NC}"
$VENV_PIP install -e .

# Create global symbolic link
echo -e "${BLUE}[*] Creating global symbolic link in /usr/local/bin/dnwatch...${NC}"
REAL_WRAPPER_PATH=$(readlink -f "dnwatch")
if [ -w "/usr/local/bin" ]; then
    ln -sf "$REAL_WRAPPER_PATH" /usr/local/bin/dnwatch
    GLOBAL_OK=1
else
    echo -e "${YELLOW}[!] Permission denied for /usr/local/bin. Attempting with sudo...${NC}"
    sudo ln -sf "$REAL_WRAPPER_PATH" /usr/local/bin/dnwatch
    if [ $? -eq 0 ]; then GLOBAL_OK=1; fi
fi

if [ $? -eq 0 ] && [ "$GLOBAL_OK" == "1" ]; then
    echo -e "${GREEN}[+] DNwatch installed successfully!${NC}"
    echo -e "${YELLOW}[!] You can now run 'dnwatch' from anywhere in your terminal.${NC}"
else
    echo -e "${GREEN}[+] DNwatch installed locally.${NC}"
    echo -e "${YELLOW}[!] Global link failed. You can still run it as './dnwatch' or add this directory to your PATH.${NC}"
fi
