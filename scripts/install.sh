#!/bin/bash
# Deep Eye Installation Script for Linux/Mac

echo "===================================="
echo "  Deep Eye Installation Script"
echo "===================================="
echo ""

# Check Python installation
echo "[*] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "[+] Python found: $PYTHON_VERSION"
else
    echo "[!] Python 3.8+ not found. Please install Python first."
    exit 1
fi

# Create virtual environment
echo ""
echo "[*] Creating virtual environment..."
if [ -d "../venv" ]; then
    echo "[*] Virtual environment already exists. Skipping..."
else
    cd ..
    python3 -m venv venv
    cd scripts
    echo "[+] Virtual environment created"
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source ../venv/bin/activate

# Upgrade pip
echo ""
echo "[*] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "[*] Installing dependencies..."
pip install -r ../requirements.txt

if [ $? -ne 0 ]; then
    echo "[!] Failed to install dependencies"
    exit 1
fi

echo "[+] Dependencies installed successfully"

# Create necessary directories
echo ""
echo "[*] Creating necessary directories..."
mkdir -p ../logs ../data ../reports ../templates

echo "[+] Directories created"

# Copy configuration template
echo ""
echo "[*] Setting up configuration..."
if [ ! -f "../config/config.yaml" ]; then
    cp ../config/config.example.yaml ../config/config.yaml
    echo "[+] Configuration file created: config/config.yaml"
    echo "[!] IMPORTANT: Edit config/config.yaml and add your API keys!"
else
    echo "[*] Configuration file already exists"
fi

# Make scripts executable
chmod +x ../deep_eye.py
chmod +x ../examples/*.py

# Installation complete
echo ""
echo "===================================="
echo "  Installation Complete!"
echo "===================================="
echo ""
echo "Next steps:"
echo "1. Edit config/config.yaml and add your AI provider API keys"
echo "2. Activate virtual environment: source venv/bin/activate"
echo "3. Run Deep Eye: python deep_eye.py -u https://example.com"
echo ""
echo "For help: python deep_eye.py --help"
echo "Documentation: See README.md and docs/ folder"
echo ""
echo "WARNING: Only use on authorized targets!"
echo ""
