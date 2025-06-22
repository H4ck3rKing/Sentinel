#!/bin/bash
set -e

# This script installs the Go tools required by the Sentinel framework.
# It should be run with sudo privileges as part of the post-install process.

echo "[*] Installing required Go tools to /usr/local/bin..."
echo "This may take a few minutes..."

# Set GOBIN to ensure all go install commands place binaries in /usr/local/bin
export GOBIN=/usr/local/bin

# Project Discovery tools
echo "[+] Installing subfinder..."
/usr/local/go/bin/go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo "[+] Installing dnsx..."
/usr/local/go/bin/go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
echo "[+] Installing naabu..."
/usr/local/go/bin/go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
echo "[+] Installing httpx..."
/usr/local/go/bin/go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "[+] Installing katana..."
/usr/local/go/bin/go install -v github.com/projectdiscovery/katana/cmd/katana@latest
echo "[+] Installing gau..."
/usr/local/go/bin/go install -v github.com/lc/gau/v2/cmd/gau@latest

# Other Go-based tools
echo "[+] Installing ffuf..."
/usr/local/go/bin/go install -v github.com/ffuf/ffuf@latest
echo "[+] Installing gowitness..."
/usr/local/go/bin/go install -v github.com/sensepost/gowitness@latest
echo "[+] Installing truffleHog..."
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin


# Python-based tools
echo "[*] Installing Python tools..."
echo "[+] Installing arjun..."
# Use pip3 directly for system-wide installation
pip3 install --break-system-packages arjun


echo
echo "[*] Tool installation complete."

# Final check to ensure all tools are installed
echo "[*] Verifying installation..."
TOOLS="subfinder dnsx naabu httpx katana gau ffuf gowitness trufflehog arjun"
FAILED_TOOLS=""
for tool in $TOOLS; do
    if ! command -v $tool > /dev/null; then
        echo "  [!] FAILED to install $tool"
        FAILED_TOOLS="$FAILED_TOOLS $tool"
    else
        echo "  [✔] $tool is installed."
    fi
done

if [ -n "$FAILED_TOOLS" ]; then
    echo "\n[ERROR] Some tools could not be installed:$FAILED_TOOLS"
    echo "Please try running the script again, or install them manually."
    exit 1
else
    echo "\n[SUCCESS] All tools have been successfully installed."
fi 