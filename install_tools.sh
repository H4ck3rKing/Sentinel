#!/bin/bash

# This script installs the Go tools required by the Sentinel framework.
# Make sure you have Go installed and your GOPATH is set up correctly.

echo "[*] Installing required Go tools..."
echo "This may take a few minutes..."

# Project Discovery tools
echo "[+] Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo "[+] Installing dnsx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
echo "[+] Installing naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
echo "[+] Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "[+] Installing katana..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Other Go-based tools
echo "[+] Installing ffuf..."
go install -v github.com/ffuf/ffuf@latest
echo "[+] Installing gowitness..."
go install -v github.com/sensepost/gowitness@latest
echo "[+] Installing truffleHog..."
go install github.com/trufflesecurity/trufflehog/v3/cmd/trufflehog@latest


# Python-based tools
echo "[*] Installing Python tools..."

# Check for pipx, recommend installation if not found
if ! command -v pipx &> /dev/null
then
    echo "[!] WARNING: pipx could not be found."
    echo "[!] pipx is the recommended way to install arjun on your system."
    echo "[!] Please install it first, usually via 'sudo apt install pipx'."
    echo "[!] After installing pipx, you may need to run 'pipx ensurepath' and restart your terminal."
    echo "[!] Then, you can manually install arjun with 'pipx install arjun'."
else
    echo "[+] Installing arjun via pipx..."
    pipx install arjun
fi


echo
echo "[*] Tool installation complete."
echo "[*] Please ensure that your \$GOPATH/bin directory is in your system's PATH environment variable."
echo "[*] You can add it by running: export PATH=\$PATH:\$(go env GOPATH)/bin" 