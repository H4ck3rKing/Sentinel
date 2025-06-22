#!/bin/bash

# Exit on any error
set -e

# --- Configuration ---
VERSION=$(grep -oP 'Version: \K.*' debian/DEBIAN/control)
ARCH="amd64"
PACKAGE_NAME="sentinel"
DEB_NAME="${PACKAGE_NAME}_${VERSION}_${ARCH}"

# --- Build ---
echo "[*] Building the Sentinel binary..."
/usr/local/go/bin/go build -o sentinel .

# --- Staging ---
echo "[*] Creating Debian package structure..."
rm -rf ${DEB_NAME}
mkdir -p ${DEB_NAME}/DEBIAN
mkdir -p ${DEB_NAME}/usr/local/bin
mkdir -p ${DEB_NAME}/usr/share/applications
mkdir -p ${DEB_NAME}/usr/share/pixmaps
mkdir -p ${DEB_NAME}/usr/share/sentinel/wordlists
mkdir -p ${DEB_NAME}/etc/profile.d

# --- Copying files ---
echo "[*] Copying files..."
# Control files
cp debian/DEBIAN/control ${DEB_NAME}/DEBIAN/control
cp debian/DEBIAN/postinst ${DEB_NAME}/DEBIAN/postinst
chmod 755 ${DEB_NAME}/DEBIAN/postinst

# Application files
cp sentinel ${DEB_NAME}/usr/local/bin/sentinel
cp install_tools.sh ${DEB_NAME}/usr/local/bin/install_tools.sh

# Desktop files
cp debian/sentinel.desktop ${DEB_NAME}/usr/share/applications/sentinel.desktop
cp assets/logo.png ${DEB_NAME}/usr/share/pixmaps/sentinel.png

# Wordlists
cp -r wordlists/* ${DEB_NAME}/usr/share/sentinel/wordlists/

# PATH configuration script
cp debian/sentinel.sh ${DEB_NAME}/etc/profile.d/sentinel.sh

# --- Build Package ---
echo "[*] Building the Debian package..."
dpkg-deb --build ${DEB_NAME}

echo "[*] Successfully built ${DEB_NAME}.deb"
echo "[*] You can now distribute this file. Install it with 'sudo dpkg -i ${DEB_NAME}.deb'" 