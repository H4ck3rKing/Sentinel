#!/bin/bash

# Exit on any error
set -e

# --- Configuration ---
VERSION="2.1.0"
ARCH="amd64"
PACKAGE_NAME="sentinel"
DEB_NAME="${PACKAGE_NAME}_${VERSION}_${ARCH}"

# --- Build the Go binary ---
echo "[*] Building the Sentinel binary..."
go build -o sentinel .

# --- Staging: Create the Debian package structure ---
echo "[*] Creating Debian package structure..."
rm -rf ${DEB_NAME}
mkdir -p ${DEB_NAME}/DEBIAN
mkdir -p ${DEB_NAME}/usr/local/bin
mkdir -p ${DEB_NAME}/usr/share/sentinel
mkdir -p ${DEB_NAME}/usr/share/applications
mkdir -p ${DEB_NAME}/usr/share/pixmaps

# --- Copying files ---
echo "[*] Copying files to the package structure..."

# Copy the control file
cp debian/DEBIAN/control ${DEB_NAME}/DEBIAN/control

# Copy the post-installation script and set permissions
cp debian/DEBIAN/postinst ${DEB_NAME}/DEBIAN/postinst
chmod 755 ${DEB_NAME}/DEBIAN/postinst

# Copy the main application binary
cp sentinel ${DEB_NAME}/usr/local/bin/sentinel

# Copy the dependency installation script
# This will be used by the postinst script
cp install_tools.sh ${DEB_NAME}/usr/share/sentinel/install_tools.sh

# --- Desktop Integration ---
echo "[*] Adding desktop application entry..."

# Copy the .desktop file
cp debian/sentinel.desktop ${DEB_NAME}/usr/share/applications/sentinel.desktop

# Copy the icon
cp assets/logo.png ${DEB_NAME}/usr/share/pixmaps/sentinel.png

# --- Building the Debian package ---
echo "[*] Building the Debian package..."
dpkg-deb --build ${DEB_NAME}

echo "[*] Successfully built ${DEB_NAME}.deb"
echo "[*] You can now distribute this file. Install it with 'sudo dpkg -i ${DEB_NAME}.deb'" 