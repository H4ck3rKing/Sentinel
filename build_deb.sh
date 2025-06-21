#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
APP_NAME="sentinel"
VERSION="2.0.0"
# Use dpkg to determine the architecture, but fall back to amd64 if it fails.
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
MAINTAINER="Andrew Gatsi <lafang4789@gmail.com>"
DESCRIPTION="Advanced Bug Bounty Automation Framework."
PACKAGE_NAME="${APP_NAME}_${VERSION}_${ARCH}"
DEB_FILE="${PACKAGE_NAME}.deb"

# --- Build Go Binary ---
echo "Building Go application for Linux..."
# Build for linux/amd64, and create a static binary to ensure it runs on most systems.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $APP_NAME -ldflags="-s -w"

# --- Create Debian Package Structure ---
echo "Creating package structure at: ${PACKAGE_NAME}"
rm -rf "$PACKAGE_NAME"
mkdir -p "${PACKAGE_NAME}/usr/local/bin"
mkdir -p "${PACKAGE_NAME}/DEBIAN"

# --- Copy Binary ---
echo "Copying binary..."
cp "$APP_NAME" "${PACKAGE_NAME}/usr/local/bin/"

# --- Create Control File ---
echo "Creating control file..."
cat > "${PACKAGE_NAME}/DEBIAN/control" << EOF
Package: $APP_NAME
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Description: $DESCRIPTION
 Sentinel is an advanced, all-in-one bug bounty automation framework written in Go.
 It is designed to streamline reconnaissance, vulnerability scanning, and reporting.
 It provides an interactive, Metasploit-like interface.
Depends: libc-bin
EOF

# --- Build the Debian Package ---
echo "Building Debian package..."
dpkg-deb --build "$PACKAGE_NAME"

echo ""
echo "Successfully created ${DEB_FILE}"
echo "You can now upload this file to your GitHub Releases page."

# --- Cleanup ---
echo "Cleaning up build directory..."
rm -rf "$PACKAGE_NAME"
echo "Done." 