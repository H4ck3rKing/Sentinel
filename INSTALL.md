# Sentinel Installation Guide

This guide provides the simple, one-command installation process for Sentinel on Debian-based Linux distributions (like Ubuntu, Kali, etc.).

## Recommended Installation

The recommended way to install Sentinel is to use the provided `.deb` package with the `apt` package manager. This will automatically handle all system dependencies and run the tool installer for a seamless setup.

1.  **Download the `.deb` file** from the latest [GitHub Release](https://github.com/H4ck3rKing/Sentinel/releases).

2.  **Open a terminal** in the directory where you downloaded the file (e.g., `~/Downloads`).

3.  **Run the installation command:**

    ```bash
    sudo apt install ./sentinel_2.4.0_amd64.deb
    ```

    You will be prompted for your password. `apt` will ask for confirmation to install Sentinel and all of its required dependencies (`golang-go`, `seclists`, `pipx`, etc.).

4.  **Installation is complete!** After the command finishes, all tools will be installed, and you can run the application by simply typing `sentinel` in your terminal.

## 