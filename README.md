# Sentinel - Advanced Bug Bounty Automation Framework

    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                         v2.0

## Overview

**Sentinel** is an advanced, all-in-one bug bounty automation framework written in Go. It is designed to streamline reconnaissance, vulnerability scanning, and reporting for security researchers. Sentinel provides an interactive shell inspired by Metasploit, allowing you to set options, manage targets, and execute modules in a powerful and flexible environment.

**Developed by:** Andrew Gatsi

---

## Features

*   **Interactive Shell:** A user-friendly, prompt-based interface for managing the entire workflow.
*   **Centralized Configuration:** Easily set and manage global options like target domains, threads, and listening hosts/ports.
*   **Modular Architecture:** The framework is built with a modular design, starting with a powerful reconnaissance module.
*   **Automated Reconnaissance:** A comprehensive discovery module that chains together top-tier tools for subdomain enumeration, port scanning, and web technology identification.
*   **Extensible by Design:** The Go codebase is structured to be easily extensible with new modules and functionality.

---

## Releases

You can find the latest `.deb` package for Debian-based systems on the [Releases page](https://github.com/H4ck3rKing/Sentinel/releases).

### Installation from .deb

1.  Download the latest `sentinel_*.deb` file from the releases page.
2.  Install it using `dpkg`:
    ```sh
    sudo dpkg -i sentinel_*.deb
    ```
3.  Run the application:
    ```sh
    sentinel
    ```

---

## Building from Source

> **Requirements:**
>
> *   Linux (tested on Ubuntu/Debian)
> *   [Go](https://golang.org/doc/install) (version 1.18 or higher)
> *   Required security tools must be installed and available in your system's `PATH`.

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/H4ck3rKing/Sentinel.git
    cd Sentinel
    ```
2.  **Build the application:**
    ```sh
    go build -o sentinel
    ```
    This will create a `sentinel` executable in the current directory.

3.  **Install Dependencies:**
    Sentinel requires several external tools to function correctly. You must install these manually.
    ```sh
    # Example installation for some tools on Debian/Ubuntu
    sudo apt update && sudo apt install -y nmap sqlmap
    
    # Go tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    ```

---

## Usage

1.  **Start Sentinel:**
    ```sh
    ./sentinel
    ```
2.  **Set the target domain:**
    ```
    sentinel> set TARGET_DOMAIN nust.na
    ```
3.  **(Optional) Configure other options:**
    ```
    sentinel> set threads 100
    sentinel> show options
    ```
4.  **Run a module:**
    ```
    sentinel> run recon
    ```
5.  **View results:**
    All outputs are saved in the `bugbounty-results/` directory, organized by target domain.

---

## Command Reference

| Command              | Description                                      |
| -------------------- | ------------------------------------------------ |
| `help`               | Show the help menu.                              |
| `set <option> <value>` | Set a configuration option (e.g., `set LHOST 127.0.0.1`). |
| `show options`       | Show the current configuration.                  |
| `run <module>`       | Run a specific module (e.g., `run recon`).       |
| `exit`               | Exit the Sentinel framework.                     |

### Modules

| Module  | Description                                |
| ------- | ------------------------------------------ |
| `recon` | Performs asset discovery and reconnaissance. |

---

## Building a .deb package

If you want to build the `.deb` package yourself:
1.  Make sure you have `dpkg-deb` installed (`sudo apt-get install dpkg-deb`).
2.  Run the build script:
    ```sh
    ./build_deb.sh
    ```
This will create the `sentinel_*.deb` file in the root directory.

---

## License

This project is licensed under the MIT License. 