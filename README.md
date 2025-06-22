<div align="center">

  <h1 align="center">Sentinel Framework</h1>
  <p align="center">
    <img src="https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
    <img src="https://img.shields.io/badge/sqlite-%23003B57.svg?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" />
    <img src="https://img.shields.io/github/license/H4ck3rKing/Sentinel?style=for-the-badge" alt="License" />
    <img src="https://img.shields.io/github/stars/H4ck3rKing/Sentinel?style=for-the-badge&color=yellow" alt="Stars" />
  </p>
  <p align="center">
    An advanced, all-in-one bug bounty automation framework designed for the modern security researcher.
  </p>
</div>

    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                         v2.0

<p align="center"><b>Developed by: Andrew Gatsi</b></p>

---

## 📖 Table of Contents
- [✨ Features](#-features)
- [🛠️ Installation](#️-installation)
- [⚙️ Configuration](#️-configuration)
- [🕹️ Usage](#️-usage)
  - [Core Commands](#core-commands)
  - [Available Modules](#available-modules)
  - [Example Workflow](#example-workflow)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## ✨ Features

Sentinel provides a powerful, modular, and interactive environment to streamline your entire security research workflow.

-   **⚡ Interactive Shell**: A user-friendly, prompt-based interface inspired by Metasploit for a seamless user experience.
-   **🔧 Modular Architecture**: A flexible design that allows for easy expansion. Each security task—from recon to reporting—is a self-contained module.
-   **🔗 Advanced Tool Chaining**: Intelligently chains together best-in-class open-source security tools (`subfinder`, `httpx`, `nuclei`, etc.) to create a comprehensive automation pipeline.
-   **📝 Centralized Configuration**: Manage your entire project from a single `config.yaml` file. Define targets, exclusions, API keys, and module-specific settings.
-   **💾 Persistent Database**: All findings are stored in a structured SQLite database within your workspace, allowing you to pause and resume projects and easily query results.
-   **✅ Automatic Dependency Checking**: Sentinel automatically checks if all required external tools are installed and available in your `PATH` on startup.

---

## 🛠️ Installation

> **Requirements:**
> * Linux (tested on Debian-based distros)
> * [Go](https://golang.org/doc/install) (version 1.18 or higher)
> * A shell environment like `bash` or `zsh`.

### 1. Clone the Repository
First, clone the Sentinel repository from GitHub.

```sh
git clone https://github.com/H4ck3rKing/Sentinel.git
cd Sentinel
```

### 2. Install Dependencies
Sentinel leverages a suite of powerful third-party tools. The included `install_tools.sh` script will download and install all of them for you.

```sh
chmod +x install_tools.sh
./install_tools.sh
```
**Important**: After running the script, you must ensure your Go bin directory is in your system's `PATH`. Add the following line to your shell's configuration file (e.g., `~/.zshrc`, `~/.bashrc`) and restart your terminal.

```sh
export PATH=$PATH:$(go env GOPATH)/bin
```

### 3. Build Sentinel
Compile the application using the `go build` command. This will create a `sentinel` executable in the current directory.

```sh
go build -o sentinel .
```

---

## ⚙️ Configuration

Sentinel uses a single `config.yaml` file to manage all settings. When you run Sentinel for the first time, a default configuration file will be created for you.

Here is a breakdown of the available options:

```yaml
# The name of your current project. All results and the database will be stored here.
workspace: "default"

# A list of root domains or IPs to include in the scope.
targets:
    - example.com

# A list of domains or IPs to explicitly exclude from all scans.
exclude:
    - "docs.example.com"

# API keys for third-party services to enhance results.
api_keys:
    # A GitHub token allows for more thorough subdomain enumeration with subfinder.
    github: "" 

# --- Module-Specific Settings ---

# Settings for the reconnaissance module.
recon:
    threads: 50

# Settings for the fuzzing module.
fuzzing:
    # Path to the wordlist for directory/file fuzzing with ffuf.
    wordlist: "/usr/share/seclists/Discovery/Web-Content/common.txt"

# Settings for the vulnerability scanning module.
scanning:
    # Defines the intensity of the Nuclei scan.
    # "light": high & critical severities
    # "normal": medium, high, & critical severities
    # "deep": all templates
    intensity: "normal"

# Settings for the crawling module.
crawling:
    # Defines the maximum depth for the web crawler (katana).
    max_depth: 2

# Settings for the reporting module.
reporting:
    # The output format for the final report.
    # Options: "md", "json", "html"
    format: "md"
```

---

## 🕹️ Usage

To start the framework, run the `sentinel` executable from your terminal:
```sh
./sentinel
```

### Core Commands
The Sentinel shell provides a set of intuitive commands to manage your workflow.

| Command         | Description                                                  | Example                               |
| --------------- | ------------------------------------------------------------ | ------------------------------------- |
| `help`          | Shows the detailed help menu.                                  | `help`                                |
| `add`           | Adds a target or an exclusion to the configuration.            | `add target example.com`              |
| `remove`        | Removes a target or an exclusion from the configuration.       | `remove target example.com`           |
| `show`          | Displays the current configuration from `config.yaml`.         | `show`                                |
| `run`           | Executes a specific module or all modules.                     | `run recon`                           |
| `banner`        | Displays the application banner.                               | `banner`                              |
| `clear`         | Clears the terminal screen.                                  | `clear`                               |
| `exit`          | Exits the Sentinel framework and saves the configuration.    | `exit`                                |


### Available Modules
You can run any of the following modules using the `run <module>` command.

| Module      | Description                                                                 |
| ----------- | --------------------------------------------------------------------------- |
| `recon`     | Performs asset discovery (subdomains, IPs, ports) and web server discovery. |
| `crawl`     | Crawls discovered web services to find more endpoints and URLs.             |
| `secrets`   | Scans JavaScript files for hardcoded secrets and credentials with TruffleHog. |
| `params`    | Discovers hidden parameters on known endpoints using Arjun.                 |
| `fuzz`      | Discovers hidden content and directories using FFUF.                        |
| `scan`      | Runs vulnerability scans on web services using Nuclei templates.            |
| `visual`    | Takes screenshots of all live web services with GoWitness.                  |
| `exploit`   | Researches public exploits for found vulnerabilities using SearchSploit.     |
| `report`    | Generates a summary report of all findings in the specified format.         |
| `all`       | Runs all modules in sequence from `recon` to `report`.                      |


### Example Workflow
Here is a sample workflow for a new bug bounty engagement:

1.  **Start Sentinel**:
    ```
    ./sentinel
    ```

2.  **Add Your Target**:
    ```
    [sentinel|default]> add target bugcrowd.com
    ```

3.  **Run Reconnaissance**:
    This is the foundational step. It will discover subdomains, resolve IPs, find open ports, and identify live web servers.
    ```
    [sentinel|default]> run recon
    ```

4.  **Crawl for More URLs**:
    Once you have live web services, crawl them to expand your attack surface.
    ```
    [sentinel|default]> run crawl
    ```

5.  **Run a Vulnerability Scan**:
    Now that you have a comprehensive list of URLs, scan them for known vulnerabilities.
    ```
    [sentinel|default]> run scan
    ```
6.  **Generate a Report**:
    Finally, generate a report of your findings.
    ```
    [sentinel|default]> run report
    ```

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for new features, bug fixes, or improvements, please feel free to open an issue or submit a pull request.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. 