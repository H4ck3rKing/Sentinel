package main

import (
	"fmt"
	"os"
	"strings"

	"bug/modules/reconnaissance"

	"github.com/c-bata/go-prompt"
)

const banner = `
    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                         v2.0

              -- Developed by Andrew Gatsi --
           -- andrew.gatsi@tech49originals.com --
`

// State holds the global configuration and targets
var config = map[string]string{
	"threads":        "50",
	"max_depth":      "3",
	"aggressive":     "true",
	"auto_exploit":   "false",
	"LHOST":          "",
	"LPORT":          "",
	"GITHUB_TOKEN":   "",
	"TARGET_URL":     "",
	"TARGET_DOMAIN":  "",
}

func executor(in string) {
	in = strings.TrimSpace(in)
	parts := strings.Split(in, " ")
	command := parts[0]
	args := parts[1:]

	switch command {
	case "exit":
		fmt.Println("Exiting Sentinel. Goodbye!")
		os.Exit(0)
	case "help":
		showHelp()
	case "set":
		if len(args) != 2 {
			fmt.Println("Usage: set <option> <value>")
			return
		}
		key, value := args[0], args[1]
		if _, ok := config[key]; ok {
			config[key] = value
			fmt.Printf("%s => %s\n", key, value)
		} else {
			fmt.Println("Unknown option:", key)
		}
	case "show":
		if len(args) > 0 && args[0] == "options" {
			showOptions()
		} else {
			fmt.Println("Usage: show options")
		}

	case "run":
		if len(args) > 0 {
			switch args[0] {
			case "recon":
				if config["TARGET_DOMAIN"] == "" {
					fmt.Println("TARGET_DOMAIN not set. Use 'set TARGET_DOMAIN <domain>'")
					return
				}
				reconnaissance.RunReconnaissance(config)
			default:
				fmt.Println("Unknown module:", args[0])
			}
		} else {
			fmt.Println("Usage: run <module>")
		}

	default:
		if in != "" {
			fmt.Println("Unknown command:", command)
		}
	}
}

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "help", Description: "Show the help menu"},
		{Text: "set", Description: "Set a configuration option (e.g., set LHOST 127.0.0.1)"},
		{Text: "show options", Description: "Display the current configuration"},
		{Text: "run", Description: "Run a module (e.g., run recon)"},
		{Text: "exit", Description: "Exit Sentinel"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func showHelp() {
	fmt.Println(`
Sentinel Command Menu:
  Core Commands:
    help                    - Show this help menu.
    set <option> <value>    - Configure an option (e.g., 'set LHOST 127.0.0.1').
    show options            - Display current configuration.
    run <module>            - Start a module (e.g., recon).
    exit                    - Exit Sentinel.

  Configuration Options (set <option> <value>):
    TARGET_DOMAIN           - The root domain to run reconnaissance on.
    LHOST                   - Local host for reverse shells.
    LPORT                   - Local port for reverse shells.
    GITHUB_TOKEN            - Your GitHub PAT for better exploit searching.
    threads                 - Number of concurrent threads for tools.
    auto_exploit            - Enable automated exploitation module [true|false].

  Execution Modules (run <module>):
    recon                   - Perform asset discovery and reconnaissance.
	`)
}

func showOptions() {
	fmt.Println("Current Configuration:")
	for key, value := range config {
		if value == "" {
			value = "<not set>"
		}
		fmt.Printf("  %s: %s\n", key, value)
	}
}

func main() {
	fmt.Println(banner)
	fmt.Println("Welcome to Sentinel. Type 'help' to get started.")
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("sentinel> "),
		prompt.OptionTitle("sentinel-prompt"),
	)
	p.Run()
} 