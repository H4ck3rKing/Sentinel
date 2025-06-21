package main

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"bug/modules/config"
	"bug/modules/database"
	"bug/modules/reconnaissance"
	"github.com/c-bata/go-prompt"
	"github.com/fatih/color"
)

var appConfig *config.Config
var db *sql.DB

// Command and option suggestions for the completer
var commands = []prompt.Suggest{
	{Text: "help", Description: "Show the help menu"},
	{Text: "set", Description: "Set a configuration value (e.g. set recon.threads 100)"},
	{Text: "add", Description: "Add a value to a configuration list (e.g. add target nust.na)"},
	{Text: "remove", Description: "Remove a value from a list (e.g. remove target nust.na)"},
	{Text: "show", Description: "Show the current configuration from config.yaml"},
	{Text: "run", Description: "Run a module (e.g. 'run recon')"},
	{Text: "banner", Description: "Display the Sentinel banner"},
	{Text: "clear", Description: "Clear the screen"},
	{Text: "exit", Description: "Exit Sentinel"},
}

var setOptions = []prompt.Suggest{
	{Text: "workspace", Description: "The name of the current project"},
	{Text: "recon.threads", Description: "Number of threads for reconnaissance tools"},
}

var addRemoveOptions = []prompt.Suggest{
	{Text: "target", Description: "A root domain or IP to include in scope"},
	{Text: "exclude", Description: "A domain or IP to exclude from scope"},
}

var runOptions = []prompt.Suggest{
	{Text: "recon", Description: "Perform asset discovery and reconnaissance for all targets"},
}

func printBanner() {
	banner := `
    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
`
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	purple := color.New(color.FgHiMagenta).SprintFunc()

	fmt.Println(cyan(banner))
	fmt.Printf("               %s Framework v2.0 %s\n", yellow("Sentinel"), purple("by Andrew Gatsi"))
	fmt.Println()
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func executor(in string) {
	in = strings.TrimSpace(in)
	parts := strings.Fields(in)
	if len(parts) == 0 {
		return
	}
	command := parts[0]
	args := parts[1:]

	switch command {
	case "exit":
		color.Yellow("Exiting Sentinel. Goodbye!")
		os.Exit(0)
	case "help":
		showHelp()
	case "banner":
		printBanner()
	case "clear":
		clearScreen()
	case "show":
		showOptions()
	case "run":
		if len(args) == 0 {
			color.Red("Usage: run <module>")
			return
		}
		module := args[0]
		if module == "recon" {
			reconnaissance.RunReconnaissance(appConfig, db)
		} else {
			color.Red("Unknown module: %s", module)
		}
	case "add":
		if len(args) != 2 {
			color.Red("Usage: add <type> <value> (e.g., add target example.com)")
			return
		}
		addType, value := args[0], args[1]
		if addType == "target" {
			appConfig.Targets = append(appConfig.Targets, value)
			color.Green("Added '%s' to targets.", value)
		} else {
			color.Red("Unknown type '%s'. Can only add 'target'.", addType)
			return
		}
	case "remove":
		if len(args) != 1 {
			color.Red("Usage: remove <target>")
			return
		}
		target := args[0]
		appConfig.Targets = removeTarget(appConfig.Targets, target)
		color.Green("Removed '%s' from targets.", target)
	case "set":
		if len(args) != 2 {
			color.Red("Usage: set <key> <value> (e.g., set recon.threads 100)")
			return
		}
		key, value := args[0], args[1]
		switch key {
		case "workspace":
			appConfig.Workspace = value
			color.Green("Workspace set to '%s'.", value)
		case "recon.threads":
			if threads, err := strconv.Atoi(value); err == nil {
				appConfig.Recon.Threads = threads
				color.Green("Recon threads set to %d.", threads)
			} else {
				color.Red("Invalid number for threads: %s", value)
				return
			}
		default:
			color.Red("Unknown config key: %s", key)
			return
		}
	default:
		color.Red("Unknown command: %s", command)
	}

	// Save config on any command that might change it
	if err := config.SaveConfig(appConfig); err != nil {
		color.Red("Failed to save config.yaml: %v", err)
	}
}

func completer(d prompt.Document) []prompt.Suggest {
	text := d.TextBeforeCursor()
	parts := strings.Fields(text)

	if len(parts) == 0 || (len(parts) == 1 && !strings.HasSuffix(text, " ")) {
		return prompt.FilterHasPrefix(commands, d.GetWordBeforeCursor(), true)
	}

	if len(parts) >= 1 {
		cmd := parts[0]
		if cmd == "run" && len(parts) == 1 {
			return prompt.FilterHasPrefix(runOptions, d.GetWordBeforeCursor(), true)
		}
	}
	return []prompt.Suggest{}
}

func showHelp() {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Println("\n" + cyan("Core Commands:"))
	fmt.Printf("  %-8s Show this help menu\n", green("help"))
	fmt.Printf("  %-8s Display the current configuration from %s\n", green("show"), yellow("config.yaml"))
	fmt.Printf("  %-8s Run a module (e.g., %s)\n", green("run"), yellow("run recon"))
	fmt.Printf("  %-8s Display the application banner\n", green("banner"))
	fmt.Printf("  %-8s Clear the terminal screen\n", green("clear"))
	fmt.Printf("  %-8s Exit the framework\n", green("exit"))
	fmt.Println()
}

func showOptions() {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Println("\n" + cyan("Current Configuration from " + config.ConfigFileName + ":"))
	fmt.Printf("  %-15s : %s\n", yellow("Workspace"), appConfig.Workspace)
	fmt.Printf("  %-15s : %s\n", yellow("Targets"), strings.Join(appConfig.Targets, ", "))
	fmt.Printf("  %-15s : %s\n", yellow("Recon Threads"), appConfig.Recon.Threads)
	fmt.Println()
}

func changeLivePrefix() (string, bool) {
	if appConfig != nil && appConfig.Workspace != "" {
		return fmt.Sprintf("[%s]> ", appConfig.Workspace), true
	}
	return "[sentinel]> ", true
}

func main() {
	var err error
	appConfig, err = config.LoadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			color.Yellow("Configuration file not found.")
			color.Green("Creating a default 'config.yaml' for you...")
			_, createErr := config.CreateDefaultConfig()
			if createErr != nil {
				color.Red("Fatal: Could not create config file: %v", createErr)
				os.Exit(1)
			}
			color.Cyan("Please edit 'config.yaml' to define your targets and then restart Sentinel.")
			os.Exit(0)
		} else {
			color.Red("Fatal: Could not load config file: %v", err)
			os.Exit(1)
		}
	}

	// Initialize the database for the workspace
	db, err = database.InitDB(appConfig.Workspace)
	if err != nil {
		color.Red("Fatal: Could not initialize database: %v", err)
		os.Exit(1)
	}

	clearScreen()
	printBanner()
	color.Yellow("Workspace '%s' loaded, database is ready. Type 'help'.", appConfig.Workspace)

	p := prompt.New(
		executor,
		completer,
		prompt.OptionTitle("Sentinel"),
		prompt.OptionLivePrefix(changeLivePrefix),
		prompt.OptionPrefixTextColor(prompt.Cyan),
		prompt.OptionSuggestionBGColor(prompt.DarkGray),
		prompt.OptionSuggestionTextColor(prompt.White),
		prompt.OptionSelectedSuggestionBGColor(prompt.Cyan),
		prompt.OptionSelectedSuggestionTextColor(prompt.Black),
		prompt.OptionDescriptionBGColor(prompt.DarkGray),
		prompt.OptionDescriptionTextColor(prompt.White),
		prompt.OptionSelectedDescriptionBGColor(prompt.DarkGray),
		prompt.OptionSelectedDescriptionTextColor(prompt.Cyan),
	)
	p.Run()
} 