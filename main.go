package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"bug/modules/config"
	"bug/modules/crawling"
	"bug/modules/database"
	"bug/modules/exploit"
	"bug/modules/fuzzing"
	"bug/modules/params"
	"bug/modules/reconnaissance"
	"bug/modules/reporting"
	"bug/modules/scanning"
	"bug/modules/secrets"
	"bug/modules/utils"
	"bug/modules/visual"

	"github.com/c-bata/go-prompt"
	"github.com/fatih/color"
)

var appConfig *config.Config
var db *sql.DB

// Command and option suggestions for the completer
var commands = []prompt.Suggest{
	{Text: "help", Description: "Show the help menu"},
	{Text: "add", Description: "Add a value to a configuration list (e.g. add target example.com)"},
	{Text: "remove", Description: "Remove a value from a list (e.g. remove target example.com)"},
	{Text: "show", Description: "Show the current configuration from config.yaml"},
	{Text: "run", Description: "Run a module (e.g. 'run recon')"},
	{Text: "banner", Description: "Display the Sentinel banner"},
	{Text: "clear", Description: "Clear the screen"},
	{Text: "exit", Description: "Exit Sentinel"},
}

var addRemoveOptions = []prompt.Suggest{
	{Text: "target", Description: "A root domain or IP to include in scope"},
	{Text: "exclude", Description: "A domain or IP to exclude from scope"},
}

var runOptions = []prompt.Suggest{
	{Text: "recon", Description: "Perform asset discovery and reconnaissance for all targets"},
	{Text: "crawl", Description: "Crawl discovered web services to find more endpoints"},
	{Text: "secrets", Description: "Scan JavaScript files for hardcoded secrets and credentials"},
	{Text: "params", Description: "Discover hidden parameters on known endpoints"},
	{Text: "fuzz", Description: "Discover hidden content and directories with ffuf"},
	{Text: "scan", Description: "Run vulnerability scans on discovered web services"},
	{Text: "visual", Description: "Take screenshots of all live web services"},
	{Text: "exploit", Description: "Research public exploits for vulnerabilities found"},
	{Text: "report", Description: "Generate a summary report of all findings"},
	{Text: "all", Description: "Run all modules in sequence: recon -> crawl -> secrets -> params -> fuzz -> scan -> exploit -> report"},
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
	// Create color functions
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	fmt.Println(cyan(banner))
	fmt.Printf("               %s Framework v2.0 %s\n", yellow("Sentinel"), gray("by Andrew Gatsi"))
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

	// Create a context that can be cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up a channel to listen for interrupt signals (Ctrl+C).
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Println(color.YellowString("\n[!] Cancellation signal received. Shutting down gracefully..."))
		cancel()
	}()

	switch command {
	case "exit":
		color.Yellow("Exiting Sentinel. Goodbye!")
		if err := config.SaveConfig(appConfig); err != nil {
			color.Red("Failed to save config before exiting: %v", err)
		}
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
		switch module {
		case "recon":
			reconnaissance.RunReconnaissance(ctx, appConfig, db)
		case "crawl":
			crawling.RunCrawl(ctx, appConfig, db)
		case "secrets":
			secrets.RunSecrets(ctx, appConfig, db)
		case "params":
			params.RunParams(ctx, appConfig, db)
		case "fuzz":
			fuzzing.RunFuzzing(ctx, appConfig, db)
		case "scan":
			scanning.RunScan(ctx, appConfig, db)
		case "visual":
			visual.RunVisual(ctx, appConfig, db)
		case "exploit":
			exploit.RunExploitResearch(ctx, appConfig, db)
		case "report":
			reporting.GenerateReport(appConfig, db)
		case "all":
			// Fix: Get targets from DB for 'run all'
			targets, err := database.GetTargetStrings(db)
			if err != nil {
				color.Red("Could not get targets from database for 'run all': %v", err)
				return
			}
			if len(targets) == 0 {
				color.Yellow("No targets in scope. Use 'add target <domain>' to add one.")
				return
			}
			appConfig.Targets = targets // Ensure the config state is aligned with DB for this run.

			reconnaissance.RunReconnaissance(ctx, appConfig, db)
			crawling.RunCrawl(ctx, appConfig, db)
			secrets.RunSecrets(ctx, appConfig, db)
			params.RunParams(ctx, appConfig, db)
			fuzzing.RunFuzzing(ctx, appConfig, db)
			scanning.RunScan(ctx, appConfig, db)
			exploit.RunExploitResearch(ctx, appConfig, db)
			reporting.GenerateReport(appConfig, db)
		default:
			color.Red("Unknown module: %s", module)
		}
	case "add":
		if len(args) < 2 {
			color.Red("Usage: add <type> <value> (e.g., add target example.com)")
			return
		}
		addType, value := args[0], strings.Join(args[1:], " ")
		switch addType {
		case "target":
			appConfig.Targets = append(appConfig.Targets, value)
			database.AddTarget(db, value) // Also add to DB
			color.Green("Added '%s' to targets.", value)
		case "exclude":
			appConfig.Exclude = append(appConfig.Exclude, value)
			color.Green("Added '%s' to exclusions.", value)
		default:
			color.Red("Unknown type '%s'. Can only add 'target' or 'exclude'.", addType)
		}
	case "remove":
		if len(args) < 2 {
			color.Red("Usage: remove <type> <value>")
			return
		}
		removeType, value := args[0], strings.Join(args[1:], " ")
		switch removeType {
		case "target":
			appConfig.Targets = removeStringFromSlice(appConfig.Targets, value)
			color.Green("Removed '%s' from targets.", value)
		case "exclude":
			appConfig.Exclude = removeStringFromSlice(appConfig.Exclude, value)
			color.Green("Removed '%s' from exclusions.", value)
		default:
			color.Red("Unknown type '%s'. Can only remove 'target' or 'exclude'.", removeType)
		}

	default:
		color.Red("Unknown command: %s", command)
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
		if cmd == "run" && len(parts) <= 2 {
			return prompt.FilterHasPrefix(runOptions, d.GetWordAfterCursor(), true)
		}
		if (cmd == "add" || cmd == "remove") && len(parts) <= 2 {
			return prompt.FilterHasPrefix(addRemoveOptions, d.GetWordAfterCursor(), true)
		}
	}
	return []prompt.Suggest{}
}

func removeStringFromSlice(slice []string, itemToRemove string) []string {
	var newSlice []string
	for _, i := range slice {
		if i != itemToRemove {
			newSlice = append(newSlice, i)
		}
	}
	return newSlice
}

func showHelp() {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	fmt.Println("\n" + cyan("Core Commands:"))
	fmt.Printf("  %-20s %s\n", green("help"), white("Show this help menu"))
	fmt.Printf("  %-20s %s (e.g., %s)\n", green("add target"), white("Add a target to the scope"), yellow("add target example.com"))
	fmt.Printf("  %-20s %s (e.g., %s)\n", green("remove target"), white("Remove a target from the scope"), yellow("remove target example.com"))
	fmt.Printf("  %-20s %s (e.g., %s)\n", green("run"), white("Run a module"), yellow("run recon"))
	fmt.Printf("  %-20s %s\n", green("show"), white("Display the current configuration"))
	fmt.Printf("  %-20s %s\n", green("banner"), white("Display the application banner"))
	fmt.Printf("  %-20s %s\n", green("clear"), white("Clear the terminal screen"))
	fmt.Printf("  %-20s %s\n", green("exit"), white("Exit the framework"))

	fmt.Println("\n" + cyan("Available Modules for 'run':"))
	for _, opt := range runOptions {
		fmt.Printf("  %-20s %s\n", green(opt.Text), white(opt.Description))
	}
	fmt.Println()
}

func showOptions() {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	fmt.Println("\n" + cyan("--- Current Configuration ("+config.ConfigFileName+") ---"))
	fmt.Printf("  %-20s : %s\n", yellow("Workspace"), white(appConfig.Workspace))
	fmt.Printf("  %-20s : %s\n", yellow("Targets"), white(strings.Join(appConfig.Targets, ", ")))
	fmt.Printf("  %-20s : %s\n", yellow("Exclude"), white(strings.Join(appConfig.Exclude, ", ")))
	fmt.Println()

	fmt.Printf("  %s\n", cyan("API Keys:"))
	fmt.Printf("    %-18s : %s\n", yellow("GitHub"), white(appConfig.APIKeys.GitHub)+gray(" (set for better subdomain results)"))
	fmt.Println()

	fmt.Printf("  %s\n", cyan("Module Settings:"))
	fmt.Printf("    %-18s : %s\n", yellow("Recon Threads"), white(strconv.Itoa(appConfig.Recon.Threads)))
	fmt.Printf("    %-18s : %s\n", yellow("Fuzzing Wordlist"), white(appConfig.Fuzzing.Wordlist))
	fmt.Printf("    %-18s : %s\n", yellow("Scanning Intensity"), white(appConfig.Scanning.Intensity))
	fmt.Printf("    %-18s : %s\n", yellow("Crawling Max Depth"), white(strconv.Itoa(appConfig.Crawling.MaxDepth)))
	fmt.Printf("    %-18s : %s\n", yellow("Reporting Format"), white(appConfig.Reporting.Format))
	fmt.Println(cyan("-------------------------------------------\n"))
}

func checkGoPath() {
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		// If GOPATH is not set, try getting it from `go env`
		out, err := exec.Command("go", "env", "GOPATH").Output()
		if err == nil {
			goPath = strings.TrimSpace(string(out))
		}
	}

	if goPath == "" {
		utils.Warn("Could not determine GOPATH. Please ensure Go is installed correctly.")
		return
	}

	goBin := filepath.Join(goPath, "bin")
	pathEnv := os.Getenv("PATH")

	if !strings.Contains(pathEnv, goBin) {
		utils.Warn(fmt.Sprintf("Your Go binary path (%s) is not in your system's PATH.", goBin))
		utils.Warn(fmt.Sprintf("Please add it to your shell's config file (e.g., ~/.zshrc, ~/.bashrc):"))
		color.Yellow("  export PATH=$PATH:%s", goBin)
	}
}

func changeLivePrefix() (string, bool) {
	if appConfig != nil && appConfig.Workspace != "" {
		prompt := fmt.Sprintf("[sentinel|%s]> ", appConfig.Workspace)
		return prompt, true
	}
	prompt := "[sentinel]> "
	return prompt, true
}

func checkDependencies() {
	color.New(color.FgYellow).Println("[*] Checking for required tools...")
	requiredTools := []string{
		"subfinder", "dnsx", "naabu", "httpx", "katana", "gau",
		"ffuf", "gowitness", "trufflehog", "arjun",
	}
	missingTools := false
	for _, tool := range requiredTools {
		if !utils.CommandExists(tool) {
			color.Red("  [!] %s is not installed or not in your PATH.", tool)
			missingTools = true
		} else {
			color.Green("  [✔] %s is installed.", tool)
		}
	}

	if missingTools {
		color.New(color.FgRed, color.Bold).Println("\n[!] Some tools are missing.")
		color.Yellow("Please run the './install_tools.sh' script to install all dependencies.")
		color.Yellow("Then, ensure your GOPATH/bin is in your system's PATH environment variable.")
		color.Yellow("Ex: export PATH=$PATH:$(go env GOPATH)/bin")
		os.Exit(1)
	} else {
		color.New(color.FgGreen).Println("\n[✔] All required tools are installed.")
	}
	fmt.Println()
}

func main() {
	checkDependencies()
	checkGoPath()

	var err error
	appConfig, err = config.LoadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			color.Yellow("Configuration file not found. Creating a default 'config.yaml'...")
			appConfig, err = config.CreateDefaultConfig()
			if err != nil {
				color.Red("Fatal: Could not create default config: %v", err)
				os.Exit(1)
			}
			color.Green("Default 'config.yaml' created. Please edit it to define your targets.")
		} else {
			color.Red("Fatal: Could not load config: %v", err)
			os.Exit(1)
		}
	}

	db, err = database.InitDB(appConfig)
	if err != nil {
		color.Red("Fatal: Could not initialize database: %v", err)
		os.Exit(1)
	}
	// The defer should be right after the successful initialization
	// defer db.Close() // This causes issues with the interactive prompt loop

	printBanner()

	// Initial clear of the screen for a clean start
	clearScreen()
	printBanner() // Reprint banner after clearing

	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("[-] "),
		prompt.OptionLivePrefix(changeLivePrefix),
		prompt.OptionTitle("Sentinel"),
	)
	p.Run()
}
