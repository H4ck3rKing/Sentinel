package main

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
	"bug/modules/visual"

	"github.com/c-bata/go-prompt"
	"github.com/fatih/color"
)

var appConfig *config.Config
var db *sql.DB

// Command and option suggestions for the completer
var commands = []prompt.Suggest{
	{Text: "help", Description: "Show the help menu"},
	{Text: "add", Description: "Add a value to a configuration list (e.g. add target nust.na)"},
	{Text: "remove", Description: "Remove a value from a list (e.g. remove target nust.na)"},
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
			reconnaissance.RunReconnaissance(appConfig, db)
		case "crawl":
			crawling.RunCrawl(appConfig, db)
		case "secrets":
			secrets.RunSecrets(appConfig, db)
		case "params":
			params.RunParams(appConfig, db)
		case "fuzz":
			fuzzing.RunFuzzing(appConfig, db)
		case "scan":
			scanning.RunScan(appConfig, db)
		case "visual":
			visual.RunVisual(appConfig, db)
		case "exploit":
			exploit.RunExploitResearch(appConfig, db)
		case "report":
			reporting.GenerateReport(appConfig, db)
		case "all":
			reconnaissance.RunReconnaissance(appConfig, db)
			crawling.RunCrawl(appConfig, db)
			secrets.RunSecrets(appConfig, db)
			params.RunParams(appConfig, db)
			fuzzing.RunFuzzing(appConfig, db)
			scanning.RunScan(appConfig, db)
			exploit.RunExploitResearch(appConfig, db)
			reporting.GenerateReport(appConfig, db)
		default:
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
			database.AddTarget(db, value) // Also add to DB
			color.Green("Added '%s' to targets.", value)
		} else {
			color.Red("Unknown type '%s'. Can only add 'target'.", addType)
			return
		}
	case "remove":
		if len(args) != 2 {
			color.Red("Usage: remove <type> <value>")
			return
		}
		removeType, value := args[0], args[1]
		if removeType == "target" {
			appConfig.Targets = removeTarget(appConfig.Targets, value)
			color.Green("Removed '%s' from targets.", value)
		} else {
			color.Red("Unknown type '%s'.", removeType)
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

func removeTarget(targets []string, targetToRemove string) []string {
	var newTargets []string
	for _, t := range targets {
		if t != targetToRemove {
			newTargets = append(newTargets, t)
		}
	}
	return newTargets
}

func showHelp() {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Println("\n" + cyan("Core Commands:"))
	fmt.Printf("  %-8s Show this help menu\n", green("help"))
	fmt.Printf("  %-8s Display the current configuration from %s\n", green("show"), yellow("config.yaml"))
	fmt.Printf("  %-8s Run a module (e.g., %s)\n", green("run"), yellow("run recon"))
	fmt.Printf("  %-8s Add a target (e.g., %s)\n", green("add"), yellow("add target example.com"))
	fmt.Printf("  %-8s Remove a target (e.g., %s)\n", green("remove"), yellow("remove target example.com"))
	fmt.Printf("  %-8s Display the application banner\n", green("banner"))
	fmt.Printf("  %-8s Clear the terminal screen\n", green("clear"))
	fmt.Printf("  %-8s Exit the framework\n", green("exit"))
	fmt.Println()
}

func showOptions() {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Println("\n" + cyan("Current Configuration from "+config.ConfigFileName+":"))
	fmt.Printf("  %-15s : %s\n", yellow("Workspace"), appConfig.Workspace)
	fmt.Printf("  %-15s : %s\n", yellow("Targets"), strings.Join(appConfig.Targets, ", "))
	fmt.Printf("  %-15s : %d\n", yellow("Recon Threads"), appConfig.Recon.Threads)
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
			appConfig, err = config.CreateDefaultConfig()
			if err != nil {
				color.Red("Fatal: Could not create config file: %v", err)
			os.Exit(1)
		}
			color.Cyan("Default 'config.yaml' created. Please edit it to define your targets and then restart Sentinel.")
			os.Exit(0)
		} else {
			color.Red("Fatal: Could not load config file: %v", err)
			os.Exit(1)
		}
	}

	db, err = database.InitDB(appConfig)
	if err != nil {
		color.Red("Fatal: Could not initialize database: %v", err)
		os.Exit(1)
	}
	defer db.Close()

	// Sync targets from config file to database on startup
	for _, target := range appConfig.Targets {
		database.AddTarget(db, target)
	}

	printBanner()
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("[sentinel]> "),
		prompt.OptionLivePrefix(changeLivePrefix),
		prompt.OptionTitle("sentinel"),
	)
	p.Run()
}
