package crawling

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"bug/modules/config"
	"github.com/fatih/color"
	"bug/modules/database"
	"bug/modules/utils"
)

// KatanaOutput represents the structure of a single JSON line from katana output
type KatanaOutput struct {
	Request struct {
		Endpoint string `json:"endpoint"`
	} `json:"request"`
}

func RunCrawl(ctx context.Context, config *config.Config, db *sql.DB) {
	options := utils.Options{
		Output:  config.Workspace,
		Threads: config.Recon.Threads, // Not used by crawl, but good for consistency
	}
	color.Cyan("[*] Starting Crawling phase")

	if !utils.CommandExists("katana") {
		color.Red("katana not found. Please install it first.")
		color.Yellow("Hint: go install github.com/projectdiscovery/katana/cmd/katana@latest")
		return
	}

	tempDir := filepath.Join(options.Output, "temp")
	os.MkdirAll(tempDir, 0755)
	katanaInputFile := filepath.Join(tempDir, "katana-input.txt")
	katanaOutputFile := filepath.Join(tempDir, "katana-output.json")
	// Defer cleanup
	defer os.Remove(katanaInputFile)
	defer os.Remove(katanaOutputFile)

	utils.Banner("Fetching live URLs from database")
	urls, err := database.GetLiveURLs(db)
	if err != nil {
		color.Red("Error getting URLs from database: %v", err)
		return
	}

	if len(urls) == 0 {
		color.Yellow("No live URLs found in the database to crawl.")
		return
	}
	color.Green("Found %d live URLs to crawl.", len(urls))

	file, err := os.Create(katanaInputFile)
	if err != nil {
		color.Red("Error creating input file for katana: %v", err)
		return
	}
	for _, u := range urls {
		fmt.Fprintln(file, u)
	}
	file.Close()

	utils.Banner("Running katana against live URLs")
	// Use crawl depth from config
	crawlDepth := strconv.Itoa(config.Crawling.MaxDepth)
	if crawlDepth == "0" {
		crawlDepth = "2" // Default if not set
	}
	utils.RunCommand(ctx, options, "katana", "-list", katanaInputFile, "-json", "-depth", crawlDepth, "-o", katanaOutputFile)

	utils.Banner("Parsing katana output and adding new URLs to database")
	targets, err := database.GetTargets(db)
	if err != nil {
		color.Red("Error getting targets from database: %v", err)
		return
	}

	outputFile, err := os.Open(katanaOutputFile)
	if err != nil {
		// It's possible katana found nothing, so the file might not exist.
		color.Yellow("No katana output file found. Skipping parsing.")
		return
	}
	defer outputFile.Close()

	scanner := bufio.NewScanner(outputFile)
	var newURLsFound int
	for scanner.Scan() {
		var katanaOut KatanaOutput
		line := scanner.Text()
		if err := json.Unmarshal([]byte(line), &katanaOut); err == nil {
			newURL := katanaOut.Request.Endpoint
			var associatedTargetID int = -1

			parsedNewUrl, err := url.Parse(newURL)
			if err != nil {
				continue
			}

			for id, targetDomain := range targets {
				if strings.HasSuffix(parsedNewUrl.Hostname(), targetDomain) {
					associatedTargetID = id
					break
				}
			}

			if associatedTargetID != -1 {
				if _, err := database.AddURL(db, associatedTargetID, newURL, "katana"); err == nil {
					newURLsFound++
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading katana output: %v", err)
	}

	color.Green("Crawling phase completed. Found %d new URLs.", newURLsFound)
}

func RunCrawling(ctx context.Context, cfg *config.Config, db *sql.DB) {
	utils.Banner("Starting Crawling phase")

	options := utils.Options{
		Output:  cfg.Workspace,
		Threads: cfg.Recon.Threads, // Not used by crawl, but good for consistency
	}

	urls, err := getURLsToCrawl(db)
	if err != nil || len(urls) == 0 {
		utils.Warn("No URLs found in the database to crawl. Run 'recon' first.")
		return
	}

	for _, url := range urls {
		runKatana(ctx, url, options, db)
	}

	utils.Banner("Crawling phase complete.")
}

func runKatana(ctx context.Context, url string, options utils.Options, db *sql.DB) {
	// Since we are capturing output, any errors will be returned by the function.
	output, err := utils.RunCommandAndCapture(ctx, options, "katana", "-u", url, "-silent", "-jc")
	if err != nil {
		utils.Error(fmt.Sprintf("Error crawling %s", url), err)
		return
	}

	utils.Banner("Parsing katana output and adding new URLs to database")
	targets, err := database.GetTargets(db)
	if err != nil {
		color.Red("Error getting targets from database: %v", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	var newURLsFound int
	for scanner.Scan() {
		var katanaOut KatanaOutput
		line := scanner.Text()
		if err := json.Unmarshal([]byte(line), &katanaOut); err == nil {
			newURL := katanaOut.Request.Endpoint
			var associatedTargetID int = -1

			parsedNewUrl, err := url.Parse(newURL)
			if err != nil {
				continue
			}

			for id, targetDomain := range targets {
				if strings.HasSuffix(parsedNewUrl.Hostname(), targetDomain) {
					associatedTargetID = id
					break
				}
			}

			if associatedTargetID != -1 {
				if _, err := database.AddURL(db, associatedTargetID, newURL, "katana"); err == nil {
					newURLsFound++
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading katana output: %v", err)
	}

	color.Green("Crawling phase completed. Found %d new URLs.", newURLsFound)
}

func getURLsToCrawl(db *sql.DB) ([]string, error) {
	urls, err := database.GetLiveURLs(db)
	if err != nil {
		return nil, err
	}
	return urls, nil
} 