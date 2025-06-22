package fuzzing

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"bug/modules/config"
	"bug/modules/database"
	"bug/modules/utils"
	"github.com/fatih/color"
)

// FFUFOutput represents the structure of ffuf's JSON output
type FFUFOutput struct {
	Results []struct {
		URL string `json:"url"`
	} `json:"results"`
}

// getBaseURLs extracts unique base URLs (scheme + host) from a list of full URLs.
func getBaseURLs(urls map[string]int) []string {
	baseURLs := make(map[string]struct{})
	for uStr := range urls {
		parsed, err := url.Parse(uStr)
		if err == nil {
			base := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
			baseURLs[base] = struct{}{}
		}
	}

	keys := make([]string, 0, len(baseURLs))
	for k := range baseURLs {
		keys = append(keys, k)
	}
	return keys
}

func RunFuzzing(ctx context.Context, config *config.Config, db *sql.DB) {
	options := utils.Options{
		Output:  config.Workspace,
		Threads: config.Recon.Threads, // ffuf uses its own thread control
	}
	color.Cyan("[*] Starting Content Discovery (Fuzzing) phase")

	if !utils.CommandExists("ffuf") {
		color.Red("ffuf not found. Please install it first.")
		color.Yellow("Hint: go install github.com/ffuf/ffuf@latest")
		return
	}

	wordlist := config.Fuzzing.Wordlist
	// If the user hasn't specified a custom wordlist in config.yaml,
	// use the default wordlist that is packaged with the application.
	if wordlist == "" {
		wordlist = "/usr/share/sentinel/wordlists/default.txt"
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		// As a last resort, check the local path for development environments.
		localWordlist := "wordlists/default.txt"
		if _, err := os.Stat(localWordlist); err == nil {
			wordlist = localWordlist
		} else {
			utils.Error(fmt.Sprintf("Fuzzing wordlist not found at default location: %s", wordlist), err)
			utils.Warn("Please ensure Sentinel is installed correctly or specify a valid wordlist path in config.yaml.")
			return
		}
	}

	utils.Banner("Fetching live URLs to determine base targets for fuzzing")
	urls, err := database.GetLiveURLsAsMap(db)
	if err != nil {
		color.Red("Error getting URLs from database: %v", err)
		return
	}

	baseURLs := getBaseURLs(urls)
	if len(baseURLs) == 0 {
		color.Yellow("No base URLs found to fuzz.")
		return
	}
	color.Green("Found %d unique base URLs to fuzz.", len(baseURLs))

	targets, err := database.GetTargets(db)
	if err != nil {
		color.Red("Error getting targets for URL association: %v", err)
		return
	}

	newURLsFound := 0
	for _, baseURL := range baseURLs {
		utils.Log(fmt.Sprintf("Fuzzing: %s", baseURL))
		output, err := utils.RunCommandAndCapture(ctx, options, "ffuf", "-w", wordlist, "-u", baseURL+"/FUZZ", "-ac", "-o", "/dev/stdout", "-of", "json")
		if err != nil && len(output) == 0 {
			utils.Warn(fmt.Sprintf("Error running ffuf on %s: %v", baseURL, err))
			continue
		}

		var ffufResult FFUFOutput
		if err := json.Unmarshal([]byte(output), &ffufResult); err == nil {
			for _, result := range ffufResult.Results {
				newURL := result.URL

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
					if _, err := database.AddURL(db, associatedTargetID, newURL, "ffuf"); err == nil {
						newURLsFound++
						color.HiGreen("  [+] Found content: %s", newURL)
					}
				}
			}
		} else {
			utils.Warn(fmt.Sprintf("Failed to parse ffuf output for %s: %v", baseURL, err))
		}
	}

	utils.Success(fmt.Sprintf("Fuzzing phase completed. Found %d new URLs.", newURLsFound))
}
