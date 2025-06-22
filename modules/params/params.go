package params

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"bug/modules/config"
	"bug/modules/database"
	"bug/modules/utils"
	"github.com/fatih/color"
)

// ArjunOutput represents the structure of arjun's JSON output for a single URL.
type ArjunOutput struct {
	Parameters map[string][]string `json:"parameters"`
}

func RunParams(ctx context.Context, config *config.Config, db *sql.DB) {
	options := utils.Options{
		Output:  config.Workspace,
		Threads: config.Recon.Threads,
	}
	color.Cyan("[*] Starting Parameter discovery phase")

	if !utils.CommandExists("arjun") {
		color.Red("arjun not found. Please install it first.")
		color.Yellow("Hint: pip3 install arjun")
		return
	}

	utils.Banner("Fetching live URLs from database for parameter discovery")
	urls, err := database.GetLiveURLsAsMap(db)
	if err != nil {
		color.Red("Error getting URLs from database: %v", err)
		return
	}

	if len(urls) == 0 {
		color.Yellow("No live URLs found in the database to scan for parameters.")
		return
	}
	color.Green("Found %d live URLs to scan for parameters.", len(urls))

	paramsFoundCount := 0
	for urlStr, urlID := range urls {
		utils.Log(fmt.Sprintf("Scanning: %s", urlStr))

		output, err := utils.RunCommandAndCapture(ctx, options, "arjun", "-u", urlStr, "-oJ", "/dev/stdout", "--stable")
		if err != nil {
			if len(output) == 0 {
				utils.Warn(fmt.Sprintf("Error running arjun on %s: %v", urlStr, err))
				continue
			}
		}

		jsonStartIndex := strings.Index(output, "{")
		if jsonStartIndex == -1 {
			continue
		}
		jsonOutput := output[jsonStartIndex:]

		var arjunResult ArjunOutput
		if err := json.Unmarshal([]byte(jsonOutput), &arjunResult); err == nil {
			if params, ok := arjunResult.Parameters[urlStr]; ok {
				for _, param := range params {
					database.AddParameter(db, urlID, param, "arjun")
					paramsFoundCount++
					utils.Success(fmt.Sprintf("  [+] Found parameter: %s", param))
				}
			}
		} else {
			utils.Warn(fmt.Sprintf("Failed to parse arjun output for %s: %v", urlStr, err))
		}
	}

	utils.Success(fmt.Sprintf("Parameter discovery phase completed. Found %d new parameters.", paramsFoundCount))
} 