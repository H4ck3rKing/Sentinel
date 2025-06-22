package visual

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"sentinel/modules/config"
	"sentinel/modules/database"
	"sentinel/modules/utils"
	"github.com/fatih/color"
	_ "github.com/mattn/go-sqlite3"
)

func RunVisual(ctx context.Context, config *config.Config, db *sql.DB) {
	options := utils.Options{
		Output:  config.Workspace,
		Threads: config.Recon.Threads,
	}
	color.Cyan("[*] Starting Visual Reconnaissance phase")

	if !utils.CommandExists("gowitness") {
		color.Red("gowitness not found. Please install it first.")
		color.Yellow("Hint: go install github.com/sensepost/gowitness@latest")
		return
	}

	utils.Banner("Fetching live URLs for screenshotting")
	urls, err := database.GetLiveURLs(db)
	if err != nil {
		color.Red("Error getting URLs from database: %v", err)
		return
	}

	if len(urls) == 0 {
		color.Yellow("No live URLs found to screenshot.")
		return
	}
	color.Green("Found %d live URLs to screenshot.", len(urls))

	screenshotDir := filepath.Join(options.Output, "screenshots")
	os.MkdirAll(screenshotDir, 0755)
	gowitnessDBPath := filepath.Join(screenshotDir, "gowitness.sqlite")

	// Create a temporary file for gowitness to read URLs from
	tempInputFile, err := os.CreateTemp(options.Output, "gowitness-input-*.txt")
	if err != nil {
		color.Red("Failed to create temp input file: %v", err)
		return
	}
	defer os.Remove(tempInputFile.Name())

	for _, u := range urls {
		fmt.Fprintln(tempInputFile, u)
	}
	tempInputFile.Close()

	utils.Banner("Running gowitness... this may take a while")
	// gowitness command to use our temp file and output to our designated screenshot directory
	utils.RunCommand(ctx, options, "gowitness", "file", "-f", tempInputFile.Name(), "-d", screenshotDir, "--db-path", gowitnessDBPath)

	utils.Banner("Updating database with screenshot paths")
	// Now, read the gowitness database to get the paths
	gwDB, err := sql.Open("sqlite3", gowitnessDBPath)
	if err != nil {
		color.Red("Failed to open gowitness database at %s: %v", gowitnessDBPath, err)
		return
	}
	defer gwDB.Close()

	rows, err := gwDB.Query("SELECT url, screenshot_path FROM urls WHERE screenshot_path IS NOT NULL")
	if err != nil {
		color.Red("Failed to query gowitness database: %v", err)
		return
	}
	defer rows.Close()

	updateCount := 0
	for rows.Next() {
		var u, path string
		if err := rows.Scan(&u, &path); err == nil {
			fullPath := filepath.Join(screenshotDir, path)
			if err := database.UpdateURLScreenshotPath(db, u, fullPath); err == nil {
				updateCount++
			}
		}
	}
	color.Green("Visual recon phase completed. Updated %d screenshot paths in the database.", updateCount)
	color.Cyan("Screenshots are saved in: %s", screenshotDir)
} 