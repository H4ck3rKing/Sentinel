package scanning

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bug/modules/config"
	"bug/modules/database"
	"bug/modules/utils"
)

// NucleiResult defines the structure for a single line of Nuclei's JSON output.
type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
}

// RunScan orchestrates the vulnerability scanning workflow.
func RunScan(ctx context.Context, cfg *config.Config, db *sql.DB) {
	options := utils.Options{
		Output:  cfg.Workspace,
		Threads: cfg.Recon.Threads, // Nuclei uses its own concurrency settings
	}
	utils.Banner("Starting Vulnerability Scanning phase")

	// 1. Get all live URLs from the database
	urls, err := database.GetLiveURLs(db)
	if err != nil {
		utils.Error("Could not retrieve URLs from database", err)
		return
	}
	if len(urls) == 0 {
		utils.Warn("No live URLs found in the database to scan. Run 'recon' and 'crawl' first.")
		return
	}

	// 2. Run Nuclei on the discovered URLs
	results, err := runNuclei(ctx, urls, options, cfg)
	if err != nil {
		utils.Error("Error running Nuclei scan", err)
		return
	}

	// 3. Save findings to the database
	savedCount := 0
	for _, res := range results {
		// Find the URL ID to associate with the finding
		var urlID int
		err := db.QueryRow("SELECT id FROM urls WHERE url = ?", res.MatchedAt).Scan(&urlID)
		if err != nil {
			// Try the host if MatchedAt didn't work (for some templates)
			err = db.QueryRow("SELECT id FROM urls WHERE url = ?", res.Host).Scan(&urlID)
			if err != nil {
				utils.Warn(fmt.Sprintf("Could not find URL '%s' in database for finding '%s'", res.MatchedAt, res.Info.Name))
				continue
			}
		}
		if err := database.AddVulnerability(db, urlID, res.TemplateID, res.Info.Name, res.Info.Severity, res.Info.Description); err == nil {
			savedCount++
		}
	}

	utils.Success(fmt.Sprintf("Vulnerability scan complete. Found and saved %d potential vulnerabilities.", savedCount))
}

func runNuclei(ctx context.Context, urls []string, options utils.Options, cfg *config.Config) ([]NucleiResult, error) {
	utils.Banner(fmt.Sprintf("Running Nuclei on %d URLs...", len(urls)))

	tempDir := filepath.Join(options.Output, "temp")
	os.MkdirAll(tempDir, 0755)
	tempInputFile := filepath.Join(tempDir, "nuclei-input.txt")
	err := os.WriteFile(tempInputFile, []byte(strings.Join(urls, "\n")), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write nuclei input file: %w", err)
	}
	defer os.Remove(tempInputFile)

	// Base command arguments
	args := []string{"-l", tempInputFile, "-jsonl"}

	// Adjust templates based on intensity
	switch cfg.Scanning.Intensity {
	case "deep":
		utils.Log("Running deep scan with all templates.")
		// Default behavior is all templates
	case "light":
		utils.Log("Running light scan with high and critical severity templates.")
		args = append(args, "-severity", "high,critical")
	default: // "normal"
		utils.Log("Running normal scan with medium, high, and critical severity templates.")
		args = append(args, "-severity", "medium,high,critical")
	}

	output, err := utils.RunCommandAndCapture(ctx, options, "nuclei", args...)
	if err != nil {
		return nil, err
	}

	var results []NucleiResult
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var res NucleiResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue // Ignore malformed JSON lines
		}
		results = append(results, res)
	}

	return results, nil
} 