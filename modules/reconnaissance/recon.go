package reconnaissance

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sentinel/modules/config"
	"sentinel/modules/database"
	"sentinel/modules/utils"

	_ "github.com/mattn/go-sqlite3"
)

// RunReconnaissance orchestrates the full reconnaissance workflow.
func RunReconnaissance(ctx context.Context, cfg *config.Config, db *sql.DB) {
	for _, target := range cfg.Targets {
		runForTarget(ctx, target, cfg, db)
	}
}

func runForTarget(ctx context.Context, target string, cfg *config.Config, db *sql.DB) {
	utils.Banner(fmt.Sprintf("Starting reconnaissance for target: %s", target))

	options := utils.Options{
		Output:  cfg.Workspace,
		Threads: cfg.Recon.Threads,
	}

	targetID, err := database.AddTarget(db, target)
	if err != nil {
		utils.Error(fmt.Sprintf("Could not add or get target ID for %s", target), err)
		return
	}

	// --- Phase 1: Subdomain Enumeration ---
	subdomains, err := runSubfinder(ctx, target, options, cfg)
	if err != nil {
		return // Error already logged
	}
	for _, sub := range subdomains {
		_, err := db.Exec("INSERT OR IGNORE INTO subdomains(target_id, subdomain) VALUES(?, ?)", targetID, sub)
		if err != nil {
			utils.Warn(fmt.Sprintf("Failed to insert subdomain %s: %v", sub, err))
		}
	}
	utils.Success(fmt.Sprintf("Found %d subdomains.", len(subdomains)))

	// --- Phase 1.5: Passive URL Discovery ---
	gauURLs, err := runGau(ctx, target, options)
	if err != nil {
		// This is a soft error, passive discovery might fail
		utils.Warn(fmt.Sprintf("gau passive discovery failed: %v", err))
	} else {
		for _, u := range gauURLs {
			_, err := db.Exec("INSERT OR IGNORE INTO urls(target_id, url, source) VALUES(?, ?, ?)", targetID, u, "gau")
			if err != nil {
				utils.Warn(fmt.Sprintf("Failed to insert gau URL %s: %v", u, err))
			}
		}
		utils.Success(fmt.Sprintf("Found %d URLs via passive discovery.", len(gauURLs)))
	}

	// --- Phase 2: DNS Resolution ---
	liveSubdomains, err := runDnsx(ctx, subdomains, options)
	if err != nil {
		return
	}
	for sub, ips := range liveSubdomains {
		var subID int64
		err := db.QueryRow("SELECT id FROM subdomains WHERE subdomain = ?", sub).Scan(&subID)
		if err != nil {
			continue // Skip if subdomain not in DB
		}
		for _, ip := range ips {
			_, err := db.Exec("INSERT OR IGNORE INTO ips(subdomain_id, ip_address) VALUES(?, ?)", subID, ip)
			if err != nil {
				utils.Warn(fmt.Sprintf("Failed to insert IP %s for %s: %v", ip, sub, err))
			}
		}
	}
	utils.Success(fmt.Sprintf("Resolved IPs for %d live subdomains.", len(liveSubdomains)))

	// --- Phase 3: Port Scanning ---
	var openPorts = make(map[string][]int)
	ips, err := getIPsForTarget(db, targetID)
	if err != nil {
		utils.Warn(fmt.Sprintf("Could not get IPs for target %d from db", targetID))
	}

	if len(ips) > 0 {
		openPorts, err = runNaabu(ctx, ips, options)
		if err != nil {
			return // Naabu error is critical enough to stop
		}
		for host, ports := range openPorts {
			var ipID int64
			err := db.QueryRow("SELECT id FROM ips WHERE ip_address = ?", host).Scan(&ipID)
			if err != nil {
				continue
			}
			for _, port := range ports {
				_, err := db.Exec("INSERT OR IGNORE INTO ports(ip_id, port) VALUES(?, ?)", ipID, port)
				if err != nil {
					utils.Warn(fmt.Sprintf("Failed to insert port %d for %s: %v", port, host, err))
				}
			}
		}
		utils.Success(fmt.Sprintf("Found open ports for %d hosts.", len(openPorts)))
	} else {
		utils.Warn("No IPs found for port scanning. Proceeding with web discovery on subdomains.")
	}

	// --- Phase 4: Web Server Discovery ---
	// Get all subdomains for the target to scan them with httpx
	allSubdomains, err := getSubdomainsForTarget(db, targetID)
	if err != nil {
		utils.Warn("Could not get subdomains from database for httpx.")
		allSubdomains = []string{} // ensure it's not nil
	}
	// Also get URLs from passive discovery
	urls, err := getURLsForTarget(db, targetID)
	if err != nil {
		utils.Warn("Could not get URLs from database for httpx.")
		urls = []string{}
	}

	liveURLs, err := runHttpx(ctx, openPorts, allSubdomains, urls, options, db, targetID)
	if err != nil {
		return
	}
	utils.Success(fmt.Sprintf("Found and processed %d live web services.", len(liveURLs)))

	utils.Banner(fmt.Sprintf("Reconnaissance complete for: %s", target))
}

func runSubfinder(ctx context.Context, target string, options utils.Options, cfg *config.Config) ([]string, error) {
	utils.Banner("Running Subdomain Enumeration (subfinder)")

	// Use API keys if available
	if cfg.APIKeys.GitHub != "" {
		if options.Env == nil {
			options.Env = make(map[string]string)
		}
		options.Env["GITHUB_TOKEN"] = cfg.APIKeys.GitHub
		utils.Success("Using GitHub API key for subfinder.")
	}

	output, err := utils.RunCommandAndCapture(ctx, options, "subfinder", "-d", target)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

func runGau(ctx context.Context, target string, options utils.Options) ([]string, error) {
	utils.Banner("Running Passive URL Discovery (gau)")
	output, err := utils.RunCommandAndCapture(ctx, options, "gau", target)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

type DnsxResult struct {
	Host string   `json:"host"`
	IPs  []string `json:"ip"`
}

func runDnsx(ctx context.Context, subdomains []string, options utils.Options) (map[string][]string, error) {
	utils.Banner("Running DNS Resolution (dnsx)")
	tempDir := filepath.Join(options.Output, "temp")
	os.MkdirAll(tempDir, 0755)
	tempInputFile := filepath.Join(tempDir, "dnsx-input.txt")
	err := os.WriteFile(tempInputFile, []byte(strings.Join(subdomains, "\n")), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write dnsx input file: %w", err)
	}
	defer os.Remove(tempInputFile)

	absInputFile, err := filepath.Abs(tempInputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for dnsx input: %w", err)
	}

	output, err := utils.RunCommandAndCapture(ctx, options, "dnsx", "-l", absInputFile, "-json")
	if err != nil {
		// dnsx can return an error if it fails to resolve anything, which isn't a fatal error for the whole program.
		// We log it and return an empty map to allow the recon flow to continue.
		utils.Warn(fmt.Sprintf("dnsx command failed. This may happen if no domains could be resolved. Error: %v", err))
		return make(map[string][]string), nil
	}

	// If the output is empty, it means no domains were resolved.
	if strings.TrimSpace(output) == "" {
		utils.Log("dnsx returned no output, meaning no subdomains could be resolved.")
		return make(map[string][]string), nil
	}

	results := make(map[string][]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var res DnsxResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			utils.Warn(fmt.Sprintf("Could not unmarshal dnsx output line: %s", line))
			continue
		}
		if len(res.IPs) > 0 {
			results[res.Host] = res.IPs
		}
	}
	return results, nil
}

func getIPsForTarget(db *sql.DB, targetID int64) ([]string, error) {
	rows, err := db.Query(`
		SELECT DISTINCT i.ip_address
		FROM ips i
		JOIN subdomains s ON i.subdomain_id = s.id
		WHERE s.target_id = ?`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func getURLsForTarget(db *sql.DB, targetID int64) ([]string, error) {
	rows, err := db.Query("SELECT url FROM urls WHERE target_id = ?", targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var urls []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, err
		}
		urls = append(urls, url)
	}
	return urls, nil
}

type NaabuResult struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func runNaabu(ctx context.Context, ips []string, options utils.Options) (map[string][]int, error) {
	utils.Banner("Running Port Scanning (naabu)")
	tempDir := filepath.Join(options.Output, "temp")
	os.MkdirAll(tempDir, 0755)
	tempInputFile := filepath.Join(tempDir, "naabu-input.txt")
	err := os.WriteFile(tempInputFile, []byte(strings.Join(ips, "\n")), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write naabu input file: %w", err)
	}
	defer os.Remove(tempInputFile)

	absInputFile, err := filepath.Abs(tempInputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for naabu input: %w", err)
	}

	output, err := utils.RunCommandAndCapture(ctx, options, "naabu", "-l", absInputFile, "-json")
	if err != nil {
		return nil, err
	}

	results := make(map[string][]int)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var res NaabuResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			utils.Warn(fmt.Sprintf("Could not unmarshal naabu output line: %s", line))
			continue
		}
		results[res.Host] = append(results[res.Host], res.Port)
	}
	return results, nil
}

type HttpxResult struct {
	Input      string   `json:"input"`
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
}

func runHttpx(ctx context.Context, ports map[string][]int, subdomains []string, passiveURLs []string, options utils.Options, db *sql.DB, targetID int64) ([]HttpxResult, error) {
	utils.Banner("Running Web Server Discovery (httpx)")
	targets := passiveURLs
	targets = append(targets, subdomains...)
	for host, portList := range ports {
		for _, port := range portList {
			targets = append(targets, fmt.Sprintf("%s:%d", host, port))
		}
	}

	tempDir := filepath.Join(options.Output, "temp")
	os.MkdirAll(tempDir, 0755)
	tempInputFile := filepath.Join(tempDir, "httpx-input.txt")
	err := os.WriteFile(tempInputFile, []byte(strings.Join(targets, "\n")), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write httpx input file: %w", err)
	}
	defer os.Remove(tempInputFile)

	absInputFile, err := filepath.Abs(tempInputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for httpx input: %w", err)
	}

	output, err := utils.RunCommandAndCapture(ctx, options, "httpx", "-l", absInputFile, "-json", "-tech-detect", "-status-code", "-title")
	if err != nil {
		utils.Warn(fmt.Sprintf("httpx failed: %v", err))
		// We return a partial result if possible
		var results []HttpxResult
		for _, url := range passiveURLs {
			results = append(results, HttpxResult{URL: url})
		}
		return results, nil
	}

	var results []HttpxResult
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var res HttpxResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			utils.Warn(fmt.Sprintf("Could not unmarshal httpx output line: %s", line))
			continue // Ignore lines that aren't valid JSON
		}

		// Combine technologies into a single string
		techStr := strings.Join(res.Tech, ", ")

		// Insert or Update the URL in the database
		// We use INSERT OR IGNORE and then UPDATE to handle both new and existing (from gau) URLs.
		_, err := db.Exec("INSERT OR IGNORE INTO urls(target_id, url, source) VALUES(?, ?, ?)",
			targetID, res.URL, "httpx")
		if err != nil {
			utils.Warn(fmt.Sprintf("Failed to insert URL %s: %v", res.URL, err))
			continue
		}

		// Now update the details for the URL.
		_, err = db.Exec("UPDATE urls SET status_code = ?, title = ?, tech = ? WHERE url = ?",
			res.StatusCode, res.Title, techStr, res.URL)
		if err != nil {
			utils.Warn(fmt.Sprintf("Failed to update details for URL %s: %v", res.URL, err))
			continue
		}

		results = append(results, res)
	}
	return results, nil
}

func getSubdomainsForTarget(db *sql.DB, targetID int64) ([]string, error) {
	rows, err := db.Query(`
		SELECT s.subdomain
		FROM subdomains s
		WHERE s.target_id = ?`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subdomains []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			return nil, err
		}
		subdomains = append(subdomains, sub)
	}
	return subdomains, nil
}
