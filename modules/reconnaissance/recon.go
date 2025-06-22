package reconnaissance

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"bug/modules/config"
	"bug/modules/database"
	"bug/modules/utils"
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
	ips, err := getIPsForTarget(db, targetID)
	if err != nil || len(ips) == 0 {
		utils.Warn("No IPs found for port scanning.")
		return
	}
	openPorts, err := runNaabu(ctx, ips, options)
	if err != nil {
		return
	}
	for host, ports := range openPorts {
		var ipID int64
		// This is a simplification; a real implementation would handle domain-to-IP relationships better.
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

	// --- Phase 4: Web Server Discovery ---
	// First, get URLs from passive discovery
	urls, err := getURLsForTarget(db, targetID)
	if err != nil {
		utils.Warn("Could not get URLs from database for httpx.")
		urls = []string{}
	}

	liveURLs, err := runHttpx(ctx, openPorts, urls, options, db)
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

	output, err := utils.RunCommandAndCapture(ctx, options, "subfinder", "-d", target, "-silent")
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

	output, err := utils.RunCommandAndCapture(ctx, options, "dnsx", "-l", tempInputFile, "-silent", "-json")
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

	output, err := utils.RunCommandAndCapture(ctx, options, "naabu", "-l", tempInputFile, "-silent", "-json")
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

func runHttpx(ctx context.Context, ports map[string][]int, passiveURLs []string, options utils.Options, db *sql.DB) ([]HttpxResult, error) {
	utils.Banner("Running Web Server Discovery (httpx)")
	targets := passiveURLs
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

	output, err := utils.RunCommandAndCapture(ctx, options, "httpx", "-l", tempInputFile, "-silent", "-json", "-tech-detect", "-status-code", "-title")
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

		// Parse the input to get the original IP and Port
		host, portStr, err := net.SplitHostPort(res.Input)
		if err != nil {
			utils.Warn(fmt.Sprintf("Could not parse httpx input %s: %v", res.Input, err))
			continue
		}
		port, _ := strconv.Atoi(portStr)

		// Find the corresponding port_id in the database
		var portID int64
		// We need to find the ip_id first
		var ipID int64
		err = db.QueryRow("SELECT id FROM ips WHERE ip_address = ?", host).Scan(&ipID)
		if err != nil {
			// This can happen if the host is a domain, not an IP. For now, we'll log and skip.
			utils.Warn(fmt.Sprintf("Could not find ip_id for host %s from httpx input. URL: %s. Error: %v", host, res.URL, err))
			continue
		}

		// Now find the port_id
		err = db.QueryRow("SELECT id FROM ports WHERE ip_id = ? AND port = ?", ipID, port).Scan(&portID)
		if err != nil {
			utils.Warn(fmt.Sprintf("Could not find port_id for IP %s and port %d: %v", host, port, err))
			continue
		}

		// Insert the URL into the database
		result, err := db.Exec("INSERT OR IGNORE INTO urls(port_id, url, status_code, title) VALUES(?, ?, ?, ?)",
			portID, res.URL, res.StatusCode, res.Title)
		if err != nil {
			utils.Warn(fmt.Sprintf("Failed to insert URL %s: %v", res.URL, err))
			continue
		}

		urlID, err := result.LastInsertId()
		if err != nil {
			utils.Warn(fmt.Sprintf("Failed to get last insert ID for URL %s: %v", res.URL, err))
			continue
		}

		// Insert technologies
		for _, tech := range res.Tech {
			_, err := db.Exec("INSERT OR IGNORE INTO technologies(url_id, technology) VALUES(?, ?)", urlID, tech)
			if err != nil {
				utils.Warn(fmt.Sprintf("Failed to insert technology %s for URL %s: %v", tech, res.URL, err))
			}
		}

		results = append(results, res)
	}
	return results, nil
} 