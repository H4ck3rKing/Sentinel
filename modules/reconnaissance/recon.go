package reconnaissance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"bug/modules/config"
	"bug/modules/utils"
	_ "github.com/mattn/go-sqlite3"
)

// RunReconnaissance orchestrates the full reconnaissance workflow.
func RunReconnaissance(cfg *config.Config, db *sql.DB) {
	options := utils.Options{
		Output:  cfg.Workspace,
		Threads: cfg.Recon.Threads,
	}

	for _, target := range cfg.Targets {
		runForTarget(target, options, db)
	}
}

func runForTarget(target string, options utils.Options, db *sql.DB) {
	utils.Banner(fmt.Sprintf("Starting reconnaissance for target: %s", target))

	var targetID int64
	// This logic needs to be updated to use the AddTarget function
	// For now, we assume the target exists from the initial setup.
	db.QueryRow("SELECT id FROM targets WHERE target = ?", target).Scan(&targetID)
	if targetID == 0 {
		utils.Error(fmt.Sprintf("Could not find target ID for %s", target), nil)
		return
	}

	// --- Phase 1: Subdomain Enumeration ---
	subdomains, err := runSubfinder(target, options)
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

	// --- Phase 2: DNS Resolution ---
	liveSubdomains, err := runDnsx(subdomains, options)
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
	openPorts, err := runNaabu(ips, options)
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
	liveURLs, err := runHttpx(openPorts, options, db)
	if err != nil {
		return
	}
	utils.Success(fmt.Sprintf("Found and processed %d live web services.", len(liveURLs)))

	utils.Banner(fmt.Sprintf("Reconnaissance complete for: %s", target))
}

func runSubfinder(target string, options utils.Options) ([]string, error) {
	utils.Banner("Running Subdomain Enumeration (subfinder)")
	subfinderCmd := fmt.Sprintf("subfinder -d %s -silent", target)
	output, err := utils.RunCommandAndCapture(subfinderCmd, options)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

func runDnsx(subdomains []string, options utils.Options) (map[string][]string, error) {
	utils.Banner("Running DNS Resolution (dnsx)")
	tempDir := filepath.Join(options.Output, "temp")
	os.MkdirAll(tempDir, 0755)
	tempInputFile := filepath.Join(tempDir, "dnsx-input.txt")
	err := os.WriteFile(tempInputFile, []byte(strings.Join(subdomains, "\n")), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write dnsx input file: %w", err)
	}
	defer os.Remove(tempInputFile)

	dnsxCmd := fmt.Sprintf("dnsx -l %s -silent -a -resp", tempInputFile)
	output, err := utils.RunCommandAndCapture(dnsxCmd, options)
	if err != nil {
		return nil, err
	}

	results := make(map[string][]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.Fields(line)
		if len(parts) > 1 && strings.HasPrefix(parts[1], "[") {
			sub := parts[0]
			ips := strings.Trim(parts[1], "[]")
			results[sub] = strings.Split(ips, ",")
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

func runNaabu(ips []string, options utils.Options) (map[string][]int, error) {
	utils.Banner("Running Port Scanning (naabu)")
	tempDir := filepath.Join(options.Output, "temp")
	os.MkdirAll(tempDir, 0755)
	tempInputFile := filepath.Join(tempDir, "naabu-input.txt")
	err := os.WriteFile(tempInputFile, []byte(strings.Join(ips, "\n")), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write naabu input file: %w", err)
	}
	defer os.Remove(tempInputFile)

	naabuCmd := fmt.Sprintf("naabu -l %s -silent", tempInputFile)
	output, err := utils.RunCommandAndCapture(naabuCmd, options)
	if err != nil {
		return nil, err
	}

	results := make(map[string][]int)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		host := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		results[host] = append(results[host], port)
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

func runHttpx(ports map[string][]int, options utils.Options, db *sql.DB) ([]HttpxResult, error) {
	utils.Banner("Running Web Server Discovery (httpx)")
	var targets []string
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

	httpxCmd := fmt.Sprintf("httpx -l %s -silent -json -tech-detect -status-code -title", tempInputFile)
	output, err := utils.RunCommandAndCapture(httpxCmd, options)
	if err != nil {
		return nil, err
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