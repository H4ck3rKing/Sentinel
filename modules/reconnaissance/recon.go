package reconnaissance

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bug/modules/config"
	"bug/modules/utils"
)

// RunReconnaissance orchestrates the full reconnaissance workflow.
func RunReconnaissance(cfg *config.Config, db *sql.DB) {
	for _, target := range cfg.Targets {
		runForTarget(target, cfg, db)
	}
}

func runForTarget(target string, cfg *config.Config, db *sql.DB) {
	utils.Log(fmt.Sprintf("Starting reconnaissance for: %s", target))

	// Get target ID from the database
	var targetID int64
	err := db.QueryRow("INSERT INTO targets(name) VALUES(?) ON CONFLICT(name) DO UPDATE SET name=name RETURNING id", target).Scan(&targetID)
	if err != nil {
		utils.Error("Could not get target ID from database", err)
		return
	}

	// --- Subdomain Enumeration ---
	utils.Log("Phase 1: Subdomain Enumeration for " + target)
	subdomains, err := runSubfinder(target, cfg)
	if err != nil {
		utils.Error("Subfinder execution failed", err)
		return
	}
	// Insert subdomains into DB
	for _, sub := range subdomains {
		_, err := db.Exec("INSERT OR IGNORE INTO subdomains(target_id, subdomain) VALUES(?, ?)", targetID, sub)
		if err != nil {
			utils.Warn(fmt.Sprintf("Failed to insert subdomain %s: %v", sub, err))
		}
	}
	utils.Success(fmt.Sprintf("Found and saved %d subdomains for %s", len(subdomains), target))

	// Step 2: Resolve discovered subdomains to IPs
	dnsDir := filepath.Join("bugbounty-results", cfg.Workspace, target, "dns")
	os.MkdirAll(dnsDir, 0755)
	resolvedOutputFile := filepath.Join(dnsDir, "resolved.txt")
	runDnsx(subdomains, resolvedOutputFile)

	// Step 3: Scan for open ports on resolved IPs
	portsDir := filepath.Join("bugbounty-results", cfg.Workspace, target, "ports")
	os.MkdirAll(portsDir, 0755)
	naabuOutputFile := filepath.Join(portsDir, "ports.txt")
	runNaabu(resolvedOutputFile, naabuOutputFile)

	// Step 4: Identify web servers on the open ports
	webDir := filepath.Join("bugbounty-results", cfg.Workspace, target, "web")
	os.MkdirAll(webDir, 0755)
	httpxOutputFile := filepath.Join(webDir, "webservers.txt")
	runHttpx(naabuOutputFile, httpxOutputFile)

	// Step 5: Run context-aware vulnerability scans
	runContextualNucleiScans(httpxOutputFile, target)

	utils.Success(fmt.Sprintf("Reconnaissance complete for: %s", target))
}

func runSubfinder(target string, cfg *config.Config) ([]string, error) {
	utils.Log("Running passive subdomain enumeration with Subfinder...")
	// We run the command and capture its output, instead of writing to a file.
	output, err := utils.RunCommandAndCapture("subfinder", "-d", target, "-silent")
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

func runDnsx(inputFile, outputFile string) {
	utils.Log("Resolving subdomains to IP addresses with Dnsx...")
	err := utils.RunCommand("dnsx", "-l", inputFile, "-resp-only", "-o", outputFile, "-silent")
	if err != nil {
		utils.Error("Error running dnsx", err)
	}
}

func runNaabu(inputFile, outputFile string) {
	utils.Log("Scanning for open ports with Naabu...")
	err := utils.RunCommand("naabu", "-l", inputFile, "-o", outputFile, "-silent")
	if err != nil {
		utils.Error("Error running naabu", err)
	}
}

func runHttpx(inputFile, outputFile string) {
	utils.Log("Identifying live web servers with Httpx...")
	err := utils.RunCommand("httpx", "-l", inputFile, "-tech-detect", "-status-code", "-title", "-o", outputFile, "-silent")
	if err != nil {
		utils.Error("Error running httpx", err)
	}
}

func runContextualNucleiScans(httpxFile, targetResultDir string) {
	utils.Log("Starting context-aware vulnerability scanning with Nuclei...")
	techToUrls, err := parseHttpxOutput(httpxFile)
	if err != nil {
		utils.Error("Error parsing httpx output", err)
		return
	}

	if len(techToUrls) == 0 {
		utils.Warn("No technologies detected from httpx output. Skipping targeted Nuclei scans.")
		return
	}

	nucleiDir := filepath.Join(targetResultDir, "vulnerabilities")
	os.MkdirAll(nucleiDir, 0755)
	nucleiOutputFile := filepath.Join(nucleiDir, "nuclei_findings.txt")

	for tech, urls := range techToUrls {
		utils.Log(fmt.Sprintf("Found %d URLs with technology: %s. Running targeted scan.", len(urls), tech))

		tempFile, err := ioutil.TempFile("", "nuclei-targets-*.txt")
		if err != nil {
			utils.Error(fmt.Sprintf("Failed to create temp file for %s", tech), err)
			continue
		}

		for _, url := range urls {
			tempFile.WriteString(url + "\n")
		}
		tempFile.Close()

		err = utils.RunCommand("nuclei", "-l", tempFile.Name(), "-t", "technologies", "-tags", tech, "-o", nucleiOutputFile, "-silent")
		if err != nil {
			utils.Error(fmt.Sprintf("Error running nuclei for tech %s", tech), err)
		}

		os.Remove(tempFile.Name())
	}
}

func parseHttpxOutput(httpxFile string) (map[string][]string, error) {
	file, err := os.Open(httpxFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	techToUrls := make(map[string][]string)
	re := regexp.MustCompile(`\[(.*?)\]`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) < 2 {
			continue
		}
		url := parts[0]

		matches := re.FindAllStringSubmatch(line, -1)
		if len(matches) > 1 {
			techsRaw := matches[1][1]
			techs := strings.Split(techsRaw, ",")
			for _, tech := range techs {
				t := strings.ToLower(strings.TrimSpace(tech))
				if t != "" {
					techToUrls[t] = append(techToUrls[t], url)
				}
			}
		}
	}
	return techToUrls, scanner.Err()
} 