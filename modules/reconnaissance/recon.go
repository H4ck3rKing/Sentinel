package reconnaissance

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"bug/modules/utils"
)

// RunReconnaissance orchestrates the full reconnaissance workflow.
func RunReconnaissance(config map[string]string) {
	target := config["TARGET_DOMAIN"]
	utils.Log(fmt.Sprintf("Starting reconnaissance for: %s", target))

	targetResultDir := filepath.Join("bugbounty-results", target, "recon")
	if err := os.MkdirAll(targetResultDir, 0755); err != nil {
		utils.Error("Error creating target directory", err)
		return
	}
	utils.Log(fmt.Sprintf("Results will be saved in: %s", targetResultDir))

	// Step 1: Discover subdomains
	subdomainsDir := filepath.Join(targetResultDir, "subdomains")
	os.MkdirAll(subdomainsDir, 0755)
	subfinderOutputFile := filepath.Join(subdomainsDir, "subfinder.txt")
	runSubfinder(target, subfinderOutputFile)

	// Step 2: Resolve discovered subdomains to IPs
	dnsDir := filepath.Join(targetResultDir, "dns")
	os.MkdirAll(dnsDir, 0755)
	resolvedOutputFile := filepath.Join(dnsDir, "resolved.txt")
	runDnsx(subfinderOutputFile, resolvedOutputFile)

	// Step 3: Scan for open ports on resolved IPs
	portsDir := filepath.Join(targetResultDir, "ports")
	os.MkdirAll(portsDir, 0755)
	naabuOutputFile := filepath.Join(portsDir, "ports.txt")
	runNaabu(resolvedOutputFile, naabuOutputFile)

	// Step 4: Identify web servers on the open ports
	webDir := filepath.Join(targetResultDir, "web")
	os.MkdirAll(webDir, 0755)
	httpxOutputFile := filepath.Join(webDir, "webservers.txt")
	runHttpx(naabuOutputFile, httpxOutputFile)

	// Step 5: Run context-aware vulnerability scans
	runContextualNucleiScans(httpxOutputFile, targetResultDir)

	utils.Success(fmt.Sprintf("Reconnaissance complete for: %s", target))
}

func runSubfinder(target, outputFile string) {
	utils.Log("Running passive subdomain enumeration with Subfinder...")
	err := utils.RunCommand("subfinder", "-d", target, "-o", outputFile, "-silent")
	if err != nil {
		utils.Error("Error running subfinder", err)
	}
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