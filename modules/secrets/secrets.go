package secrets

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"bug/modules/config"
	"bug/modules/database"
	"bug/modules/utils"
	"github.com/fatih/color"
)

// TruffleHogOutput defines the structure for a single secret found by truffleHog
type TruffleHogOutput struct {
	SourceMetadata struct {
		Data struct {
			Git struct {
				Commit string `json:"commit"`
				File   string `json:"file"`
				Email  string `json:"email"`
				Repo   string `json:"repo"`
				Stamp  string `json:"stamp"`
			} `json:"git"`
		} `json:"data"`
	} `json:"source_metadata"`
	SourceID       int    `json:"source_id"`
	SourceType     int    `json:"source_type"`
	SourceName     string `json:"source_name"`
	DetectorType   int    `json:"detector_type"`
	DetectorName   string `json:"detector_name"`
	DecoderName    string `json:"decoder_name"`
	Verified       bool   `json:"verified"`
	Raw            string `json:"raw"`
	Redacted       string `json:"redacted"`
	ExtraData      any    `json:"extra_data"`
	StructuredData any    `json:"structured_data"`
}

func RunSecrets(ctx context.Context, config *config.Config, db *sql.DB) {
	options := utils.Options{
		Output:  config.Workspace,
		Threads: config.Recon.Threads,
	}
	color.Cyan("[*] Starting Secrets scanning phase")

	if !utils.CommandExists("trufflehog") {
		color.Red("trufflehog not found. Please install it first.")
		color.Yellow("Hint: go install github.com/trufflesecurity/trufflehog/v3@latest")
		return
	}

	utils.Banner("Fetching JavaScript URLs from database")
	jsURLs, err := database.GetJavaScriptURLs(db)
	if err != nil {
		color.Red("Error getting JavaScript URLs from database: %v", err)
		return
	}

	if len(jsURLs) == 0 {
		color.Yellow("No JavaScript files found in the database to scan.")
		return
	}
	color.Green("Found %d JavaScript files to scan.", len(jsURLs))

	tempDir := filepath.Join(options.Output, "temp", "secrets")
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir)

	secretsFoundCount := 0
	for urlID, jsURL := range jsURLs {
		color.White("Scanning: %s", jsURL)
		resp, err := http.Get(jsURL)
		if err != nil {
			color.Yellow("Failed to download %s: %v", jsURL, err)
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			color.Yellow("Failed to read content of %s: %v", jsURL, err)
			continue
		}

		tmpFile, err := ioutil.TempFile(tempDir, "trufflehog-*.js")
		if err != nil {
			color.Red("Failed to create temp file: %v", err)
			continue
		}
		tmpFile.Write(body)
		tmpFile.Close()

		// We use RunCommandAndCapture since trufflehog might print a lot of stuff to stderr
		// that we don't want to pollute the main UI with. The output is what matters.
		output, err := utils.RunCommandAndCapture(ctx, options, "trufflehog", "filesystem", tmpFile.Name(), "--json")
		if err != nil {
			// trufflehog exits with non-zero if it finds secrets, so we can't rely on the exit code
			// but we should still log if there's a different kind of error.
			if len(output) == 0 {
				color.Red("Error running trufflehog on %s: %v", tmpFile.Name(), err)
				continue
			}
		}

		scanner := bufio.NewScanner(strings.NewReader(output))
		for scanner.Scan() {
			var secret TruffleHogOutput
			line := scanner.Text()
			if err := json.Unmarshal([]byte(line), &secret); err == nil {
				if secret.DetectorName != "" && secret.Raw != "" {
					color.HiRed("[!] Secret Found in %s!", jsURL)
					color.Yellow("  > Type: %s", secret.DetectorName)
					color.Yellow("  > Value: %s", secret.Redacted) // Show redacted value for safety
					database.AddSecret(db, urlID, secret.DetectorName, secret.Raw, "trufflehog")
					secretsFoundCount++
				}
			}
		}
	}

	color.Green("Secrets scanning phase completed. Found %d new secrets.", secretsFoundCount)
} 