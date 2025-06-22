package reporting

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sentinel/modules/config"
	"sentinel/modules/utils"
)

// ReportData holds all the structured information for a report.
type ReportData struct {
	Workspace      string
	Timestamp      string
	Targets        []TargetData
	TotalVulns     int
	SeverityCounts map[string]int
}

type TargetData struct {
	Name           string
	Vulnerabilities []VulnInfo
}

type VulnInfo struct {
	Name        string
	Severity    string
	Description string
	URL         string
	Exploits    []ExploitInfo
}

type ExploitInfo struct {
	Title  string
	EDB_ID string
	Path   string
}

// GenerateReport creates a markdown report from the database.
func GenerateReport(cfg *config.Config, db *sql.DB) {
	utils.Log("Generating professional engagement report...")

	data, err := gatherData(db, cfg.Workspace)
	if err != nil {
		utils.Error("Failed to gather data for report", err)
		return
	}

	reportContent := buildMarkdown(data)
	reportsDir := filepath.Join(cfg.Workspace, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		utils.Error("Failed to create reports directory", err)
		return
	}
	reportPath := filepath.Join(reportsDir, "summary_report.md")

	err = os.WriteFile(reportPath, []byte(reportContent), 0644)
	if err != nil {
		utils.Error("Failed to write report to file", err)
		return
	}

	utils.Success(fmt.Sprintf("Report successfully generated at: %s", reportPath))
}

func gatherData(db *sql.DB, workspace string) (*ReportData, error) {
	data := &ReportData{
		Workspace:      workspace,
		Timestamp:      time.Now().Format(time.RFC822),
		SeverityCounts: make(map[string]int),
	}

	rows, err := db.Query(`
		SELECT t.target, v.name, v.severity, v.description, u.url, e.title, e.edb_id, e.path
		FROM vulnerabilities v
		JOIN urls u ON v.url_id = u.id
		JOIN targets t ON u.target_id = t.id
		LEFT JOIN exploits e ON v.id = e.vulnerability_id
		ORDER BY t.target, v.severity, v.name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query report data: %w", err)
	}
	defer rows.Close()

	vulnMap := make(map[string]map[string]*VulnInfo)
	targetMap := make(map[string]bool)

	for rows.Next() {
		var targetName, vulnName, severity, description, url, exploitTitle, edbID, exploitPath sql.NullString
		if err := rows.Scan(&targetName, &vulnName, &severity, &description, &url, &exploitTitle, &edbID, &exploitPath); err != nil {
			return nil, fmt.Errorf("failed to scan report row: %w", err)
		}

		if !targetName.Valid || !vulnName.Valid {
			continue
		}
		targetMap[targetName.String] = true

		if _, ok := vulnMap[targetName.String]; !ok {
			vulnMap[targetName.String] = make(map[string]*VulnInfo)
		}

		vulnKey := fmt.Sprintf("%s|%s", url.String, vulnName.String)
		if _, ok := vulnMap[targetName.String][vulnKey]; !ok {
			vulnMap[targetName.String][vulnKey] = &VulnInfo{
				Name:        vulnName.String,
				Severity:    severity.String,
				Description: description.String,
				URL:         url.String,
				Exploits:    []ExploitInfo{},
			}
			data.TotalVulns++
			data.SeverityCounts[severity.String]++
		}

		if exploitTitle.Valid {
			vulnMap[targetName.String][vulnKey].Exploits = append(vulnMap[targetName.String][vulnKey].Exploits, ExploitInfo{
				Title:  exploitTitle.String,
				EDB_ID: edbID.String,
				Path:   exploitPath.String,
			})
		}
	}

	for targetName, vulns := range vulnMap {
		target := TargetData{Name: targetName}
		for _, v := range vulns {
			target.Vulnerabilities = append(target.Vulnerabilities, *v)
		}
		data.Targets = append(data.Targets, target)
	}

	return data, nil
}

func buildMarkdown(data *ReportData) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Sentinel Engagement Report: %s\n\n", data.Workspace))
	sb.WriteString(fmt.Sprintf("**Report Generated:** %s\n\n", data.Timestamp))
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("This report details the findings from an automated security assessment conducted by the Sentinel framework. The following is a summary of vulnerabilities discovered across all targets.\n\n")

	// Severity Table
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	severities := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severities {
		if count, ok := data.SeverityCounts[sev]; ok {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.Title(sev), count))
		}
	}
	sb.WriteString(fmt.Sprintf("\nA total of **%d vulnerabilities** were identified.\n\n", data.TotalVulns))

	sb.WriteString("## Detailed Findings\n\n")
	if len(data.Targets) == 0 {
		sb.WriteString("No vulnerabilities to report.\n")
	} else {
		for _, target := range data.Targets {
			sb.WriteString(fmt.Sprintf("### Target: `%s`\n\n", target.Name))
			for _, vuln := range target.Vulnerabilities {
				sb.WriteString(fmt.Sprintf("#### %s\n\n", vuln.Name))
				sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.Title(vuln.Severity)))
				sb.WriteString(fmt.Sprintf("- **URL:** `%s`\n", vuln.URL))
				sb.WriteString(fmt.Sprintf("- **Description:** %s\n", vuln.Description))

				if len(vuln.Exploits) > 0 {
					sb.WriteString("- **Potential Exploits:**\n")
					for _, exploit := range vuln.Exploits {
						sb.WriteString(fmt.Sprintf("  - **Title:** %s\n", exploit.Title))
						sb.WriteString(fmt.Sprintf("    - **EDB-ID:** %s\n", exploit.EDB_ID))
						sb.WriteString(fmt.Sprintf("    - **Path:** `%s`\n", exploit.Path))
					}
				}
				sb.WriteString("\n---\n\n")
			}
		}
	}

	return sb.String()
} 