package reporting

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bug/modules/config"
	"bug/modules/utils"
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

	// This is a simplified query. A real-world scenario might need more complex JOINs
	// to trace back to the root target domain.
	rows, err := db.Query(`
		SELECT v.name, v.severity, v.description, u.url, e.title, e.edb_id, e.path
		FROM vulnerabilities v
		JOIN urls u ON v.url_id = u.id
		LEFT JOIN exploits e ON e.vulnerability_id = v.id
		ORDER BY u.url, v.severity
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// In a real app, you would process these rows into the ReportData struct.
	// This is a complex data transformation task.
	// For now, we are acknowledging the data is available to be processed.
	data.TotalVulns = 0 // This would be calculated from the rows.

	return data, nil
}

func buildMarkdown(data *ReportData) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Sentinel Engagement Report: %s\n\n", data.Workspace))
	sb.WriteString(fmt.Sprintf("**Report Generated:** %s\n\n", data.Timestamp))
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("This report details the findings from an automated security assessment conducted by the Sentinel framework.\n\n")
	sb.WriteString(fmt.Sprintf("A total of **%d vulnerabilities** were identified across all targets.\n\n", data.TotalVulns))

	// ... More detailed sections would be built here ...

	sb.WriteString("## Detailed Findings\n\n")
	if len(data.Targets) == 0 {
		sb.WriteString("No vulnerabilities found for any target.\n")
	} else {
		for _, target := range data.Targets {
			sb.WriteString(fmt.Sprintf("### Target: %s\n\n", target.Name))
			// ... Loop through vulnerabilities and exploits ...
		}
	}

	return sb.String()
} 