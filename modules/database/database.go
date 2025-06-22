package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"bug/modules/config"
	_ "github.com/mattn/go-sqlite3"
)

// InitDB initializes a new SQLite database for the given workspace.
func InitDB(config *config.Config) (*sql.DB, error) {
	// The database will be stored in the workspace directory. We resolve it to an absolute path.
	workspacePath, err := filepath.Abs(config.Workspace)
	if err != nil {
		return nil, fmt.Errorf("could not resolve absolute path for workspace: %w", err)
	}

	// Ensure the directory exists.
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return nil, fmt.Errorf("could not create workspace directory '%s': %w", workspacePath, err)
	}

	dbPath := filepath.Join(workspacePath, "sentinel.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %w", err)
	}

	if err = CreateTables(db); err != nil {
		return nil, fmt.Errorf("could not create tables: %w", err)
	}

	return db, nil
}

// CreateTables sets up the initial schema for the database.
func CreateTables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS targets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL UNIQUE
		);`,
		`CREATE TABLE IF NOT EXISTS subdomains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target_id INTEGER,
			subdomain TEXT NOT NULL UNIQUE,
			FOREIGN KEY(target_id) REFERENCES targets(id)
		);`,
		`CREATE TABLE IF NOT EXISTS ips (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			subdomain_id INTEGER,
			ip_address TEXT NOT NULL,
			FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
		);`,
		`CREATE TABLE IF NOT EXISTS ports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_id INTEGER,
			port INTEGER NOT NULL,
			service TEXT,
			UNIQUE(ip_id, port),
			FOREIGN KEY(ip_id) REFERENCES ips(id)
		);`,
		`CREATE TABLE IF NOT EXISTS urls (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target_id INTEGER,
			url TEXT NOT NULL UNIQUE,
			source TEXT,
			status_code INTEGER,
			title TEXT,
			tech TEXT,
			screenshot_path TEXT,
			FOREIGN KEY(target_id) REFERENCES targets(id)
		);`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url_id INTEGER,
			template_id TEXT NOT NULL,
			name TEXT NOT NULL,
			severity TEXT,
			description TEXT,
			UNIQUE(url_id, template_id),
			FOREIGN KEY (url_id) REFERENCES urls(id)
		);`,
		`CREATE TABLE IF NOT EXISTS exploits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vulnerability_id INTEGER,
			title TEXT NOT NULL,
			edb_id TEXT,
			path TEXT,
			FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
		);`,
		`CREATE TABLE IF NOT EXISTS secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url_id INTEGER,
			type TEXT NOT NULL,
			value TEXT NOT NULL,
			source TEXT NOT NULL,
			FOREIGN KEY (url_id) REFERENCES urls(id)
		);`,
		`CREATE TABLE IF NOT EXISTS parameters (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url_id INTEGER,
			name TEXT NOT NULL,
			source TEXT NOT NULL,
			UNIQUE(url_id, name),
			FOREIGN KEY (url_id) REFERENCES urls(id)
		);`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

// AddTarget adds a new target to the database.
func AddTarget(db *sql.DB, target string) (int64, error) {
	result, err := db.Exec("INSERT OR IGNORE INTO targets (target) VALUES (?)", target)
	if err != nil {
		return 0, err
	}
	id, _ := result.LastInsertId()
	if id == 0 {
		// If LastInsertId is 0, it means the target already existed. Get its ID.
		db.QueryRow("SELECT id FROM targets WHERE target = ?", target).Scan(&id)
	}
	return id, nil
}

// AddSubdomain adds a new subdomain to the database.
func AddSubdomain(db *sql.DB, targetID int64, subdomain string) (int64, error) {
	result, err := db.Exec("INSERT OR IGNORE INTO subdomains (target_id, subdomain) VALUES (?, ?)", targetID, subdomain)
	if err != nil {
		return 0, err
	}
	id, _ := result.LastInsertId()
	if id == 0 {
		db.QueryRow("SELECT id FROM subdomains WHERE subdomain = ?", subdomain).Scan(&id)
	}
	return id, nil
}

// AddIP adds a new IP address for a subdomain.
func AddIP(db *sql.DB, subdomainID int64, ip string) (int64, error) {
	result, err := db.Exec("INSERT OR IGNORE INTO ips (subdomain_id, ip_address) VALUES (?, ?)", subdomainID, ip)
	if err != nil {
		return 0, err
	}
	id, _ := result.LastInsertId()
	if id == 0 {
		db.QueryRow("SELECT id FROM ips WHERE ip_address = ? AND subdomain_id = ?", ip, subdomainID).Scan(&id)
	}
	return id, nil
}

// AddPort adds a new open port for an IP address.
func AddPort(db *sql.DB, ipID int64, port int, service string) (int64, error) {
	result, err := db.Exec("INSERT OR IGNORE INTO ports (ip_id, port, service) VALUES (?, ?, ?)", ipID, port, service)
	if err != nil {
		return 0, err
	}
	id, _ := result.LastInsertId()
	if id == 0 {
		db.QueryRow("SELECT id FROM ports WHERE ip_id = ? AND port = ?", ipID, port).Scan(&id)
	}
	return id, nil
}

// AddURL adds a new URL to the database if it doesn't already exist.
func AddURL(db *sql.DB, targetID int, url string, source string) (int64, error) {
	result, err := db.Exec("INSERT OR IGNORE INTO urls (target_id, url, source) VALUES (?, ?, ?)", targetID, url, source)
	if err != nil {
		return 0, err
	}
	id, _ := result.LastInsertId()
	if id == 0 {
		db.QueryRow("SELECT id FROM urls WHERE url = ?", url).Scan(&id)
	}
	return id, nil
}

// UpdateURLDetails updates the status code, title, and tech for a given URL.
func UpdateURLDetails(db *sql.DB, url, title, tech string, statusCode int) error {
	_, err := db.Exec("UPDATE urls SET status_code = ?, title = ?, tech = ? WHERE url = ?", statusCode, title, tech, url)
	return err
}

// UpdateURLScreenshotPath updates the screenshot path for a given URL.
func UpdateURLScreenshotPath(db *sql.DB, url, path string) error {
	_, err := db.Exec("UPDATE urls SET screenshot_path = ? WHERE url = ?", path, url)
	return err
}

// AddVulnerability adds a new vulnerability to the database.
func AddVulnerability(db *sql.DB, urlID int, templateID, name, severity, description string) error {
	_, err := db.Exec("INSERT OR IGNORE INTO vulnerabilities (url_id, template_id, name, severity, description) VALUES (?, ?, ?, ?, ?)",
		urlID, templateID, name, severity, description)
	return err
}

// AddExploit adds a new exploit to the database.
func AddExploit(db *sql.DB, vulnID int, title, edbID, path string) error {
	_, err := db.Exec("INSERT INTO exploits (vulnerability_id, title, edb_id, path) VALUES (?, ?, ?, ?)", vulnID, title, edbID, path)
	return err
}

// AddSecret adds a new discovered secret to the database.
func AddSecret(db *sql.DB, urlID int, secretType, value, source string) error {
	_, err := db.Exec("INSERT INTO secrets (url_id, type, value, source) VALUES (?, ?, ?, ?)", urlID, secretType, value, source)
	return err
}

// AddParameter adds a new discovered parameter for a URL.
func AddParameter(db *sql.DB, urlID int, name, source string) error {
	_, err := db.Exec("INSERT OR IGNORE INTO parameters (url_id, name, source) VALUES (?, ?, ?)", urlID, name, source)
	return err
}

// GetSubdomains retrieves all subdomains from the database.
func GetSubdomains(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT subdomain FROM subdomains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subdomains []string
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			return nil, err
		}
		subdomains = append(subdomains, subdomain)
	}
	return subdomains, nil
}

// GetIPsForSubdomain retrieves all IPs for a given subdomain ID.
func GetIPsForSubdomain(db *sql.DB, subdomainID int64) ([]string, error) {
	rows, err := db.Query("SELECT ip_address FROM ips WHERE subdomain_id = ?", subdomainID)
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

// GetTargets retrieves all targets from the database.
func GetTargets(db *sql.DB) (map[int]string, error) {
	rows, err := db.Query("SELECT id, target FROM targets")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := make(map[int]string)
	for rows.Next() {
		var id int
		var target string
		if err := rows.Scan(&id, &target); err != nil {
			return nil, err
		}
		targets[id] = target
	}
	return targets, nil
}

// GetLiveURLs retrieves all URLs with a positive status code from the database.
func GetLiveURLs(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT url FROM urls WHERE status_code > 0")
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

// GetLiveURLsAsMap retrieves all URLs with a positive status code from the database as a map[url]id.
func GetLiveURLsAsMap(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query("SELECT id, url FROM urls WHERE status_code > 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	urls := make(map[string]int)
	for rows.Next() {
		var id int
		var url string
		if err := rows.Scan(&id, &url); err != nil {
			return nil, err
		}
		urls[url] = id
	}
	return urls, nil
}

// GetJavaScriptURLs retrieves all JS file URLs from the database.
func GetJavaScriptURLs(db *sql.DB) (map[int]string, error) {
	rows, err := db.Query("SELECT id, url FROM urls WHERE url LIKE '%.js' AND status_code > 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	urls := make(map[int]string)
	for rows.Next() {
		var id int
		var url string
		if err := rows.Scan(&id, &url); err != nil {
			return nil, err
		}
		urls[id] = url
	}
	return urls, nil
}