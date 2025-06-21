package database

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3" // The database driver
)

const dbDir = "bugbounty-results"

// InitDB initializes a new SQLite database for the given workspace.
func InitDB(workspace string) (*sql.DB, error) {
	dbPath := filepath.Join(dbDir, workspace, "sentinel.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %w", err)
	}

	if err = createTables(db); err != nil {
		return nil, fmt.Errorf("could not create tables: %w", err)
	}

	return db, nil
}

// createTables sets up the initial schema for the database.
func createTables(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE
	);

	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER,
		subdomain TEXT NOT NULL UNIQUE,
		FOREIGN KEY(target_id) REFERENCES targets(id)
	);

	CREATE TABLE IF NOT EXISTS ips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		subdomain_id INTEGER,
		ip_address TEXT NOT NULL,
		FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
	);

	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_id INTEGER,
		port INTEGER NOT NULL,
		service TEXT,
		UNIQUE(ip_id, port),
		FOREIGN KEY(ip_id) REFERENCES ips(id)
	);

	CREATE TABLE IF NOT EXISTS urls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		port_id INTEGER,
		url TEXT NOT NULL UNIQUE,
		status_code INTEGER,
		title TEXT,
		tech TEXT,
		FOREIGN KEY(port_id) REFERENCES ports(id)
	);
	`
	_, err := db.Exec(schema)
	return err
} 