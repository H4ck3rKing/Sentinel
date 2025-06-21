package utils

import (
	"fmt"
	"log"
	"time"
)

// --- Colors and Formatting ---
const (
	ColorRed    = "\033[0;31m"
	ColorGreen  = "\033[0;32m"
	ColorYellow = "\033[1;33m"
	ColorBlue   = "\033[0;34m"
	ColorPurple = "\033[0;35m"
	ColorCyan   = "\033[0;36m"
	ColorWhite  = "\033[1;37m"
	ColorReset  = "\033[0m"
)

// --- Logging Functions ---

// getTimestamp creates a formatted timestamp string.
func getTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// Log prints a standard informational message.
func Log(message string) {
	fmt.Printf("%s[INFO][%s]%s %s\n", ColorGreen, getTimestamp(), ColorReset, message)
}

// Warn prints a warning message.
func Warn(message string) {
	fmt.Printf("%s[WARN][%s]%s %s\n", ColorYellow, getTimestamp(), ColorReset, message)
}

// Error prints an error message and logs it to a file.
func Error(message string, err error) {
	fullMessage := fmt.Sprintf("%s[ERROR][%s]%s %s: %v", ColorRed, getTimestamp(), ColorReset, message, err)
	fmt.Println(fullMessage)
	// Future: Add file logging here, e.g., to bugbounty-results/logs/sentinel.log
}

// Success prints a success message.
func Success(message string) {
	fmt.Printf("%s[SUCCESS][%s]%s %s\n", ColorCyan, getTimestamp(), ColorReset, message)
}

// Critical prints a critical error message and exits.
func Critical(message string, err error) {
	fullMessage := fmt.Sprintf("%s[CRITICAL][%s]%s %s: %v", ColorRed, getTimestamp(), ColorReset, message, err)
	log.Fatalf(fullMessage)
} 