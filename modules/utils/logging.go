package utils

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
)

// --- Colors are now handled by the fatih/color library ---

// --- Logging Functions ---

// getTimestamp creates a formatted timestamp string.
func getTimestamp() string {
	return time.Now().Format("15:04:05")
}

// Log prints a standard informational message.
func Log(message string) {
	color.New(color.FgGreen).Printf("[INFO][%s] ", getTimestamp())
	fmt.Println(message)
}

// Warn prints a warning message.
func Warn(message string) {
	color.New(color.FgYellow).Printf("[WARN][%s] ", getTimestamp())
	fmt.Println(message)
}

// Error prints an error message and logs it to a file.
func Error(message string, err error) {
	color.New(color.FgRed).Printf("[ERROR][%s] ", getTimestamp())
	if err != nil {
		fmt.Printf("%s: %v\n", message, err)
	} else {
		fmt.Println(message)
	}
	// Future: Add file logging here
}

// Success prints a success message.
func Success(message string) {
	color.New(color.FgCyan).Printf("[SUCCESS][%s] ", getTimestamp())
	fmt.Println(message)
}

// Critical prints a critical error message and exits.
func Critical(message string, err error) {
	errorMsg := fmt.Sprintf("[%s] %s: %v", getTimestamp(), message, err)
	color.New(color.FgRed, color.Bold).Fprintln(os.Stderr, "[CRITICAL]"+errorMsg)
	log.Fatalf("") // fatih/color handles printing, exit cleanly.
} 