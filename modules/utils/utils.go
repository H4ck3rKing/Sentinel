package utils

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
)

// Options holds common options for module execution.
type Options struct {
	Output  string
	Threads int
	Env     map[string]string
}

// CommandExists checks if a command exists in the system's PATH.
func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// Banner prints a styled banner for module sections.
func Banner(text string) {
	color.New(color.FgCyan, color.Bold).Printf("\n--- %s ---\n\n", text)
}

// RunCommand executes an external command and prints its output.
// It accepts a context to allow for cancellation.
func RunCommand(ctx context.Context, options Options, name string, args ...string) error {
	fmt.Println(color.GreenString("▶ Running: %s %s", name, strings.Join(args, " ")))
	cmd := exec.CommandContext(ctx, name, args...)
	if options.Env != nil {
		cmd.Env = os.Environ()
		for k, v := range options.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// The new modules often need to be run from the workspace directory
	// to handle relative paths for output correctly.
	cmd.Dir = options.Output
	return cmd.Run()
}

// RunCommandAndCapture executes a command and returns its output.
// It accepts a context to allow for cancellation.
func RunCommandAndCapture(ctx context.Context, options Options, name string, args ...string) (string, error) {
	fmt.Println(color.GreenString("▶ Capturing: %s %s", name, strings.Join(args, " ")))
	cmd := exec.CommandContext(ctx, name, args...)
	if options.Env != nil {
		cmd.Env = os.Environ()
		for k, v := range options.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Dir = options.Output

	var out bytes.Buffer
	// To provide verbose output, we'll pipe stderr to the user's terminal in real-time.
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		// Stderr was already printed, so we just return the error.
		return "", fmt.Errorf("command failed: %v", err)
	}
	return out.String(), nil
}
