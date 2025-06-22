package utils

import (
	"bytes"
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
// It is a simplified version for better UI control.
func RunCommand(options Options, name string, args ...string) error {
	fmt.Println(color.GreenString("▶ Running: %s %s", name, strings.Join(args, " ")))
	cmd := exec.Command(name, args...)
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
func RunCommandAndCapture(options Options, name string, args ...string) (string, error) {
	fmt.Println(color.GreenString("▶ Capturing: %s %s", name, strings.Join(args, " ")))
	cmd := exec.Command(name, args...)
	if options.Env != nil {
		cmd.Env = os.Environ()
		for k, v := range options.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Dir = options.Output

	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Return the error along with stderr for better debugging
		return "", fmt.Errorf("command failed: %v\nstderr: %s", err, stderr.String())
	}
	return out.String(), nil
}

// RunCommandAndCaptureWithInput is not used by the new modules, so it can be removed
// for now to simplify the utils package. If needed later, it can be re-added. 