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
func RunCommand(command string, options Options) error {
	fmt.Println(color.GreenString("▶ Running: %s", command))
	parts := strings.Fields(command)
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// The new modules often need to be run from the workspace directory
	// to handle relative paths for output correctly.
	cmd.Dir = options.Output
	return cmd.Run()
}

// RunCommandAndCapture executes a command and returns its output.
func RunCommandAndCapture(command string, options Options) (string, error) {
	fmt.Println(color.GreenString("▶ Capturing: %s", command))
	parts := strings.Fields(command)
	cmd := exec.Command(parts[0], parts[1:]...)
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