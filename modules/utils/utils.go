package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// RunCommand executes an external command and streams its output to stdout/stderr.
func RunCommand(commandName string, args ...string) error {
	Log(fmt.Sprintf("Running: %s %s", commandName, strings.Join(args, " ")))
	cmd := exec.Command(commandName, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		Error("Command finished with error", err)
	} else {
		Success(fmt.Sprintf("Successfully executed: %s", commandName))
	}
	return err
}

// RunCommandAndCapture executes a command and captures its standard output.
func RunCommandAndCapture(commandName string, args ...string) (string, error) {
	Log(fmt.Sprintf("Capturing output from: %s %s", commandName, strings.Join(args, " ")))
	cmd := exec.Command(commandName, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	// Stderr is ignored for now, but could be captured as well
	err := cmd.Run()
	if err != nil {
		Error("Command finished with error", err)
		return "", err
	}
	Success(fmt.Sprintf("Successfully captured output from: %s", commandName))
	return out.String(), nil
} 