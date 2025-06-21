package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// RunCommand executes an external command and streams its output to stdout.
// This provides real-time feedback on the tool's progress.
func RunCommand(commandName string, args ...string) error {
	// Print the command being executed for better user feedback
	Log(fmt.Sprintf("Running command: %s %s", commandName, strings.Join(args, " ")))

	cmd := exec.Command(commandName, args...)

	// Get the command's stdout and stderr pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating stdout pipe for %s: %w", commandName, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for %s: %w", commandName, err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		Error("Error starting command", err)
		return fmt.Errorf("error starting command %s: %w", commandName, err)
	}

	// Create scanners to read the output line by line
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)

	// Concurrently read from stdout and stderr
	go func() {
		for stdoutScanner.Scan() {
			fmt.Println(stdoutScanner.Text())
		}
	}()

	go func() {
		for stderrScanner.Scan() {
			fmt.Fprintln(os.Stderr, stderrScanner.Text())
		}
	}()

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		Error("Command finished with error", err)
		return fmt.Errorf("command %s finished with error: %w", commandName, err)
	}

	Success(fmt.Sprintf("Successfully executed: %s", commandName))
	return nil
} 