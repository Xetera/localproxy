package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

func StartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the localproxy daemon and Caddy",
		RunE: func(cmd *cobra.Command, args []string) error {
			if isRunning() {
				fmt.Println("daemon is already running")
				return nil
			}

			if err := os.MkdirAll(DataDir(), 0755); err != nil {
				return err
			}

			daemonPath, err := findDaemon()
			if err != nil {
				return err
			}

			proc := exec.Command(daemonPath)
			proc.SysProcAttr = &syscall.SysProcAttr{
				Setpgid: true,
			}
			proc.Stdout = nil
			proc.Stderr = nil

			if err := proc.Start(); err != nil {
				return fmt.Errorf("failed to start daemon: %w", err)
			}

			if err := os.WriteFile(PidFile(), []byte(strconv.Itoa(proc.Process.Pid)), 0644); err != nil {
				return err
			}

			fmt.Printf("daemon started (pid: %d)\n", proc.Process.Pid)
			return nil
		},
	}
}

func isRunning() bool {
	data, err := os.ReadFile(PidFile())
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return false
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

func findDaemon() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	dir := filepath.Dir(exe)
	daemonPath := filepath.Join(dir, "localproxyd")

	if _, err := os.Stat(daemonPath); err == nil {
		return daemonPath, nil
	}

	path, err := exec.LookPath("localproxyd")
	if err == nil {
		return path, nil
	}

	return "", fmt.Errorf("localproxyd not found")
}
