package commands

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

func StopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the localproxy daemon and Envoy",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(PidFile())
			if err != nil {
				fmt.Println("daemon is not running")
				return nil
			}

			pid, err := strconv.Atoi(string(data))
			if err != nil {
				return fmt.Errorf("invalid pid file: %w", err)
			}

			proc, err := os.FindProcess(pid)
			if err != nil {
				os.Remove(PidFile())
				fmt.Println("daemon is not running")
				return nil
			}

			if err := proc.Signal(syscall.SIGTERM); err != nil {
				os.Remove(PidFile())
				fmt.Println("daemon is not running")
				return nil
			}

			os.Remove(PidFile())
			fmt.Println("daemon stopped")
			return nil
		},
	}
}
