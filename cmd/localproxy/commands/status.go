package commands

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

func StatusCmd() *cobra.Command {
	var envoyAdminPort int

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon and proxy status",
		RunE: func(cmd *cobra.Command, args []string) error {
			daemonStatus := "stopped"
			daemonPid := 0

			data, err := os.ReadFile(PidFile())
			if err == nil {
				pid, err := strconv.Atoi(string(data))
				if err == nil {
					proc, err := os.FindProcess(pid)
					if err == nil {
						if proc.Signal(syscall.Signal(0)) == nil {
							daemonStatus = "running"
							daemonPid = pid
						}
					}
				}
			}

			envoyStatus := "stopped"
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", envoyAdminPort))
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					envoyStatus = "running"
				}
			}

			fmt.Printf("daemon: %s", daemonStatus)
			if daemonPid > 0 {
				fmt.Printf(" (pid: %d)", daemonPid)
			}
			fmt.Println()

			fmt.Printf("envoy: %s\n", envoyStatus)

			return nil
		},
	}

	cmd.Flags().IntVar(&envoyAdminPort, "envoy-admin-port", 9901, "Envoy admin interface port")

	return cmd
}
