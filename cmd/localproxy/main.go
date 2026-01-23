package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/xetera/localproxy/cmd/localproxy/commands"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "localproxy",
		Short: "Local development reverse proxy",
	}

	rootCmd.AddCommand(
		commands.StartCmd(),
		commands.StopCmd(),
		commands.AddCmd(),
		commands.RemoveCmd(),
		commands.ListCmd(),
		commands.InitCmd(),
		commands.StatusCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
