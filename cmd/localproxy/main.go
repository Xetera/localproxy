package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/xetera/localproxy/cmd/localproxy/commands"
)

var watchPaths []string

func main() {
	rootCmd := &cobra.Command{
		Use:   "localproxy",
		Short: "Local development reverse proxy",
	}

	rootCmd.PersistentFlags().StringArrayVar(&watchPaths, "watch", []string{}, "Paths to watch for changes (can be specified multiple times)")

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
