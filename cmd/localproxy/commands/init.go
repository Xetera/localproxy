package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/xetera/localproxy/internal/config"
)

func InitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [name]",
		Short: "Create a .localproxy.yaml file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := os.Getwd()
			if err != nil {
				return err
			}

			if config.ConfigExists(dir) {
				return fmt.Errorf(".localproxy.yaml already exists")
			}

			name := filepath.Base(dir)
			if len(args) > 0 {
				name = args[0]
			}

			cfg := &config.ProjectConfig{
				Name: name,
				Env: map[string]string{
					"PORT": "{{.Port}}",
				},
			}

			if err := config.SaveConfig(dir, cfg); err != nil {
				return err
			}

			fmt.Printf("created .localproxy.yaml for %s\n", name)
			return nil
		},
	}
}
