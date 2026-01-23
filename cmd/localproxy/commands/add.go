package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/xetera/localproxy/internal/config"
	"github.com/xetera/localproxy/internal/registry"
)

func AddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add [dir]",
		Short: "Register a project directory",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			absDir, err := filepath.Abs(dir)
			if err != nil {
				return err
			}

			cfg, err := config.LoadConfig(absDir)
			if err != nil {
				return fmt.Errorf("no .localproxy.yaml found in %s", absDir)
			}

			store, err := registry.NewStore(DBPath())
			if err != nil {
				return err
			}
			defer store.Close()

			existing, _ := store.GetProject(cfg.Name)
			if existing != nil {
				fmt.Printf("project %s already registered at port %d\n", cfg.Name, existing.Port)
				return nil
			}

			port := cfg.Port
			if port == 0 {
				port, err = store.AllocatePort()
				if err != nil {
					return err
				}
			}

			project := &registry.Project{
				Name:      cfg.Name,
				Subdomain: cfg.Subdomain,
				Port:      port,
				Path:      absDir,
				Source:    "filesystem",
			}

			if err := store.AddProject(project); err != nil {
				return err
			}

			fmt.Printf("registered %s at https://%s.localhost (port %d)\n", cfg.Name, cfg.Subdomain, port)

			if _, err := os.Stat(SocketPath()); err == nil {
				fmt.Println("restart daemon to apply changes: localproxy stop && localproxy start")
			}

			return nil
		},
	}
}
