package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/xetera/localproxy/internal/registry"
)

func RemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Unregister a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			store, err := registry.NewStore(DBPath())
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.RemoveProject(name); err != nil {
				return err
			}

			fmt.Printf("removed %s\n", name)
			return nil
		},
	}
}
