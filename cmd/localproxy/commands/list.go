package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/xetera/localproxy/internal/registry"
)

func ListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show all registered projects",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := registry.NewStore(DBPath())
			if err != nil {
				return err
			}
			defer store.Close()

			projects, err := store.ListProjects()
			if err != nil {
				return err
			}

			if len(projects) == 0 {
				fmt.Println("no projects registered")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSUBDOMAIN\tPORT\tSOURCE\tPATH")
			for _, p := range projects {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", p.Name, p.Subdomain, p.Port, p.Source, p.Path)
			}
			w.Flush()

			return nil
		},
	}
}
