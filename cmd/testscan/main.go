package main

import (
	"fmt"

	"github.com/xetera/localproxy/internal/discovery"
)

func main() {
	w, err := discovery.NewProcessWatcher("/Users/xetera")
	if err != nil {
		fmt.Printf("error creating watcher: %v\n", err)
		return
	}

	w.SetOnChange(func(processes []discovery.ListeningProcess) {
		fmt.Printf("Processes: %d\n", len(processes))
		for _, p := range processes {
			fmt.Printf("  process: %s -> :%d (pid %d, cwd %s, disabled %v)\n",
				p.Subdomain, p.Port, p.PID, p.Cwd, p.Disabled)
		}
	})

	w.SetOnWellKnownChange(func(processes []discovery.WellKnownProcess) {
		fmt.Printf("Well-known: %d\n", len(processes))
		for _, p := range processes {
			fmt.Printf("  wellknown: %s -> :%d (pid %d)\n", p.Subdomain, p.Port, p.PID)
		}
	})

	if err := w.Start(); err != nil {
		fmt.Printf("error starting: %v\n", err)
		return
	}

	w.Stop()
}
