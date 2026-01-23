package main

import (
	"fmt"
	"os"

	"github.com/xetera/localproxy/internal/discovery"
)

func main() {
	basePath := "/Users/xetera"
	if len(os.Args) > 1 {
		basePath = os.Args[1]
	}

	watcher, err := discovery.NewProcessWatcher(basePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	watcher.SetOnChange(func(processes []discovery.ListeningProcess) {
		fmt.Printf("\n=== Found %d processes ===\n", len(processes))
		for _, p := range processes {
			fmt.Printf("PID: %d | Port: %d | Subdomain: %s | Cwd: %s\n", p.PID, p.Port, p.Subdomain, p.Cwd)
		}
	})

	fmt.Printf("Watching for processes under: %s\n", basePath)
	fmt.Println("Press Ctrl+C to exit")

	if err := watcher.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "error starting watcher: %v\n", err)
		os.Exit(1)
	}

	select {}
}
