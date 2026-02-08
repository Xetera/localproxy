package main

import (
	"fmt"
	"log"
)

const defaultBasePath = "/Users/xetera"

func main() {
	fmt.Println("Starting localproxy daemon with embedded Caddy...")

	cfg := CaddyConfig{
		WatchPaths:       []string{defaultBasePath},
		LogLevel:         "info",
		TraceProcessLogs: false,
	}

	daemon, err := NewCaddyDaemon(cfg)
	if err != nil {
		log.Fatalf("failed to create daemon: %v", err)
	}

	if err := daemon.Start(); err != nil {
		log.Fatalf("failed to start daemon: %v", err)
	}

	daemon.Wait()
	daemon.Stop()
}
