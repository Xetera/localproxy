package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var defaultBasePath = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "projects")
}()

type watchPaths []string

func (w *watchPaths) String() string {
	return strings.Join(*w, ", ")
}

func (w *watchPaths) Set(value string) error {
	*w = append(*w, value)
	return nil
}

func main() {
	var paths watchPaths
	var logLevel string
	var traceProcessLogs bool
	var httpsRedirect bool

	flag.Var(&paths, "watch", "paths to watch for processes (can be specified multiple times)")
	flag.StringVar(&logLevel, "log-level", "info", "log level")
	flag.BoolVar(&traceProcessLogs, "trace-process-logs", false, "enable dtrace-based process log tracing")
	flag.BoolVar(&httpsRedirect, "https-redirect", false, "redirect HTTP requests to HTTPS")
	flag.Parse()

	if len(paths) == 0 {
		paths = []string{defaultBasePath}
	}

	log.Println("Starting localproxy daemon with embedded Caddy...")

	cfg := CaddyConfig{
		WatchPaths:       paths,
		LogLevel:         logLevel,
		TraceProcessLogs: traceProcessLogs,
		HTTPSRedirect:    httpsRedirect,
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
