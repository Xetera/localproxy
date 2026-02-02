package main

import (
	"fmt"
	"log"

	"github.com/spf13/pflag"
)

const defaultBasePath = "/Users/xetera"

var watchPaths []string
var logLevel string
var httpsRedirect bool
var traceProcessLogs bool
var envoyAdminPort int

func init() {
	pflag.StringArrayVar(&watchPaths, "watch", []string{}, "Folders to watch for processes (can be specified multiple times)")
	pflag.StringVar(&logLevel, "log-level", "info", "Envoy log level (trace, debug, info, warning, error, critical, off)")
	pflag.BoolVar(&httpsRedirect, "https-redirect", false, "Redirect HTTP requests to HTTPS")
	pflag.BoolVar(&traceProcessLogs, "trace-process-logs", false, "Trace logs from spawned process stdout/stderr. Requires SIP to be disabled on macos (Will probably cause your system to freeze if you're below Tahoe)")
	pflag.IntVar(&envoyAdminPort, "envoy-admin-port", 9901, "Envoy admin interface port")
	pflag.Parse()
}

func main() {
	fmt.Println("Starting localproxy daemon...")

	cfg := Config{
		WatchPaths:       watchPaths,
		LogLevel:         logLevel,
		HTTPSRedirect:    httpsRedirect,
		TraceProcessLogs: traceProcessLogs,
		EnvoyAdminPort:   envoyAdminPort,
	}

	daemon, err := NewDaemon(cfg)
	if err != nil {
		log.Fatalf("failed to create daemon: %v", err)
	}

	if err := daemon.Start(); err != nil {
		log.Fatalf("failed to start daemon: %v", err)
	}

	daemon.Wait()
	daemon.Stop()
}
