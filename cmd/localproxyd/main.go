package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/xetera/localproxy/internal/certs"
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/proxy"
	"github.com/xetera/localproxy/internal/registry"
)

const defaultBasePath = "/Users/xetera"

func main() {
	fmt.Println("starting daemon...")
	dataDir := dataDir()
	fmt.Println("data dir:", dataDir)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}

	logFile, err := os.OpenFile(filepath.Join(dataDir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	fmt.Println("logfile", logFile)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	certMgr := certs.NewCertManager(dataDir)
	if err := certMgr.Init(); err != nil {
		log.Printf("warning: failed to init certs: %v", err)
		certMgr = nil
	}

	proxyServer := proxy.NewServer(certMgr)
	routeRegistry := registry.NewRouteRegistry()
	log.Print("Hello world")

	routeRegistry.SetOnChange(func(routes []proxy.Route) {
		proxyServer.UpdateRoutes(routes)
		log.Printf("updated routes: %d active", len(routes))
	})

	// dockerWatcher, err := discovery.NewDockerWatcher()
	// log.Print(dockerWatcher)
	// if err != nil {
	// 	log.Printf("warning: docker watcher disabled: %v", err)
	// } else {
	// 	dockerWatcher.SetOnChange(func(containers []discovery.DockerContainer) {
	// 		routeRegistry.UpdateDockerContainers(containers)
	// 	})
	// 	if err := dockerWatcher.Start(); err != nil {
	// 		log.Printf("warning: failed to start docker watcher: %v", err)
	// 	}
	// }

	basePath := os.Getenv("LOCALPROXY_BASE_PATH")
	if basePath == "" {
		basePath = defaultBasePath
	}

	processWatcher, err := discovery.NewProcessWatcher(basePath)
	if err != nil {
		log.Printf("warning: process watcher disabled: %v", err)
	} else {
		processWatcher.SetOnChange(func(processes []discovery.ListeningProcess) {
			routeRegistry.UpdateProcesses(processes)
		})
		if err := processWatcher.Start(); err != nil {
			log.Printf("warning: failed to start process watcher: %v", err)
		}
	}

	if err := proxyServer.Start(); err != nil {
		log.Fatalf("failed to start proxy server: %v", err)
	}
	log.Printf("proxy server listening on :80 and :443")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigCh
	log.Printf("received signal: %v", sig)

	log.Println("shutting down...")

	// if dockerWatcher != nil {
	// 	dockerWatcher.Stop()
	// }
	if processWatcher != nil {
		processWatcher.Stop()
	}
	proxyServer.Stop()

	log.Println("daemon stopped")
}

func dataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".localproxy")
}
