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
	"github.com/xetera/localproxy/internal/envoy"
	"github.com/xetera/localproxy/internal/hosts"
	"github.com/xetera/localproxy/internal/proxy"
	"github.com/xetera/localproxy/internal/registry"
	"github.com/xetera/localproxy/internal/xds"
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

	hostsMgr, err := hosts.NewManager()
	if err != nil {
		log.Printf("warning: hosts manager disabled: %v", err)
	}

	certMgr := certs.NewCertManager(dataDir)
	if err := certMgr.Init(); err != nil {
		log.Fatalf("failed to init certs: %v", err)
	}

	certPath, keyPath := certMgr.GetWildcardCert()

	xdsServer := xds.NewServer()
	if err := xdsServer.Start(":18000"); err != nil {
		log.Fatalf("failed to start xds server: %v", err)
	}
	log.Printf("xds server listening on :18000")

	envoyMgr := envoy.NewManager(dataDir, "127.0.0.1:18000", xdsServer.NodeID())
	if err := envoyMgr.Start(); err != nil {
		log.Fatalf("failed to start envoy: %v", err)
	}

	dashboardServer := proxy.NewDashboardServer()
	routeRegistry := registry.NewRouteRegistry()

	proxyRoute := xds.Route{
		Subdomain: "proxy",
		Host:      "127.0.0.1",
		Port:      8080,
		Protocol:  xds.ProtocolHTTP,
	}

	routeRegistry.SetOnChange(func(routes []proxy.Route) {
		dashboardServer.UpdateRoutes(routes)

		xdsRoutes := []xds.Route{proxyRoute}
		var subdomains []string
		subdomains = append(subdomains, "proxy")

		for _, r := range routes {
			if r.Disabled {
				continue
			}
			xdsRoute := xds.Route{
				Subdomain: r.Subdomain,
				Host:      r.Host,
				Port:      r.Port,
				TCPPort:   r.TCPPort,
				Protocol:  xds.ProtocolHTTP,
			}
			if r.TCPPort > 0 {
				xdsRoute.Protocol = xds.ProtocolTCP
			}
			xdsRoutes = append(xdsRoutes, xdsRoute)
			subdomains = append(subdomains, r.Subdomain)
		}

		if err := xdsServer.UpdateSnapshot(xdsRoutes, certPath, keyPath); err != nil {
			log.Printf("failed to update xds snapshot: %v", err)
		}

		if hostsMgr != nil {
			if err := hostsMgr.Update(subdomains); err != nil {
				log.Printf("failed to update hosts: %v", err)
			}
		}

		log.Printf("updated routes: %d active", len(routes))
	})

	if err := xdsServer.UpdateSnapshot([]xds.Route{proxyRoute}, certPath, keyPath); err != nil {
		log.Printf("failed to set initial xds snapshot: %v", err)
	}

	if hostsMgr != nil {
		if err := hostsMgr.Update([]string{"proxy"}); err != nil {
			log.Printf("failed to set initial hosts: %v", err)
		}
	}

	dockerWatcher, err := discovery.NewDockerWatcher()
	if err != nil {
		log.Printf("warning: docker watcher disabled: %v", err)
	} else {
		dockerWatcher.SetOnChange(func(containers []discovery.DockerContainer) {
			log.Printf("docker containers changed: %d", len(containers))
			routeRegistry.UpdateDockerContainers(containers)
		})
		if err := dockerWatcher.Start(); err != nil {
			log.Printf("warning: failed to start docker watcher: %v", err)
		}
	}

	basePath := os.Getenv("LOCALPROXY_BASE_PATH")
	if basePath == "" {
		basePath = defaultBasePath
	}

	processWatcher, err := discovery.NewProcessWatcher(basePath)
	if err != nil {
		log.Printf("warning: process watcher disabled: %v", err)
	} else {
		processWatcher.SetOnChange(func(processes []discovery.ListeningProcess) {
			log.Printf("processes changed: %d", len(processes))
			routeRegistry.UpdateProcesses(processes)
		})
		processWatcher.SetOnWellKnownChange(func(processes []discovery.WellKnownProcess) {
			log.Printf("well-known changed: %d", len(processes))
			for _, p := range processes {
				log.Printf("  well-known: %s -> :%d (pid %d)", p.Subdomain, p.Port, p.PID)
			}
			routeRegistry.UpdateWellKnownPorts(processes)
		})
		if err := processWatcher.Start(); err != nil {
			log.Printf("warning: failed to start process watcher: %v", err)
		}
	}

	if err := dashboardServer.Start(); err != nil {
		log.Fatalf("failed to start dashboard server: %v", err)
	}
	log.Printf("dashboard server listening on 127.0.0.1:8080")
	log.Printf("envoy proxy listening on :80 and :443")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigCh
	log.Printf("received signal: %v", sig)

	log.Println("shutting down...")

	if dockerWatcher != nil {
		dockerWatcher.Stop()
	}
	if processWatcher != nil {
		processWatcher.Stop()
	}
	envoyMgr.Stop()
	dashboardServer.Stop()
	xdsServer.Stop()

	if hostsMgr != nil {
		if err := hostsMgr.Cleanup(); err != nil {
			log.Printf("failed to cleanup hosts: %v", err)
		}
	}

	log.Println("daemon stopped")
}

func dataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".localproxy")
}
