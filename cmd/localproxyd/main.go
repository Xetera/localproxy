package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/pflag"
	"github.com/xetera/localproxy/internal/certs"
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/envoy"
	"github.com/xetera/localproxy/internal/hosts"
	"github.com/xetera/localproxy/internal/notification"
	"github.com/xetera/localproxy/internal/proxy"
	"github.com/xetera/localproxy/internal/registry"
	"github.com/xetera/localproxy/internal/xds"
)

const defaultBasePath = "/Users/xetera"

var watchPaths []string
var logLevel string
var httpsRedirect bool
var traceProcessLogs bool

func init() {
	pflag.StringArrayVar(&watchPaths, "watch", []string{}, "Folders to watch for processes (can be specified multiple times)")
	pflag.StringVar(&logLevel, "log-level", "info", "Envoy log level (trace, debug, info, warning, error, critical, off)")
	pflag.BoolVar(&httpsRedirect, "https-redirect", false, "Redirect HTTP requests to HTTPS")
	pflag.BoolVar(&traceProcessLogs, "trace-process-logs", false, "Trace logs from spawned process stdout/stderr. Requires SIP to be disabled on macos (Will probably cause your system to freeze if you're below Tahoe)")
	pflag.Parse()
}

func main() {
	fmt.Println("Starting localproxy daemon...")
	dataDir := dataDir()
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}

	logFile, err := os.OpenFile(filepath.Join(dataDir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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
	xdsServer.SetHTTPSRedirect(httpsRedirect)
	if err := xdsServer.Start(":18000"); err != nil {
		log.Fatalf("failed to start xds server: %v", err)
	}
	log.Printf("xds server listening on :18000")

	envoyMgr := envoy.NewManager(dataDir, "127.0.0.1:18000", xdsServer.NodeID(), logLevel)
	if err := envoyMgr.Start(); err != nil {
		log.Fatalf("failed to start envoy: %v", err)
	}

	dashboardServer := proxy.NewDashboardServer(nil, traceProcessLogs)
	routeRegistry := registry.NewRouteRegistry()

	routeRegistry.SetOnChange(func(routes []proxy.Route) {
		dashboardServer.UpdateRoutes(routes)

		xdsRoutes := []xds.Route{}
		var subdomains []string

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

	if err := xdsServer.UpdateSnapshot([]xds.Route{}, certPath, keyPath); err != nil {
		log.Printf("failed to set initial xds snapshot: %v", err)
	}

	if hostsMgr != nil {
		if err := hostsMgr.Update([]string{"proxy"}); err != nil {
			log.Printf("failed to set initial hosts: %v", err)
		}
	}

	basePaths := watchPaths
	if len(basePaths) == 0 {
		if envPath := os.Getenv("LOCALPROXY_BASE_PATH"); envPath != "" {
			basePaths = strings.Split(envPath, ":")
		} else {
			basePaths = []string{defaultBasePath}
		}
	}

	homeDir, _ := os.UserHomeDir()
	dashboardServer.SetBasePaths(append(basePaths, homeDir))

	notifier := notification.NewNotifier()
	seenBackends := make(map[string]bool)
	watcherStarted := false

	processWatcher, err := discovery.NewProcessWatcher(basePaths)
	if err != nil {
		log.Printf("warning: process watcher disabled: %v", err)
	} else {
		processWatcher.SetOnChange(func(services []discovery.DiscoveredService) {
			log.Printf("processes changed: %d", len(services))
			routeRegistry.UpdateServices(discovery.RouteSourceProcess, filterBySource(services, discovery.RouteSourceProcess))
			routeRegistry.UpdateServices(discovery.RouteSourceWellKnown, filterBySource(services, discovery.RouteSourceWellKnown))

			for _, s := range services {
				if !seenBackends[s.Subdomain] {
					if watcherStarted && (s.Process == nil || !s.Process.Disabled) {
						cwd := ""
						if s.Process != nil {
							cwd = s.Process.Cwd
						}
						log.Printf("sending notification for backend: %s", s.Subdomain)
						if err := notifier.NotifyBackend(s.Subdomain, notification.IsDockerBackend(s.Subdomain, cwd)); err != nil {
							log.Printf("failed to send notification: %v", err)
						}
					}
					seenBackends[s.Subdomain] = true
				}
			}
		})
		if err := processWatcher.Start(); err != nil {
			log.Printf("warning: failed to start process watcher: %v", err)
		} else {
			watcherStarted = true
		}
	}

	dockerWatcher, err := discovery.NewDockerWatcher()
	if err != nil {
		log.Printf("warning: docker watcher disabled: %v", err)
	} else {
		dockerWatcher.SetOnChange(func(services []discovery.DiscoveredService) {
			log.Printf("docker containers changed: %d", len(services))
			routeRegistry.UpdateServices(discovery.RouteSourceDocker, services)

			for _, svc := range services {
				dockerWatcher.DiscoverServiceInfo(svc, func(updated discovery.DiscoveredService) {
					routeRegistry.UpdateServices(discovery.RouteSourceDocker, []discovery.DiscoveredService{updated})
				})
			}

			if processWatcher != nil {
				ports := make([]int, 0, len(services))
				for _, s := range services {
					ports = append(ports, s.Port)
				}
				processWatcher.SetDockerPorts(ports)
			}
		})
		dockerWatcher.SetOnHealthy(func(svc discovery.DiscoveredService) {
			log.Printf("docker: container healthy %s", svc.Subdomain)
			dockerWatcher.DiscoverServiceInfo(svc, func(updated discovery.DiscoveredService) {
				routeRegistry.UpdateServices(discovery.RouteSourceDocker, []discovery.DiscoveredService{updated})
			})
		})
		if err := dockerWatcher.Start(); err != nil {
			log.Printf("warning: failed to start docker watcher: %v", err)
		}
	}

	if err := dashboardServer.Start(); err != nil {
		log.Fatalf("failed to start dashboard server: %v", err)
	}
	log.Printf("dashboard server listening on 127.0.0.1:%d", proxy.ServerPort)
	log.Printf("envoy proxy listening on :80 and :443")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	<-sigCh
	log.Println("daemon stopped")
}

func filterBySource(services []discovery.DiscoveredService, source discovery.RouteSource) []discovery.DiscoveredService {
	var result []discovery.DiscoveredService
	for _, s := range services {
		if s.Source == source {
			result = append(result, s)
		}
	}
	return result
}

func dataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".localproxy")
}
