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

	"github.com/xetera/localproxy/internal/dashboard"
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/hosts"
	"github.com/xetera/localproxy/internal/notification"
	"github.com/xetera/localproxy/internal/proxy"
	"github.com/xetera/localproxy/internal/registry"
)

type Config struct {
	WatchPaths       []string
	LogLevel         string
	HTTPSRedirect    bool
	TraceProcessLogs bool
}

type Daemon struct {
	config  Config
	dataDir string

	hostsMgr        *hosts.Manager
	routeRegistry   *registry.RouteRegistry
	store           *registry.Store
	dashboardServer *dashboard.DashboardServer
	processWatcher  *discovery.ProcessWatcher
	dockerWatcher   *discovery.DockerWatcher
	notifier        *notification.Notifier

	seenBackends   map[string]bool
	watcherStarted bool
	logFile        *os.File
	sigCh          chan os.Signal
}

func NewDaemon(cfg Config) (*Daemon, error) {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".localproxy")

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}

	logFile, err := os.OpenFile(filepath.Join(dataDir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	return &Daemon{
		config:       cfg,
		dataDir:      dataDir,
		seenBackends: make(map[string]bool),
		logFile:      logFile,
		sigCh:        make(chan os.Signal, 1),
	}, nil
}

func (d *Daemon) Start() error {
	if err := d.initHosts(); err != nil {
		return fmt.Errorf("warning: hosts manager disabled: %v", err)
	}

	if err := d.initRouting(); err != nil {
		return err
	}

	if err := d.initWatchers(); err != nil {
		return err
	}

	if err := d.dashboardServer.Start(); err != nil {
		return err
	}

	log.Printf("dashboard server listening on 127.0.0.1:%d", dashboard.ServerPort)

	return nil
}

func (d *Daemon) Stop() {
	if d.store != nil {
		d.store.Close()
	}
	if d.logFile != nil {
		d.logFile.Close()
	}
	if d.hostsMgr != nil {
		err := d.hostsMgr.Cleanup()
		if err != nil {
			log.Printf("warning: hosts manager cleanup failed: %v", err)
		}
	}
	log.Println("daemon stopped")
}

func (d *Daemon) Wait() {
	signal.Notify(d.sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-d.sigCh
}

func (d *Daemon) initHosts() error {
	hostsMgr, err := hosts.NewManager()
	if err != nil {
		return err
	}
	d.hostsMgr = hostsMgr
	return nil
}

func (d *Daemon) initRouting() error {
	storePath := filepath.Join(d.dataDir, "store.db")
	store, err := registry.NewStore(storePath)
	if err != nil {
		return fmt.Errorf("failed to open store: %v", err)
	}
	d.store = store

	basePaths := d.getBasePaths()
	d.dashboardServer = dashboard.NewDashboardServer(basePaths, d.config.TraceProcessLogs)
	d.routeRegistry = registry.NewRouteRegistry(d.onRoutesChanged, d.store)

	d.dashboardServer.SetRegistry(d.routeRegistry)
	d.dashboardServer.SetStore(d.store)

	d.store.SetOnChange(func() {
		d.routeRegistry.RefreshRoutes()
	})

	if d.hostsMgr != nil {
		if err := d.hostsMgr.Update([]string{""}); err != nil {
			return fmt.Errorf("failed to set initial hosts: %v", err)
		}
	}
	return nil
}

func (d *Daemon) initWatchers() error {
	d.notifier = notification.NewNotifier()
	basePaths := d.getBasePaths()

	processWatcher, err := discovery.NewProcessWatcher(basePaths)
	if err != nil {
		log.Printf("warning: process watcher disabled: %v", err)
	} else {
		d.processWatcher = processWatcher
		d.processWatcher.SetOnChange(d.onProcessesChanged)
		if err := d.processWatcher.Start(); err != nil {
			log.Printf("warning: failed to start process watcher: %v", err)
		} else {
			d.watcherStarted = true
		}
	}

	dockerWatcher, err := discovery.NewDockerWatcher()
	if err != nil {
		log.Printf("warning: docker watcher disabled: %v", err)
	} else {
		d.dockerWatcher = dockerWatcher
		d.dockerWatcher.SetOnChange(d.onDockerChanged)
		d.dockerWatcher.SetOnHealthy(d.onDockerHealthy)
		d.dockerWatcher.SetOnUnroutedChanged(d.onUnroutedContainersChanged)
		if err := d.dockerWatcher.Start(); err != nil {
			log.Printf("warning: failed to start docker watcher: %v", err)
		}
	}

	return nil
}

func (d *Daemon) getBasePaths() []string {
	if len(d.config.WatchPaths) > 0 {
		return d.config.WatchPaths
	}
	if envPath := os.Getenv("LOCALPROXY_BASE_PATH"); envPath != "" {
		return strings.Split(envPath, ":")
	}
	return []string{defaultBasePath}
}

func (d *Daemon) onRoutesChanged(routes []proxy.Route, backends []dashboard.Backend) {
	d.dashboardServer.UpdateBackends(backends)

	var subdomains []string
	for i, r := range routes {
		if backends[i].Disabled {
			continue
		}
		subdomains = append(subdomains, r.Subdomain)
	}

	if d.hostsMgr != nil {
		if err := d.hostsMgr.Update(subdomains); err != nil {
			log.Printf("failed to update hosts: %v", err)
		}
	}

	log.Printf("updated routes: %d active", len(routes))
}

func (d *Daemon) onProcessesChanged(services []discovery.DiscoveredService) {
	log.Printf("processes changed: %d", len(services))
	d.routeRegistry.UpdateServices(discovery.RouteSourceProcess, filterBySource(services, discovery.RouteSourceProcess))
	d.routeRegistry.UpdateServices(discovery.RouteSourceWellKnown, filterBySource(services, discovery.RouteSourceWellKnown))

	for _, s := range services {
		if !d.seenBackends[s.Subdomain] {
			if d.watcherStarted && (s.Process == nil || !s.Process.Disabled) {
				cwd := ""
				if s.Process != nil {
					cwd = s.Process.Cwd
				}
				log.Printf("sending notification for backend: %s", s.Subdomain)
				if err := d.notifier.NotifyBackend(s.Subdomain, notification.IsDockerBackend(s.Subdomain, cwd)); err != nil {
					log.Printf("failed to send notification: %v", err)
				}
			}
			d.seenBackends[s.Subdomain] = true
		}
	}
}

func (d *Daemon) onDockerChanged(services []discovery.DiscoveredService) {
	log.Printf("docker containers changed: %d", len(services))
	d.routeRegistry.UpdateServices(discovery.RouteSourceDocker, services)

	for _, svc := range services {
		d.dockerWatcher.DiscoverServiceInfo(svc, func(updated discovery.DiscoveredService) {
			d.routeRegistry.UpdateService(updated)
		})
	}

	if d.processWatcher != nil {
		ports := make([]uint16, 0, len(services))
		for _, s := range services {
			ports = append(ports, s.Endpoint.Port())
		}
		d.processWatcher.SetDockerPorts(ports)
	}
}

func (d *Daemon) onDockerHealthy(svc discovery.DiscoveredService) {
	log.Printf("docker: container healthy %s", svc.Subdomain)
	d.dockerWatcher.DiscoverServiceInfo(svc, func(updated discovery.DiscoveredService) {
		d.routeRegistry.UpdateService(updated)
	})
}

func (d *Daemon) onUnroutedContainersChanged(containers []discovery.UnroutedContainer) {
	log.Printf("unrouted docker containers: %d", len(containers))
	unrouted := make([]dashboard.UnroutedContainer, len(containers))
	for i, c := range containers {
		unrouted[i] = dashboard.UnroutedContainer{
			ID:     c.ID,
			Name:   c.Name,
			Reason: c.Reason,
		}
	}
	d.dashboardServer.UpdateUnroutedContainers(unrouted)
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
