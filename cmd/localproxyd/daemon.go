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
	"time"

	"github.com/xetera/localproxy/internal/certs"
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/envoy"
	"github.com/xetera/localproxy/internal/hosts"
	"github.com/xetera/localproxy/internal/notification"
	"github.com/xetera/localproxy/internal/proxy"
	"github.com/xetera/localproxy/internal/registry"
	"github.com/xetera/localproxy/internal/xds"
)

type Config struct {
	WatchPaths       []string
	LogLevel         string
	HTTPSRedirect    bool
	TraceProcessLogs bool
	EnvoyAdminPort   int
}

type Daemon struct {
	config  Config
	dataDir string

	hostsMgr        *hosts.Manager
	certMgr         *certs.CertManager
	xdsServer       *xds.Server
	envoyMgr        *envoy.Manager
	statsScraper    *envoy.StatsScraper
	routeRegistry   *registry.RouteRegistry
	dashboardServer *proxy.DashboardServer
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

	if err := d.initCerts(); err != nil {
		return err
	}

	if err := d.initXDS(); err != nil {
		return err
	}

	if err := d.initEnvoy(); err != nil {
		return err
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

	log.Printf("dashboard server listening on 127.0.0.1:%d", proxy.ServerPort)
	log.Printf("envoy proxy listening on :80 and :443")

	return nil
}

func (d *Daemon) Stop() {
	if d.statsScraper != nil {
		d.statsScraper.Stop()
	}
	if d.envoyMgr != nil {
		d.envoyMgr.Stop()
	}
	if d.logFile != nil {
		d.logFile.Close()
	}
	err := d.hostsMgr.Cleanup()
	if err != nil {
		log.Printf("warning: hosts manager cleanup failed: %v", err)
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

func (d *Daemon) initCerts() error {
	d.certMgr = certs.NewCertManager(d.dataDir)
	return d.certMgr.Init()
}

func (d *Daemon) initXDS() error {
	d.xdsServer = xds.NewServer()
	d.xdsServer.SetHTTPSRedirect(d.config.HTTPSRedirect)
	if err := d.xdsServer.Start(":18000"); err != nil {
		return err
	}
	log.Printf("xds server listening on :18000")
	return nil
}

func (d *Daemon) initEnvoy() error {
	d.envoyMgr = envoy.NewManager(d.dataDir, "127.0.0.1:18000", d.xdsServer.NodeID(), d.config.LogLevel, d.config.EnvoyAdminPort)
	if err := d.envoyMgr.Start(); err != nil {
		return err
	}
	d.statsScraper = envoy.NewStatsScraper(fmt.Sprintf("http://127.0.0.1:%d", d.config.EnvoyAdminPort), 10*time.Second)
	d.statsScraper.Start()
	return nil
}

func (d *Daemon) initRouting() error {
	basePaths := d.getBasePaths()
	d.dashboardServer = proxy.NewDashboardServer(basePaths, d.config.TraceProcessLogs, d.statsScraper)
	d.routeRegistry = registry.NewRouteRegistry(d.onRoutesChanged)

	certPath, keyPath, _ := d.certMgr.GetCert("localhost")
	initialRoute := xds.Route{
		Subdomain: "",
		Host:      "127.0.0.1",
		Port:      proxy.ServerPort,
		Protocol:  xds.ProtocolHTTP,
		CertPath:  certPath,
		KeyPath:   keyPath,
	}
	if err := d.xdsServer.UpdateSnapshot([]xds.Route{initialRoute}); err != nil {
		return fmt.Errorf("failed to set initial xds snapshot: %v", err)
	}

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

func (d *Daemon) onRoutesChanged(routes []proxy.Route) {
	d.dashboardServer.UpdateRoutes(routes)

	certPath, keyPath, _ := d.certMgr.GetCert("localhost")
	xdsRoutes := []xds.Route{{
		Subdomain: "",
		Host:      "127.0.0.1",
		Port:      proxy.ServerPort,
		Protocol:  xds.ProtocolHTTP,
		CertPath:  certPath,
		KeyPath:   keyPath,
	}}
	var subdomains []string

	for _, r := range routes {
		if r.Disabled {
			continue
		}

		certKey := r.Subdomain
		if certKey == "" {
			certKey = "localhost"
		}
		if err := d.certMgr.EnsureCert(certKey); err != nil {
			log.Printf("failed to generate cert for %s: %v", certKey, err)
			continue
		}
		certPath, keyPath, _ := d.certMgr.GetCert(certKey)

		xdsRoute := xds.Route{
			Subdomain: r.Subdomain,
			Host:      r.Endpoint.Addr().String(),
			Port:      int(r.Endpoint.Port()),
			TCPPort:   r.TCPPort,
			Protocol:  xds.ProtocolHTTP,
			CertPath:  certPath,
			KeyPath:   keyPath,
		}
		if r.TCPPort > 0 {
			xdsRoute.Protocol = xds.ProtocolTCP
		}
		xdsRoutes = append(xdsRoutes, xdsRoute)
		subdomains = append(subdomains, r.Subdomain)
	}

	if err := d.xdsServer.UpdateSnapshot(xdsRoutes); err != nil {
		log.Printf("failed to update xds snapshot: %v", err)
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
	unrouted := make([]proxy.UnroutedContainer, len(containers))
	for i, c := range containers {
		unrouted[i] = proxy.UnroutedContainer{
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
