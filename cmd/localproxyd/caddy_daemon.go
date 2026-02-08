package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/xetera/localproxy/internal/certs"
	"github.com/xetera/localproxy/internal/dashboard"
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/hosts"
	"github.com/xetera/localproxy/internal/notification"
	"github.com/xetera/localproxy/internal/proxy"
	"github.com/xetera/localproxy/internal/registry"
)

var adminSocket = filepath.Join(os.TempDir(), fmt.Sprintf("caddy-admin-%d.sock", os.Getuid()))

type CaddyConfig struct {
	WatchPaths       []string
	LogLevel         string
	TraceProcessLogs bool
	HTTPSRedirect    bool
}

type CaddyDaemon struct {
	config  CaddyConfig
	dataDir string

	hostsMgr        *hosts.Manager
	certMgr         *certs.CertManager
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

func NewCaddyDaemon(cfg CaddyConfig) (*CaddyDaemon, error) {
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

	return &CaddyDaemon{
		config:       cfg,
		dataDir:      dataDir,
		seenBackends: make(map[string]bool),
		logFile:      logFile,
		sigCh:        make(chan os.Signal, 1),
	}, nil
}

func (d *CaddyDaemon) Start() error {
	if err := d.initHosts(); err != nil {
		log.Printf("warning: hosts manager disabled: %v", err)
	}

	if err := d.initCerts(); err != nil {
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

	log.Printf("dashboard server listening on 127.0.0.1:%d", dashboard.ServerPort)

	if err := d.startCaddy(); err != nil {
		return err
	}

	log.Printf("caddy proxy listening on :80 and :443")

	return nil
}

func (d *CaddyDaemon) Stop() {
	caddy.Stop()
	if d.store != nil {
		d.store.Close()
	}
	if d.logFile != nil {
		d.logFile.Close()
	}
	if d.hostsMgr != nil {
		if err := d.hostsMgr.Cleanup(); err != nil {
			log.Printf("warning: hosts manager cleanup failed: %v", err)
		}
	}
	log.Println("daemon stopped")
}

func (d *CaddyDaemon) Wait() {
	signal.Notify(d.sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-d.sigCh
}

func (d *CaddyDaemon) initHosts() error {
	hostsMgr, err := hosts.NewManager()
	if err != nil {
		return err
	}
	d.hostsMgr = hostsMgr
	return nil
}

func (d *CaddyDaemon) initCerts() error {
	d.certMgr = certs.NewCertManager(d.dataDir)
	return d.certMgr.Init()
}

func (d *CaddyDaemon) initRouting() error {
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

func (d *CaddyDaemon) initWatchers() error {
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

func (d *CaddyDaemon) startCaddy() error {
	certPath, keyPath, _ := d.certMgr.GetCert("localhost")
	dashboardEndpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), dashboard.ServerPort)

	routes := []proxy.Route{
		{
			Subdomain: "",
			Endpoint:  dashboardEndpoint,
			CertPath:  certPath,
			KeyPath:   keyPath,
		},
	}

	cfg, err := proxy.BuildFullCaddyConfig(routes, adminSocket, d.config.HTTPSRedirect, d.config.LogLevel)
	if err != nil {
		return fmt.Errorf("failed to build caddy config: %w", err)
	}

	return caddy.Run(cfg)
}

func (d *CaddyDaemon) getBasePaths() []string {
	if len(d.config.WatchPaths) > 0 {
		return d.config.WatchPaths
	}
	if envPath := os.Getenv("LOCALPROXY_BASE_PATH"); envPath != "" {
		return strings.Split(envPath, ":")
	}
	return []string{defaultBasePath}
}

func (d *CaddyDaemon) onRoutesChanged(routes []proxy.Route, backends []dashboard.Backend) {
	d.dashboardServer.UpdateBackends(backends)

	certPath, keyPath, _ := d.certMgr.GetCert("localhost")
	dashboardEndpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), dashboard.ServerPort)
	caddyRoutes := []proxy.Route{
		{
			Subdomain: "",
			Endpoint:  dashboardEndpoint,
			CertPath:  certPath,
			KeyPath:   keyPath,
		},
	}
	var subdomains []string

	for i, r := range routes {
		backend := backends[i]
		if backend.Disabled {
			continue
		}

		certKey := r.Subdomain
		if certKey == "" {
			certKey = "localhost"
		}

		var cPath, kPath string
		useWildcard := r.HasWildcard || r.FolderGroup != ""

		if useWildcard {
			wildcardKey := certKey
			if r.FolderGroup != "" && !r.HasWildcard {
				wildcardKey = r.FolderGroup
			}
			if err := d.certMgr.EnsureWildcardCert(wildcardKey); err != nil {
				log.Printf("failed to generate wildcard cert for %s: %v", wildcardKey, err)
				continue
			}
			cPath, kPath, _ = d.certMgr.GetWildcardCert(wildcardKey)
		} else {
			if err := d.certMgr.EnsureCert(certKey); err != nil {
				log.Printf("failed to generate cert for %s: %v", certKey, err)
				continue
			}
			cPath, kPath, _ = d.certMgr.GetCert(certKey)
		}

		caddyRoute := proxy.Route{
			Subdomain:   r.Subdomain,
			Endpoint:    r.Endpoint,
			CertPath:    cPath,
			KeyPath:     kPath,
			HasWildcard: r.HasWildcard,
			FolderGroup: r.FolderGroup,
		}
		caddyRoutes = append(caddyRoutes, caddyRoute)
		subdomains = append(subdomains, r.Subdomain)
	}

	cfg, err := proxy.BuildFullCaddyConfig(caddyRoutes, adminSocket, d.config.HTTPSRedirect, d.config.LogLevel)
	if err != nil {
		log.Printf("failed to build caddy config: %v", err)
		return
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		log.Printf("failed to marshal caddy config: %v", err)
		return
	}

	if err := caddy.Load(cfgJSON, true); err != nil {
		log.Printf("failed to reload caddy config: %v", err)
		return
	}

	if d.hostsMgr != nil {
		if err := d.hostsMgr.Update(subdomains); err != nil {
			log.Printf("failed to update hosts: %v", err)
		}
	}

	log.Printf("updated routes: %d active", len(routes))
}

func (d *CaddyDaemon) onProcessesChanged(services []discovery.DiscoveredService) {
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

func (d *CaddyDaemon) onDockerChanged(services []discovery.DiscoveredService) {
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

func (d *CaddyDaemon) onDockerHealthy(svc discovery.DiscoveredService) {
	log.Printf("docker: container healthy %s", svc.Subdomain)
	d.dockerWatcher.DiscoverServiceInfo(svc, func(updated discovery.DiscoveredService) {
		d.routeRegistry.UpdateService(updated)
	})
}

func (d *CaddyDaemon) onUnroutedContainersChanged(containers []discovery.UnroutedContainer) {
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
