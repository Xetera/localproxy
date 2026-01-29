package discovery

import (
	"context"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type portEntry struct {
	PID  int
	Port int
	IP   string
}

type ProcessWatcher struct {
	basePaths   []string
	onChange    func([]DiscoveredService)
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	current     map[int]DiscoveredService
	dockerPorts map[int]bool
}

func NewProcessWatcher(basePaths []string) (*ProcessWatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())
	absPaths := make([]string, 0, len(basePaths))
	for _, p := range basePaths {
		absPath, err := filepath.Abs(p)
		if err != nil {
			cancel()
			return nil, err
		}
		absPaths = append(absPaths, absPath)
	}

	return &ProcessWatcher{
		basePaths:   absPaths,
		ctx:         ctx,
		cancel:      cancel,
		current:     make(map[int]DiscoveredService),
		dockerPorts: make(map[int]bool),
	}, nil
}

func (w *ProcessWatcher) SetOnChange(fn func([]DiscoveredService)) {
	w.onChange = fn
}

func (w *ProcessWatcher) SetDockerPorts(ports []int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dockerPorts = make(map[int]bool)
	for _, port := range ports {
		w.dockerPorts[port] = true
	}
}

func (w *ProcessWatcher) Start() error {
	services, err := w.scan()
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.current = make(map[int]DiscoveredService)
	for _, s := range services {
		if s.Process != nil {
			w.current[s.Process.PID] = s
		}
	}
	w.mu.Unlock()

	initialTargets := make([]ScanTarget, 0, len(services))
	for _, s := range services {
		initialTargets = append(initialTargets, ScanTarget{IP: s.IP, Port: s.Port})
	}
	if len(initialTargets) > 0 {
		w.discoverNewServices(initialTargets)
	}

	if w.onChange != nil {
		w.onChange(services)
	}

	go w.watchLoop()
	return nil
}

func (w *ProcessWatcher) Stop() {
	w.cancel()
}

func (w *ProcessWatcher) watchLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			services, err := w.scan()
			if err != nil {
				continue
			}

			w.mu.Lock()
			changed := len(services) != len(w.current)
			var newTargets []ScanTarget
			if !changed {
				for _, s := range services {
					if s.Process == nil {
						continue
					}
					if existing, ok := w.current[s.Process.PID]; !ok || existing.Port != s.Port {
						changed = true
						break
					}
				}
			}
			if changed {
				for _, s := range services {
					if s.Process == nil {
						continue
					}
					if _, ok := w.current[s.Process.PID]; !ok {
						newTargets = append(newTargets, ScanTarget{IP: s.IP, Port: s.Port})
					}
				}
			}

			if changed {
				w.current = make(map[int]DiscoveredService)
				for _, s := range services {
					if s.Process != nil {
						w.current[s.Process.PID] = s
					}
				}
			}

			w.mu.Unlock()

			if len(newTargets) > 0 {
				w.discoverNewServices(newTargets)
			}

			if changed && w.onChange != nil {
				w.onChange(services)
			}
		}
	}
}

func (w *ProcessWatcher) scan() ([]DiscoveredService, error) {
	listeners, err := w.getListeningPorts()
	if err != nil {
		return nil, err
	}

	state := &scanState{
		ignoredDirs: map[string]bool{"apps": true, "packages": true},
		usedPorts:   make(map[int]bool),
		seenPID:     make(map[int]bool),
		cwdCache:    make(map[int]string),
	}

	for _, entry := range listeners {
		w.processEntry(state, entry)
	}

	return state.results, nil
}

type scanState struct {
	ignoredDirs map[string]bool
	usedPorts   map[int]bool
	seenPID     map[int]bool
	cwdCache    map[int]string
	results     []DiscoveredService
}

func (w *ProcessWatcher) processEntry(state *scanState, entry portEntry) {
	pid := entry.PID
	port := entry.Port
	ip := entry.IP

	cwd := w.getOrCacheCWD(state, pid)

	if cwd == "" {
		w.handleUnknownCWD(state, pid, port, ip)
		return
	}

	basePath := w.findMatchingBasePath(cwd)
	if basePath == "" {
		w.handleOutsideBasePath(state, pid, port, ip)
		return
	}

	subdomain, needsCustomMapping := w.buildSubdomain(basePath, cwd, state.ignoredDirs)
	if subdomain == "" && !needsCustomMapping {
		return
	}

	w.addListeningProcess(state, pid, port, subdomain, cwd, needsCustomMapping)
	state.usedPorts[port] = true
}

func (w *ProcessWatcher) getOrCacheCWD(state *scanState, pid int) string {
	if cwd, cached := state.cwdCache[pid]; cached {
		return cwd
	}
	cwd := w.getProcCwd(pid)
	state.cwdCache[pid] = cwd
	return cwd
}

func (w *ProcessWatcher) findMatchingBasePath(cwd string) string {
	for _, basePath := range w.basePaths {
		if strings.HasPrefix(cwd, basePath) {
			return basePath
		}
	}
	return ""
}

func (w *ProcessWatcher) addWellKnownProcess(state *scanState, pid int, port int, ip string) {
	info, ok := WellKnownPorts[port]
	if !ok || state.usedPorts[port] {
		return
	}
	state.results = append(state.results, DiscoveredService{
		Subdomain: info.Subdomain,
		Port:      port,
		IP:        ip,
		TCPPort:   info.TCPPort,
		Source:    RouteSourceWellKnown,
		Process: &ProcessInfo{
			PID:         pid,
			IsWellKnown: true,
			IsDocker:    w.dockerPorts[port],
		},
	})
	state.usedPorts[port] = true
}

func (w *ProcessWatcher) addListeningProcess(state *scanState, pid int, port int, subdomain string, cwd string, needsCustomMapping bool) {
	if state.seenPID[pid] {
		return
	}
	state.results = append(state.results, DiscoveredService{
		Subdomain: subdomain,
		Port:      port,
		IP:        "127.0.0.1",
		Source:    RouteSourceProcess,
		Process: &ProcessInfo{
			PID:                pid,
			Cwd:                cwd,
			Disabled:           needsCustomMapping,
			NeedsCustomMapping: needsCustomMapping,
		},
	})
	state.seenPID[pid] = true
}

func (w *ProcessWatcher) handleUnknownCWD(state *scanState, pid int, port int, ip string) {
	w.addWellKnownProcess(state, pid, port, ip)
}

func (w *ProcessWatcher) handleOutsideBasePath(state *scanState, pid int, port int, ip string) {
	w.addWellKnownProcess(state, pid, port, ip)
}

func (w *ProcessWatcher) buildSubdomain(basePath string, cwd string, ignoredDirs map[string]bool) (string, bool) {
	rel, err := filepath.Rel(basePath, cwd)
	if err != nil {
		return "", false
	}

	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) == 0 || parts[0] == "" || parts[0] == "." {
		return "", false
	}

	filteredParts := w.filterPathParts(parts, ignoredDirs)
	if len(filteredParts) == 0 {
		return "", false
	}

	if len(filteredParts) == 1 {
		subdomain := filteredParts[0]
		return subdomain, false
	}

	return "", true
}

func (w *ProcessWatcher) filterPathParts(parts []string, ignoredDirs map[string]bool) []string {
	var filtered []string
	for _, p := range parts {
		if p != "" && p != "." && !ignoredDirs[p] {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func (w *ProcessWatcher) discoverNewServices(targets []ScanTarget) {
	ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)

	log.Printf("process: starting service discovery for %d targets", len(targets))

	results := make(chan []ServiceInfo, 1)
	DiscoverServices(ctx, targets, results)

	go func() {
		defer cancel()

		services, ok := <-results
		if !ok {
			log.Printf("process: service discovery channel closed without results")
			return
		}
		if len(services) == 0 {
			log.Printf("process: service discovery returned 0 services")
			return
		}

		log.Printf("process: discovered %d services", len(services))
		for _, s := range services {
			log.Printf("process: discovered service %s:%d protocol=%s", s.IP, s.Port, s.Protocol)
		}

		type serviceKey struct {
			IP   string
			Port int
		}
		serviceByKey := make(map[serviceKey]*ServiceInfo)
		for i := range services {
			key := serviceKey{IP: services[i].IP, Port: services[i].Port}
			serviceByKey[key] = &services[i]
		}

		w.mu.Lock()
		updated := false
		for pid, svc := range w.current {
			key := serviceKey{IP: svc.IP, Port: svc.Port}
			if info, ok := serviceByKey[key]; ok {
				log.Printf("process: assigning ServiceInfo to %s (pid %d): protocol=%s", svc.Subdomain, pid, info.Protocol)
				svc.Service = info
				w.current[pid] = svc
				updated = true
			}
		}

		if updated && w.onChange != nil {
			var all []DiscoveredService
			for _, svc := range w.current {
				all = append(all, svc)
			}
			w.mu.Unlock()
			log.Printf("process: triggering onChange with %d updated services", len(all))
			w.onChange(all)
			return
		}
		w.mu.Unlock()
	}()
}
