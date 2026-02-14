package discovery

import (
	"context"
	"log"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Pid = int
type ProcessMap = map[Pid]DiscoveredService

type listener struct {
	Endpoint netip.AddrPort
	PID      int
}

type ProcessWatcher struct {
	basePaths []string
	onChange  func([]DiscoveredService)
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	current   ProcessMap
}

func resolveToAbsolutePaths(basePaths []string) ([]string, error) {
	absPaths := make([]string, 0, len(basePaths))
	for _, p := range basePaths {
		absPath, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		absPaths = append(absPaths, absPath)
	}
	return absPaths, nil
}

func NewProcessWatcher(basePaths []string) (*ProcessWatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())
	absPaths, err := resolveToAbsolutePaths(basePaths)

	if err != nil {
		cancel()
		return nil, err
	}

	return &ProcessWatcher{
		basePaths: absPaths,
		ctx:       ctx,
		cancel:    cancel,
		current:   make(ProcessMap),
	}, nil
}

func (w *ProcessWatcher) SetOnChange(fn func([]DiscoveredService)) {
	w.onChange = fn
}

func (w *ProcessWatcher) Start() error {
	services, err := w.scan()
	if err != nil {
		return err
	}

	w.setProcesses(services)

	initialTargets := make([]netip.AddrPort, 0, len(services))
	for _, s := range services {
		initialTargets = append(initialTargets, s.Endpoint)
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

			changed := w.isServicesChanged(services)
			var newTargets []netip.AddrPort
			if changed {
				newTargets = w.getNewTargets(services)
				w.setProcesses(services)
			}

			if len(newTargets) > 0 {
				w.discoverNewServices(newTargets)
			}

			if changed && w.onChange != nil {
				w.onChange(services)
			}
		}
	}
}

func (w *ProcessWatcher) isServicesChanged(services []DiscoveredService) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	changed := len(services) != len(w.current)
	if !changed {
		for _, s := range services {
			if s.Process == nil {
				continue
			}
			if existing, ok := w.current[s.Process.PID]; !ok || existing.Endpoint.Port() != s.Endpoint.Port() {
				changed = true
				break
			}
		}
	}
	return changed
}

func (w *ProcessWatcher) setProcesses(services []DiscoveredService) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.current = make(ProcessMap)
	for _, s := range services {
		if s.Process != nil {
			w.current[s.Process.PID] = s
		}
	}
}

func (w *ProcessWatcher) getNewTargets(services []DiscoveredService) []netip.AddrPort {
	w.mu.Lock()
	defer w.mu.Unlock()

	var newTargets []netip.AddrPort
	for _, s := range services {
		if s.Process == nil {
			continue
		}
		if _, ok := w.current[s.Process.PID]; !ok {
			newTargets = append(newTargets, s.Endpoint)
		}
	}
	return newTargets
}

type scanState struct {
	ignoredDirs map[string]bool
	usedPorts   map[uint16]bool
	seenPID     map[int]bool
	cwdCache    map[int]string
}

type pathResult struct {
	needsCustomMapping bool
	topLevelFolder     string
	relativePath       string
}

func newScanState() *scanState {
	return &scanState{
		ignoredDirs: map[string]bool{"apps": true, "packages": true},
		usedPorts:   make(map[uint16]bool),
		seenPID:     make(map[int]bool),
		cwdCache:    make(map[int]string),
	}
}

func (s *scanState) tryWellKnown(pid int, endpoint netip.AddrPort) *DiscoveredService {
	port := endpoint.Port()
	info, ok := WellKnownPorts[port]
	if !ok || s.usedPorts[port] {
		return nil
	}
	s.usedPorts[port] = true
	return &DiscoveredService{
		Endpoint: endpoint,
		TCPPort:  info.TCPPort,
		Source:   RouteSourceWellKnown,
		Process: &ProcessInfo{
			PID:         pid,
			IsWellKnown: true,
		},
		Service: &ServiceInfo{
			Endpoint: endpoint,
			Protocol: info.Subdomain,
		},
	}
}

func (s *scanState) tryListeningProcess(pid int, endpoint netip.AddrPort, result pathResult, cwd string) *DiscoveredService {
	if s.seenPID[pid] {
		return nil
	}
	s.seenPID[pid] = true
	s.usedPorts[endpoint.Port()] = true
	return &DiscoveredService{
		Endpoint: endpoint,
		Source:   RouteSourceProcess,
		Process: &ProcessInfo{
			PID:                pid,
			Cwd:                cwd,
			Disabled:           result.needsCustomMapping,
			NeedsCustomMapping: result.needsCustomMapping,
			TopLevelFolder:     result.topLevelFolder,
			RelativePath:       result.relativePath,
		},
	}
}

func (s *scanState) resolvePathInfo(basePath string, cwd string) pathResult {
	rel, err := filepath.Rel(basePath, cwd)
	if err != nil {
		return pathResult{}
	}

	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) == 0 || parts[0] == "" || parts[0] == "." {
		return pathResult{}
	}

	var filteredParts []string
	for _, p := range parts {
		if p != "" && p != "." && !s.ignoredDirs[p] {
			filteredParts = append(filteredParts, p)
		}
	}
	if len(filteredParts) == 0 {
		return pathResult{}
	}

	topLevel := filteredParts[0]

	return pathResult{
		needsCustomMapping: len(filteredParts) > 1,
		topLevelFolder:     topLevel,
		relativePath:       strings.Join(filteredParts, "/"),
	}
}

func (s *scanState) getCwd(pid int, lookup func(int) string) string {
	if cwd, cached := s.cwdCache[pid]; cached {
		return cwd
	}
	cwd := lookup(pid)
	s.cwdCache[pid] = cwd
	return cwd
}

func (w *ProcessWatcher) scan() ([]DiscoveredService, error) {
	listeners, err := w.getListeningPorts()
	if err != nil {
		log.Printf("process: getListeningPorts error: %v", err)
		return nil, err
	}

	state := newScanState()
	var results []DiscoveredService

	for _, entry := range listeners {
		if svc := w.classifyListener(state, entry); svc != nil {
			results = append(results, *svc)
		}
	}

	return results, nil
}

func (w *ProcessWatcher) classifyListener(state *scanState, entry listener) *DiscoveredService {
	pid := entry.PID
	cwd := state.getCwd(pid, w.getProcCwd)

	if cwd == "" {
		log.Printf("process: PID=%d has no CWD, trying well-known", pid)
		return state.tryWellKnown(pid, entry.Endpoint)
	}

	basePath := w.findMatchingBasePath(cwd)
	if basePath == "" {
		return state.tryWellKnown(pid, entry.Endpoint)
	}

	result := state.resolvePathInfo(basePath, cwd)
	if result.topLevelFolder == "" {
		return nil
	}

	return state.tryListeningProcess(pid, entry.Endpoint, result, cwd)
}

func (w *ProcessWatcher) findMatchingBasePath(cwd string) string {
	for _, basePath := range w.basePaths {
		if strings.HasPrefix(cwd, basePath) {
			return basePath
		}
	}
	return ""
}

func (w *ProcessWatcher) discoverNewServices(targets []netip.AddrPort) {
	ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)

	log.Printf("process: starting service discovery for %d targets", len(targets))

	results := make(chan []ServiceInfo, 1)
	ProbeEndpoints(ctx, targets, results)

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
			log.Printf("process: discovered service %s protocol=%s", s.Endpoint.String(), s.Protocol)
		}

		serviceByKey := make(map[netip.AddrPort]*ServiceInfo)
		for i, svc := range services {
			key := svc.Endpoint
			serviceByKey[key] = &services[i]
		}

		w.mu.Lock()
		updated := false
		for pid, svc := range w.current {
			if info, ok := serviceByKey[svc.Endpoint]; ok {
				log.Printf("process: assigning ServiceInfo to %s (pid %d): protocol=%s", svc.Endpoint, pid, info.Protocol)
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
