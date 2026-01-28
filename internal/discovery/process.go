package discovery

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type portEntry struct {
	PID  int
	Port int
}

type ProcessWatcher struct {
	basePaths         []string
	onChange          func([]ListeningProcess)
	onWellKnownChange func([]WellKnownProcess)
	ctx               context.Context
	cancel            context.CancelFunc
	mu                sync.RWMutex
	current           map[int]ListeningProcess
	currentWellKnown  map[int]WellKnownProcess
	dockerPorts       map[int]bool
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
		basePaths:        absPaths,
		ctx:              ctx,
		cancel:           cancel,
		current:          make(map[int]ListeningProcess),
		currentWellKnown: make(map[int]WellKnownProcess),
		dockerPorts:      make(map[int]bool),
	}, nil
}

func (w *ProcessWatcher) SetOnChange(fn func([]ListeningProcess)) {
	w.onChange = fn
}

func (w *ProcessWatcher) SetOnWellKnownChange(fn func([]WellKnownProcess)) {
	w.onWellKnownChange = fn
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
	processes, wellKnown, err := w.scan()
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.current = make(map[int]ListeningProcess)
	for _, p := range processes {
		w.current[p.PID] = p
	}
	w.currentWellKnown = make(map[int]WellKnownProcess)
	for _, p := range wellKnown {
		w.currentWellKnown[p.PID] = p
	}
	w.mu.Unlock()

	if w.onChange != nil {
		w.onChange(processes)
	}
	if w.onWellKnownChange != nil {
		w.onWellKnownChange(wellKnown)
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
			processes, wellKnown, err := w.scan()
			if err != nil {
				continue
			}

			w.mu.Lock()
			changed := len(processes) != len(w.current)
			var newTargets []ScanTarget
			if !changed {
				for _, p := range processes {
					if existing, ok := w.current[p.PID]; !ok || existing.Port != p.Port {
						changed = true
						break
					}
				}
			}
			if changed {
				for _, p := range processes {
					if _, ok := w.current[p.PID]; !ok {
						newTargets = append(newTargets, ScanTarget{IP: p.IP, Port: p.Port})
					}
				}
			}

			wellKnownChanged := len(wellKnown) != len(w.currentWellKnown)
			if !wellKnownChanged {
				for _, p := range wellKnown {
					if existing, ok := w.currentWellKnown[p.PID]; !ok || existing.Port != p.Port {
						wellKnownChanged = true
						break
					}
				}
			}

			if changed {
				w.current = make(map[int]ListeningProcess)
				for _, p := range processes {
					w.current[p.PID] = p
				}
			}

			if wellKnownChanged {
				w.currentWellKnown = make(map[int]WellKnownProcess)
				for _, p := range wellKnown {
					w.currentWellKnown[p.PID] = p
				}
			}

			w.mu.Unlock()

			if len(newTargets) > 0 {
				w.discoverNewServices(newTargets)
			}

			if changed && w.onChange != nil {
				w.onChange(processes)
			}
			if wellKnownChanged && w.onWellKnownChange != nil {
				w.onWellKnownChange(wellKnown)
			}
		}
	}
}

func (w *ProcessWatcher) scan() ([]ListeningProcess, []WellKnownProcess, error) {
	listeners, err := w.getListeningPorts()
	if err != nil {
		return nil, nil, err
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

	return state.results, state.wellKnownResults, nil
}

type scanState struct {
	ignoredDirs      map[string]bool
	usedPorts        map[int]bool
	seenPID          map[int]bool
	cwdCache         map[int]string
	results          []ListeningProcess
	wellKnownResults []WellKnownProcess
}

func (w *ProcessWatcher) processEntry(state *scanState, entry portEntry) {
	pid := entry.PID
	port := entry.Port

	cwd := w.getOrCacheCWD(state, pid)

	if cwd == "" {
		w.handleUnknownCWD(state, pid, port)
		return
	}

	basePath := w.findMatchingBasePath(cwd)
	if basePath == "" {
		w.handleOutsideBasePath(state, cwd, pid, port)
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

func (w *ProcessWatcher) addWellKnownProcess(state *scanState, pid int, port int) {
	info, ok := WellKnownPorts[port]
	if !ok || state.usedPorts[port] {
		return
	}
	state.wellKnownResults = append(state.wellKnownResults, WellKnownProcess{
		PID:       pid,
		Port:      port,
		Subdomain: info.Subdomain,
		TCPPort:   info.TCPPort,
		IsDocker:  w.dockerPorts[port],
	})
	state.usedPorts[port] = true
}

func (w *ProcessWatcher) addListeningProcess(state *scanState, pid int, port int, subdomain string, cwd string, needsCustomMapping bool) {
	if state.seenPID[pid] {
		return
	}
	state.results = append(state.results, ListeningProcess{
		PID:                pid,
		Port:               port,
		IP:                 "127.0.0.1",
		Subdomain:          subdomain,
		Cwd:                cwd,
		Disabled:           needsCustomMapping,
		NeedsCustomMapping: needsCustomMapping,
	})
	state.seenPID[pid] = true
}

func (w *ProcessWatcher) handleUnknownCWD(state *scanState, pid int, port int) {
	w.addWellKnownProcess(state, pid, port)
}

func (w *ProcessWatcher) handleOutsideBasePath(state *scanState, cwd string, pid int, port int) {
	w.addWellKnownProcess(state, pid, port)
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

func (w *ProcessWatcher) reverseAndJoin(parts []string) string {
	reversed := make([]string, len(parts))
	for i := range parts {
		reversed[i] = parts[len(parts)-1-i]
	}
	return strings.Join(reversed, ".")
}

func (w *ProcessWatcher) discoverNewServices(targets []ScanTarget) {
	ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
	defer cancel()

	services, err := DiscoverServices(ctx, targets)
	if err != nil {
		return
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
	defer w.mu.Unlock()

	for pid, proc := range w.current {
		key := serviceKey{IP: proc.IP, Port: proc.Port}
		if svc, ok := serviceByKey[key]; ok {
			proc.Service = svc
			w.current[pid] = proc
		}
	}
}
