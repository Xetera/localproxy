package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/xetera/localproxy/internal/discovery"
)

const (
	ServerPort = 13279
)

func getTemplatesPath() string {
	paths := []string{
		"templates",
		"internal/proxy/templates",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, p := range paths {
			fullPath := filepath.Join(exeDir, p)
			if _, err := os.Stat(fullPath); err == nil {
				return fullPath
			}
		}
	}

	return "internal/proxy/templates"
}

type DashboardServer struct {
	server     *http.Server
	routes     map[string]Route
	routesMu   sync.RWMutex
	logManager *LogManager
	basePaths  []string
}

func NewDashboardServer(basePaths []string) *DashboardServer {
	s := &DashboardServer{
		routes:     make(map[string]Route),
		logManager: NewLogManager(),
		basePaths:  basePaths,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serveDashboard)
	mux.HandleFunc("/logs", s.serveLogs)
	mux.HandleFunc("/api/logs-preview", s.serveLogsPreview)

	s.server = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", ServerPort),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return s
}

func (s *DashboardServer) SetBasePaths(paths []string) {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	s.basePaths = paths
}

func (s *DashboardServer) UpdateRoutes(routes []Route) {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()

	s.routes = make(map[string]Route)
	for _, r := range routes {
		s.routes[r.Subdomain] = r
	}

	go s.logManager.UpdateRoutes(routes)
}

func (s *DashboardServer) Start() error {
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("dashboard server error: %v", err)
		}
	}()
	return nil
}

func (s *DashboardServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.logManager.Stop()
	return s.server.Shutdown(ctx)
}

type RouteWithLogs struct {
	Route
	RecentLogs []string
}

type ProcessGroup struct {
	Cwd        string
	DisplayCwd string
	Routes     []RouteWithLogs
}

func trimBasePath(cwd string, basePaths []string) string {
	for _, base := range basePaths {
		if trimmed, ok := strings.CutPrefix(cwd, base); ok {
			trimmed = strings.TrimPrefix(trimmed, "/")
			if idx := strings.Index(trimmed, "/"); idx != -1 {
				return trimmed[:idx]
			}
			return trimmed
		}
	}
	return cwd
}

func (s *DashboardServer) serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.routesMu.RLock()
	basePaths := s.basePaths
	var enabledRoutes, disabledRoutes, wellKnownRoutes []RouteWithLogs
	for _, route := range s.routes {
		routeWithLogs := RouteWithLogs{
			Route:      route,
			RecentLogs: []string{},
		}
		if route.Source == RouteSourceDocker && route.DockerContainerID != "" {
			buffer := s.logManager.GetBufferByContainerID(route.DockerContainerID)
			routeWithLogs.RecentLogs = buffer.GetLines()
		} else if route.PID > 0 {
			buffer := s.logManager.GetBufferByPID(route.PID)
			routeWithLogs.RecentLogs = buffer.GetLines()
		}

		if route.Disabled {
			disabledRoutes = append(disabledRoutes, routeWithLogs)
		} else if route.Source == RouteSourceWellKnown {
			wellKnownRoutes = append(wellKnownRoutes, routeWithLogs)
		} else {
			enabledRoutes = append(enabledRoutes, routeWithLogs)
		}
	}
	s.routesMu.RUnlock()

	var dockerRoutes, processRoutes []RouteWithLogs
	for _, r := range enabledRoutes {
		if r.Source == RouteSourceDocker {
			dockerRoutes = append(dockerRoutes, r)
		} else {
			processRoutes = append(processRoutes, r)
		}
	}
	for _, r := range disabledRoutes {
		if r.Source == RouteSourceProcess {
			processRoutes = append(processRoutes, r)
		}
	}

	sort.Slice(dockerRoutes, func(i, j int) bool {
		return dockerRoutes[i].Subdomain < dockerRoutes[j].Subdomain
	})
	sort.Slice(processRoutes, func(i, j int) bool {
		return processRoutes[i].Subdomain < processRoutes[j].Subdomain
	})
	sort.Slice(disabledRoutes, func(i, j int) bool {
		return disabledRoutes[i].Subdomain < disabledRoutes[j].Subdomain
	})
	var otherDisabledRoutes []RouteWithLogs
	for _, r := range disabledRoutes {
		if r.Source != RouteSourceProcess {
			otherDisabledRoutes = append(otherDisabledRoutes, r)
		}
	}
	sort.Slice(wellKnownRoutes, func(i, j int) bool {
		return wellKnownRoutes[i].Subdomain < wellKnownRoutes[j].Subdomain
	})

	type routeWithDisplayCwd struct {
		route      RouteWithLogs
		displayCwd string
	}
	var processRoutesWithDisplay []routeWithDisplayCwd
	displayCwdCounts := make(map[string]int)
	for _, r := range processRoutes {
		displayCwd := trimBasePath(r.Cwd, basePaths)
		processRoutesWithDisplay = append(processRoutesWithDisplay, routeWithDisplayCwd{
			route:      r,
			displayCwd: displayCwd,
		})
		if displayCwd != "" {
			displayCwdCounts[displayCwd]++
		}
	}

	var processGroups []ProcessGroup
	groupedDisplayCwds := make(map[string]bool)
	var ungroupedProcesses []RouteWithLogs
	fmt.Println(displayCwdCounts)

	for _, r := range processRoutesWithDisplay {
		if r.displayCwd != "" && displayCwdCounts[r.displayCwd] > 1 {
			if !groupedDisplayCwds[r.displayCwd] {
				groupedDisplayCwds[r.displayCwd] = true
				var groupRoutes []RouteWithLogs
				for _, pr := range processRoutesWithDisplay {
					if pr.displayCwd == r.displayCwd {
						groupRoutes = append(groupRoutes, pr.route)
					}
				}
				processGroups = append(processGroups, ProcessGroup{
					Cwd:        r.route.Cwd,
					DisplayCwd: r.displayCwd,
					Routes:     groupRoutes,
				})
			}
		} else {
			ungroupedProcesses = append(ungroupedProcesses, r.route)
		}
	}

	sort.Slice(processGroups, func(i, j int) bool {
		return processGroups[i].Cwd < processGroups[j].Cwd
	})

	activeWellKnown := make(map[string]bool)
	for _, r := range wellKnownRoutes {
		activeWellKnown[r.Subdomain] = true
	}

	allWellKnown := discovery.GetAllWellKnownPorts()
	var inactiveWellKnown []discovery.WellKnownPort
	for _, wk := range allWellKnown {
		if !activeWellKnown[wk.Subdomain] {
			inactiveWellKnown = append(inactiveWellKnown, wk)
		}
	}

	templatesPath := getTemplatesPath()
	tmpl, err := template.ParseFiles(filepath.Join(templatesPath, "dashboard.html"))
	if err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
		return
	}

	logsMap := make(map[string][]string)
	for _, r := range enabledRoutes {
		logsMap[r.Subdomain] = r.RecentLogs
	}
	for _, r := range processRoutes {
		if _, exists := logsMap[r.Subdomain]; !exists {
			logsMap[r.Subdomain] = r.RecentLogs
		}
	}
	for _, r := range wellKnownRoutes {
		logsMap[r.Subdomain] = r.RecentLogs
	}

	logsJSON, _ := json.Marshal(logsMap)

	routesMap := make(map[string]Route)
	for _, r := range enabledRoutes {
		routesMap[r.Subdomain] = r.Route
	}
	for _, r := range processRoutes {
		if _, exists := routesMap[r.Subdomain]; !exists {
			routesMap[r.Subdomain] = r.Route
		}
	}
	for _, r := range wellKnownRoutes {
		routesMap[r.Subdomain] = r.Route
	}
	routesJSON, _ := json.Marshal(routesMap)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, map[string]interface{}{
		"EnabledRoutes":      enabledRoutes,
		"DockerRoutes":       dockerRoutes,
		"ProcessGroups":      processGroups,
		"UngroupedProcesses": ungroupedProcesses,
		"DisabledRoutes":     otherDisabledRoutes,
		"WellKnownRoutes":    wellKnownRoutes,
		"InactiveWellKnown":  inactiveWellKnown,
		"LogsMapJSON":        template.JS(logsJSON),
		"RoutesJSON":         template.JS(routesJSON),
	})
}

func (s *DashboardServer) serveLogsPreview(w http.ResponseWriter, r *http.Request) {
	s.routesMu.RLock()
	logsMap := make(map[string][]string)
	for _, route := range s.routes {
		var buffer *LogBuffer
		if route.Source == RouteSourceDocker && route.DockerContainerID != "" {
			buffer = s.logManager.GetBufferByContainerID(route.DockerContainerID)
		} else if route.PID > 0 {
			buffer = s.logManager.GetBufferByPID(route.PID)
		}

		if buffer != nil {
			logs := buffer.GetLines()
			logsMap[route.Subdomain] = logs
		}
	}
	s.routesMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logsMap)
}

func (s *DashboardServer) serveLogs(w http.ResponseWriter, r *http.Request) {
	subdomain := r.URL.Query().Get("subdomain")
	if subdomain == "" {
		http.Error(w, "subdomain parameter required", http.StatusBadRequest)
		return
	}

	s.routesMu.RLock()
	route, exists := s.routes[subdomain]
	s.routesMu.RUnlock()

	if !exists {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") {
		s.streamLogs(w, r, subdomain)
		return
	}

	templatesPath := getTemplatesPath()
	tmpl, err := template.ParseFiles(filepath.Join(templatesPath, "logs.html"))
	if err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, map[string]interface{}{
		"Subdomain": route.Subdomain,
		"PID":       route.PID,
		"Port":      route.Port,
		"Cwd":       route.Cwd,
	})
}

func (s *DashboardServer) streamLogs(w http.ResponseWriter, r *http.Request, subdomain string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	s.routesMu.RLock()
	route, exists := s.routes[subdomain]
	s.routesMu.RUnlock()

	if !exists {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	var reader io.ReadCloser
	var err error

	if route.Source == RouteSourceDocker && route.DockerContainerID != "" {
		if s.logManager.dockerClient == nil {
			http.Error(w, "docker client not available", http.StatusInternalServerError)
			return
		}

		options := container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Tail:       "10",
		}

		reader, err = s.logManager.dockerClient.ContainerLogs(r.Context(), route.DockerContainerID, options)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get docker logs: %v", err), http.StatusInternalServerError)
			return
		}
	} else if route.PID > 0 {
		pidStr := strconv.Itoa(route.PID)
		dtrace := exec.CommandContext(r.Context(), "sudo", "dtrace", "-p", pidStr, "-qn",
			`syscall::write*:entry
			/pid == $target && arg0 == 1/ {
				printf("%s", copyinstr(arg1, arg2));
			}`)

		reader, err = dtrace.StdoutPipe()
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create pipe: %v", err), http.StatusInternalServerError)
			return
		}

		if err := dtrace.Start(); err != nil {
			http.Error(w, fmt.Sprintf("failed to start dtrace: %v", err), http.StatusInternalServerError)
			return
		}

		defer dtrace.Process.Kill()
	} else {
		http.Error(w, "no logs available for this service", http.StatusBadRequest)
		return
	}

	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if route.Source == RouteSourceDocker && len(line) > 8 {
			line = line[8:]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("log stream error: %v", err)
	}
}
