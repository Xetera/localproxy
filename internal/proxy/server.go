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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/envoy"
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

type UnroutedContainer struct {
	ID     string
	Name   string
	Reason string
}

type DashboardServer struct {
	server             *http.Server
	routes             map[string]Route
	routesMu           sync.RWMutex
	logManager         *LogManager
	basePaths          []string
	unroutedContainers []UnroutedContainer
	statsScraper       *envoy.StatsScraper
}

func NewDashboardServer(basePaths []string, traceProcessLogs bool, statsScraper *envoy.StatsScraper) *DashboardServer {
	s := &DashboardServer{
		routes:       make(map[string]Route),
		logManager:   NewLogManager(traceProcessLogs),
		basePaths:    basePaths,
		statsScraper: statsScraper,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/logs", s.serveLogs)
	mux.HandleFunc("/api/logs-preview", s.serveLogsPreview)
	mux.HandleFunc("/api/stats", s.serveStats)

	s.server = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", ServerPort),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return s
}

func (s *DashboardServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	if host == "localhost" || host == "proxy.localhost" || host == "proxy.internal" || host == fmt.Sprintf("127.0.0.1:%d", ServerPort) || host == fmt.Sprintf("localhost:%d", ServerPort) {
		s.serveDashboard(w, r)
		return
	}

	s.serve404(w, r, host)
}

func (s *DashboardServer) serve404(w http.ResponseWriter, r *http.Request, host string) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	templatesPath := getTemplatesPath()
	tmpl, err := template.ParseFiles(filepath.Join(templatesPath, "404.html"))
	if err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
		return
	}

	subdomain := ""
	if strings.HasSuffix(host, ".localhost") {
		subdomain = strings.TrimSuffix(host, ".localhost")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	tmpl.Execute(w, map[string]interface{}{
		"Host":      host,
		"Subdomain": subdomain,
	})
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

func (s *DashboardServer) UpdateUnroutedContainers(containers []UnroutedContainer) {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	s.unroutedContainers = containers
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
	RecentLogs  []string
	DisplayPath string
}

type ProcessGroup struct {
	Cwd        string
	DisplayCwd string
	Routes     []RouteWithLogs
}

type FormattedStats struct {
	RxFormatted           string
	TxFormatted           string
	RxRateFormatted       string
	TxRateFormatted       string
	RequestsFormatted     string
	RequestsRateFormatted string
	HTTP2xxFormatted      string
	HTTP4xxFormatted      string
	HTTP5xxFormatted      string
	HTTP1Formatted        string
	HTTP2Formatted        string
	HTTP3Formatted        string
	ActiveConnections     uint64
	DisconnectsFormatted  string
}

func formatBytes(bytes uint64) string {
	if bytes == 0 {
		return "0"
	}
	const k = 1024
	sizes := []string{"B", "KB", "MB", "GB"}
	i := 0
	b := float64(bytes)
	for b >= k && i < len(sizes)-1 {
		b /= k
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d%s", bytes, sizes[i])
	}
	return fmt.Sprintf("%.1f%s", b, sizes[i])
}

func formatNumber(n uint64) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func formatRate(r float64) string {
	return formatBytes(uint64(r))
}

func trimBasePath(cwd string, basePaths []string) string {
	for _, base := range basePaths {
		if trimmed, ok := strings.CutPrefix(cwd, base); ok {
			return strings.TrimPrefix(trimmed, "/")
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
	unroutedContainers := s.unroutedContainers
	var enabledRoutes, disabledRoutes, wellKnownRoutes []RouteWithLogs
	for _, route := range s.routes {
		routeWithLogs := RouteWithLogs{
			Route:      route,
			RecentLogs: []string{},
		}
		if route.Source == discovery.RouteSourceDocker && route.DockerContainerID != "" {
			buffer := s.logManager.GetBufferByContainerID(route.DockerContainerID)
			routeWithLogs.RecentLogs = buffer.GetLines()
		} else if route.PID > 0 {
			buffer := s.logManager.GetBufferByPID(route.PID)
			routeWithLogs.RecentLogs = buffer.GetLines()
		}

		if route.Disabled {
			disabledRoutes = append(disabledRoutes, routeWithLogs)
		} else if route.Source == discovery.RouteSourceWellKnown {
			wellKnownRoutes = append(wellKnownRoutes, routeWithLogs)
		} else {
			enabledRoutes = append(enabledRoutes, routeWithLogs)
		}
	}
	s.routesMu.RUnlock()

	var dockerRoutes, processRoutes []RouteWithLogs
	for _, r := range enabledRoutes {
		if r.Source == discovery.RouteSourceDocker {
			dockerRoutes = append(dockerRoutes, r)
		} else {
			processRoutes = append(processRoutes, r)
		}
	}
	for _, r := range disabledRoutes {
		if r.Source == discovery.RouteSourceProcess {
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
		if r.Source != discovery.RouteSourceProcess {
			otherDisabledRoutes = append(otherDisabledRoutes, r)
		}
	}

	for i := range processRoutes {
		processRoutes[i].DisplayPath = trimBasePath(processRoutes[i].Cwd, basePaths)
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
		trimmed := trimBasePath(r.Cwd, basePaths)
		displayCwd := trimmed
		if idx := strings.Index(trimmed, "/"); idx != -1 {
			displayCwd = trimmed[:idx]
		}
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

	selectedSubdomain := r.URL.Query().Get("service")

	var selectedRoute *RouteWithLogs
	var selectedLogs []string

	allRoutes := append(append(append([]RouteWithLogs{}, dockerRoutes...), ungroupedProcesses...), wellKnownRoutes...)
	for _, g := range processGroups {
		allRoutes = append(allRoutes, g.Routes...)
	}

	type PortRepr struct {
		Port     int
		Text     string
		Protocol string
	}

	var portRepr []PortRepr
	for i := range allRoutes {
		if allRoutes[i].Subdomain == selectedSubdomain {
			selectedRoute = &allRoutes[i]
			selectedLogs = allRoutes[i].RecentLogs
			if len(selectedRoute.DockerPorts) > 0 {
				type portInfo struct {
					udp             bool
					tcp             bool
					serviceProtocol string
				}
				portsByNumber := make(map[int]*portInfo)
				for _, p := range selectedRoute.DockerPorts {
					if portsByNumber[p.Port] == nil {
						portsByNumber[p.Port] = &portInfo{}
					}
					info := portsByNumber[p.Port]
					if p.Type == "udp" {
						info.udp = true
					}
					if p.Type == "tcp" {
						info.tcp = true
						if p.ServiceProtocol != "" {
							info.serviceProtocol = p.ServiceProtocol
						}
					}
				}
				for port, info := range portsByNumber {
					var text string
					if info.tcp && info.udp {
						text = fmt.Sprintf("%d", port)
					} else if info.tcp {
						text = fmt.Sprintf("%d/tcp", port)
					} else {
						text = fmt.Sprintf("%d/udp", port)
					}
					portRepr = append(portRepr, PortRepr{Port: port, Text: text, Protocol: info.serviceProtocol})
				}
			}
			break
		}
	}

	selectedStats := FormattedStats{
		RxFormatted:           "0",
		TxFormatted:           "0",
		RxRateFormatted:       "0",
		TxRateFormatted:       "0",
		RequestsFormatted:     "0",
		RequestsRateFormatted: "0.0",
		HTTP2xxFormatted:      "0",
		HTTP4xxFormatted:      "0",
		HTTP5xxFormatted:      "0",
		HTTP1Formatted:        "0",
		HTTP2Formatted:        "0",
		HTTP3Formatted:        "0",
		ActiveConnections:     0,
		DisconnectsFormatted:  "0",
	}
	if selectedRoute != nil && s.statsScraper != nil {
		clusterName := selectedRoute.Subdomain
		if clusterName == "" {
			clusterName = "cluster_root"
		}
		allStats := s.statsScraper.GetClusterStats()
		globalStats := s.statsScraper.GetGlobalStats()
		if stats, ok := allStats[clusterName]; ok {
			selectedStats = FormattedStats{
				RxFormatted:           formatBytes(stats.TCPBytesReceived),
				TxFormatted:           formatBytes(stats.TCPBytesSent),
				RxRateFormatted:       formatRate(stats.TCPBytesReceivedRate),
				TxRateFormatted:       formatRate(stats.TCPBytesSentRate),
				RequestsFormatted:     formatNumber(stats.HTTPRequestsTotal),
				RequestsRateFormatted: fmt.Sprintf("%.1f", stats.HTTPRequestsRate),
				HTTP2xxFormatted:      formatNumber(stats.HTTP2xx),
				HTTP4xxFormatted:      formatNumber(stats.HTTP4xx),
				HTTP5xxFormatted:      formatNumber(stats.HTTP5xx),
				HTTP1Formatted:        formatNumber(globalStats.DownstreamHTTP1),
				HTTP2Formatted:        formatNumber(globalStats.DownstreamHTTP2),
				HTTP3Formatted:        formatNumber(globalStats.DownstreamHTTP3),
				ActiveConnections:     stats.ActiveConnections,
				DisconnectsFormatted:  formatNumber(stats.DisconnectsLocal + stats.DisconnectsRemote),
			}
		}
	}

	templatesPath := getTemplatesPath()
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}
	tmpl, err := template.New("dashboard.html").Funcs(funcMap).ParseFiles(filepath.Join(templatesPath, "dashboard.html"))
	if err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, map[string]interface{}{
		"EnabledRoutes":      enabledRoutes,
		"DockerRoutes":       dockerRoutes,
		"ProcessGroups":      processGroups,
		"UngroupedProcesses": ungroupedProcesses,
		"DisabledRoutes":     otherDisabledRoutes,
		"WellKnownRoutes":    wellKnownRoutes,
		"InactiveWellKnown":  inactiveWellKnown,
		"UnroutedContainers": unroutedContainers,
		"SelectedSubdomain":  selectedSubdomain,
		"SelectedRoute":      selectedRoute,
		"SelectedLogs":       selectedLogs,
		"SelectedPorts":      portRepr,
		"SelectedStats":      selectedStats,
	})
}

func (s *DashboardServer) serveLogsPreview(w http.ResponseWriter, r *http.Request) {
	s.routesMu.RLock()
	logsMap := make(map[string][]string)
	for _, route := range s.routes {
		var buffer *LogBuffer
		if route.Source == discovery.RouteSourceDocker && route.DockerContainerID != "" {
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

// TODO: use the existing log manager functionality for this.
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

	if route.Source == discovery.RouteSourceDocker && route.DockerContainerID != "" {
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
	} else {
		http.Error(w, "no logs available for this service", http.StatusBadRequest)
		return
	}

	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if route.Source == discovery.RouteSourceDocker && len(line) > 8 {
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

func (s *DashboardServer) serveStats(w http.ResponseWriter, r *http.Request) {
	if s.statsScraper == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}

	stats := s.statsScraper.GetClusterStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
