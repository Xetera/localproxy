package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/pkg/tshark"
)

const (
	ServerPort = 13279
)

func getTemplatesPath() string {
	paths := []string{
		"templates",
		"internal/dashboard/templates",
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

	return "internal/dashboard/templates"
}

type UnroutedContainer struct {
	ID     string
	Name   string
	Reason string
}

type FolderGroupInfo struct {
	Name     string
	Services []FolderGroupService
}

type FolderGroupService struct {
	PID          int
	Port         uint16
	Cwd          string
	RelativePath string
	Subdomain    string
	IsMapped     bool
}

type RegistryInterface interface {
	GetFolderGroups() map[string][]discovery.DiscoveredService
	RefreshRoutes()
}

type MappingInfo struct {
	Subdomain string
	Cwd       string
}

type StoreInterface interface {
	AddSubdomainMappingData(folderGroup, subdomain, cwd string) error
	RemoveSubdomainMapping(cwd string) error
	GetMappingSubdomainsByCwd(folderGroup string) (map[string]string, error)
}

type PacketSource interface {
	PacketBuffer(endpoint netip.AddrPort) *tshark.PacketBuffer
}

type DashboardServer struct {
	server             *http.Server
	backends           map[string]Backend
	backendsMu         sync.RWMutex
	logManager         *LogManager
	basePaths          []string
	unroutedContainers []UnroutedContainer
	registry           RegistryInterface
	store              StoreInterface
	packetSource       PacketSource
	packetRowTmpl      *template.Template
	packetDetailTmpl   *template.Template
}

func NewDashboardServer(basePaths []string, traceProcessLogs bool) *DashboardServer {
	templatesPath := getTemplatesPath()
	packetRowTmpl := template.Must(template.ParseFiles(filepath.Join(templatesPath, "packet_row.html")))
	packetDetailTmpl := template.Must(template.ParseFiles(filepath.Join(templatesPath, "packet_detail.html")))

	s := &DashboardServer{
		backends:         make(map[string]Backend),
		logManager:       NewLogManager(traceProcessLogs),
		basePaths:        basePaths,
		packetRowTmpl:    packetRowTmpl,
		packetDetailTmpl: packetDetailTmpl,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/logs", s.serveLogs)
	mux.HandleFunc("/api/logs-preview", s.serveLogsPreview)
	mux.HandleFunc("/api/subdomain-mapping", s.handleSubdomainMapping)
	mux.HandleFunc("/api/packets", s.servePackets)
	mux.HandleFunc("/api/packet-detail", s.servePacketDetail)

	s.server = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", ServerPort),
		Handler: mux,
	}

	return s
}

func (s *DashboardServer) SetPacketSource(ps PacketSource) {
	s.packetSource = ps
}

func (s *DashboardServer) SetRegistry(registry RegistryInterface) {
	s.registry = registry
}

func (s *DashboardServer) SetStore(store StoreInterface) {
	s.store = store
}

func (s *DashboardServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	if host == "localhost" || host == "internal" || host == fmt.Sprintf("127.0.0.1:%d", ServerPort) || host == fmt.Sprintf("localhost:%d", ServerPort) {
		s.serveDashboard(w, r)
		return
	}

	if folder := s.detectFolderGroup(host); folder != "" {
		s.serveCaptivePortal(w, r, folder)
		return
	}

	s.serve404(w, r, host)
}

func (s *DashboardServer) detectFolderGroup(host string) string {
	if s.registry == nil {
		return ""
	}

	host = strings.Split(host, ":")[0]

	var folderName string
	if strings.HasSuffix(host, ".localhost") {
		subdomain := strings.TrimSuffix(host, ".localhost")
		parts := strings.Split(subdomain, ".")
		if len(parts) >= 1 {
			folderName = parts[len(parts)-1]
		}
	} else if strings.HasSuffix(host, ".internal") {
		subdomain := strings.TrimSuffix(host, ".internal")
		parts := strings.Split(subdomain, ".")
		if len(parts) >= 1 {
			folderName = parts[len(parts)-1]
		}
	}

	if folderName == "" {
		return ""
	}

	folderGroups := s.registry.GetFolderGroups()
	if _, exists := folderGroups[folderName]; exists {
		return folderName
	}

	return ""
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

func (s *DashboardServer) UpdateBackends(backends []Backend) {
	s.backendsMu.Lock()
	defer s.backendsMu.Unlock()

	s.backends = make(map[string]Backend)
	for _, b := range backends {
		s.backends[b.Subdomain] = b
	}

	go s.logManager.UpdateBackends(backends)
}

func (s *DashboardServer) UpdateUnroutedContainers(containers []UnroutedContainer) {
	s.backendsMu.Lock()
	defer s.backendsMu.Unlock()
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

type BackendWithLogs struct {
	Backend
	RecentLogs  []string
	DisplayPath string
}

type ProcessGroup struct {
	Cwd        string
	DisplayCwd string
	Backends   []BackendWithLogs
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

	s.backendsMu.RLock()
	basePaths := s.basePaths
	unroutedContainers := s.unroutedContainers
	var enabledBackends, disabledBackends, wellKnownBackends []BackendWithLogs
	for _, backend := range s.backends {
		backendWithLogs := BackendWithLogs{
			Backend:    backend,
			RecentLogs: []string{},
		}
		if backend.Source == discovery.RouteSourceDocker && backend.DockerContainerID != "" {
			buffer := s.logManager.GetBufferByContainerID(backend.DockerContainerID)
			backendWithLogs.RecentLogs = buffer.GetLines()
		} else if backend.PID > 0 {
			buffer := s.logManager.GetBufferByPID(backend.PID)
			backendWithLogs.RecentLogs = buffer.GetLines()
		}

		if backend.Disabled {
			disabledBackends = append(disabledBackends, backendWithLogs)
		} else if backend.Source == discovery.RouteSourceWellKnown {
			wellKnownBackends = append(wellKnownBackends, backendWithLogs)
		} else {
			enabledBackends = append(enabledBackends, backendWithLogs)
		}
	}
	s.backendsMu.RUnlock()

	var dockerBackends, processBackends []BackendWithLogs
	for _, b := range enabledBackends {
		if b.Source == discovery.RouteSourceDocker {
			dockerBackends = append(dockerBackends, b)
		} else {
			processBackends = append(processBackends, b)
		}
	}
	for _, b := range disabledBackends {
		if b.Source == discovery.RouteSourceProcess {
			processBackends = append(processBackends, b)
		}
	}

	sort.Slice(dockerBackends, func(i, j int) bool {
		return dockerBackends[i].Subdomain < dockerBackends[j].Subdomain
	})
	sort.Slice(processBackends, func(i, j int) bool {
		return processBackends[i].Subdomain < processBackends[j].Subdomain
	})
	sort.Slice(disabledBackends, func(i, j int) bool {
		return disabledBackends[i].Subdomain < disabledBackends[j].Subdomain
	})
	var otherDisabledBackends []BackendWithLogs
	for _, b := range disabledBackends {
		if b.Source != discovery.RouteSourceProcess {
			otherDisabledBackends = append(otherDisabledBackends, b)
		}
	}

	for i := range processBackends {
		processBackends[i].DisplayPath = trimBasePath(processBackends[i].Cwd, basePaths)
	}

	sort.Slice(wellKnownBackends, func(i, j int) bool {
		return wellKnownBackends[i].Subdomain < wellKnownBackends[j].Subdomain
	})

	type backendWithDisplayCwd struct {
		backend    BackendWithLogs
		displayCwd string
	}
	var processBackendsWithDisplay []backendWithDisplayCwd
	displayCwdCounts := make(map[string]int)
	for _, b := range processBackends {
		trimmed := trimBasePath(b.Cwd, basePaths)
		displayCwd := trimmed
		if idx := strings.Index(trimmed, "/"); idx != -1 {
			displayCwd = trimmed[:idx]
		}
		processBackendsWithDisplay = append(processBackendsWithDisplay, backendWithDisplayCwd{
			backend:    b,
			displayCwd: displayCwd,
		})
		if displayCwd != "" {
			displayCwdCounts[displayCwd]++
		}
	}

	var processGroups []ProcessGroup
	groupedDisplayCwds := make(map[string]bool)
	var ungroupedProcesses []BackendWithLogs

	for _, b := range processBackendsWithDisplay {
		if b.displayCwd != "" && displayCwdCounts[b.displayCwd] > 1 {
			if !groupedDisplayCwds[b.displayCwd] {
				groupedDisplayCwds[b.displayCwd] = true
				var groupBackends []BackendWithLogs
				for _, pb := range processBackendsWithDisplay {
					if pb.displayCwd == b.displayCwd {
						groupBackends = append(groupBackends, pb.backend)
					}
				}
				processGroups = append(processGroups, ProcessGroup{
					Cwd:        b.backend.Cwd,
					DisplayCwd: b.displayCwd,
					Backends:   groupBackends,
				})
			}
		} else {
			ungroupedProcesses = append(ungroupedProcesses, b.backend)
		}
	}

	sort.Slice(processGroups, func(i, j int) bool {
		return processGroups[i].Cwd < processGroups[j].Cwd
	})

	activeWellKnown := make(map[string]bool)
	for _, b := range wellKnownBackends {
		activeWellKnown[b.Subdomain] = true
	}

	allWellKnown := discovery.GetAllWellKnownPorts()
	var inactiveWellKnown []discovery.WellKnownPort
	for _, wk := range allWellKnown {
		if !activeWellKnown[wk.Subdomain] {
			inactiveWellKnown = append(inactiveWellKnown, wk)
		}
	}

	selectedSubdomain := r.URL.Query().Get("service")

	var selectedBackend *BackendWithLogs
	var selectedLogs []string

	allBackends := append(append(append([]BackendWithLogs{}, dockerBackends...), ungroupedProcesses...), wellKnownBackends...)
	for _, g := range processGroups {
		allBackends = append(allBackends, g.Backends...)
	}

	type PortRepr struct {
		Port     uint16
		Text     string
		Protocol string
	}

	var portRepr []PortRepr
	for i := range allBackends {
		if allBackends[i].Subdomain == selectedSubdomain {
			selectedBackend = &allBackends[i]
			selectedLogs = allBackends[i].RecentLogs
			if len(selectedBackend.DockerPorts) > 0 {
				type portInfo struct {
					udp             bool
					tcp             bool
					serviceProtocol string
				}
				portsByNumber := make(map[uint16]*portInfo)
				for _, p := range selectedBackend.DockerPorts {
					port := p.Endpoint.Port()
					if portsByNumber[port] == nil {
						portsByNumber[port] = &portInfo{}
					}
					info := portsByNumber[port]
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

	templatesPath := getTemplatesPath()
	funcMap := template.FuncMap{
		"add":  func(a, b int) int { return a + b },
		"port": func(endpoint netip.AddrPort) uint16 { return endpoint.Port() },
	}
	tmpl := template.Must(template.New("dashboard.html").Funcs(funcMap).ParseFiles(filepath.Join(templatesPath, "dashboard.html")))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, map[string]any{
		"TraceProcessLogs":   s.logManager.traceProcessLogs,
		"EnabledBackends":    enabledBackends,
		"DockerBackends":     dockerBackends,
		"ProcessGroups":      processGroups,
		"UngroupedProcesses": ungroupedProcesses,
		"DisabledBackends":   otherDisabledBackends,
		"WellKnownBackends":  wellKnownBackends,
		"InactiveWellKnown":  inactiveWellKnown,
		"UnroutedContainers": unroutedContainers,
		"SelectedSubdomain":  selectedSubdomain,
		"SelectedBackend":    selectedBackend,
		"SelectedLogs":       selectedLogs,
		"SelectedPorts":      portRepr,
	}); err != nil {
		log.Printf("template error: %v", err)
	}
}

func (s *DashboardServer) serveLogsPreview(w http.ResponseWriter, r *http.Request) {
	s.backendsMu.RLock()
	logsMap := make(map[string][]string)
	for _, backend := range s.backends {
		var buffer *LogBuffer
		if backend.Source == discovery.RouteSourceDocker && backend.DockerContainerID != "" {
			buffer = s.logManager.GetBufferByContainerID(backend.DockerContainerID)
		} else if backend.PID > 0 {
			buffer = s.logManager.GetBufferByPID(backend.PID)
		}

		if buffer != nil {
			logs := buffer.GetLines()
			logsMap[backend.Subdomain] = logs
		}
	}
	s.backendsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logsMap)
}

func (s *DashboardServer) serveLogs(w http.ResponseWriter, r *http.Request) {
	subdomain := r.URL.Query().Get("subdomain")
	if subdomain == "" {
		http.Error(w, "subdomain parameter required", http.StatusBadRequest)
		return
	}

	s.backendsMu.RLock()
	backend, exists := s.backends[subdomain]
	s.backendsMu.RUnlock()

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
		"Subdomain": backend.Subdomain,
		"PID":       backend.PID,
		"Port":      backend.Endpoint.Port(),
		"Cwd":       backend.Cwd,
	})
}

func (s *DashboardServer) streamLogs(w http.ResponseWriter, r *http.Request, subdomain string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	s.backendsMu.RLock()
	backend, exists := s.backends[subdomain]
	s.backendsMu.RUnlock()

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

	if backend.Source == discovery.RouteSourceDocker && backend.DockerContainerID != "" {
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

		reader, err = s.logManager.dockerClient.ContainerLogs(r.Context(), backend.DockerContainerID, options)
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
		if backend.Source == discovery.RouteSourceDocker && len(line) > 8 {
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

func (s *DashboardServer) serveCaptivePortal(w http.ResponseWriter, r *http.Request, folder string) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	folderGroups := s.registry.GetFolderGroups()
	services, exists := folderGroups[folder]
	if !exists {
		s.serve404(w, r, r.Host)
		return
	}

	mappingByCwd := make(map[string]string)
	if s.store != nil {
		var err error
		mappingByCwd, err = s.store.GetMappingSubdomainsByCwd(folder)
		if err != nil {
			log.Printf("captive portal: failed to get mappings: %v", err)
			mappingByCwd = make(map[string]string)
		}
	}

	var folderServices []FolderGroupService
	for _, svc := range services {
		if svc.Process == nil {
			continue
		}
		fgs := FolderGroupService{
			PID:          svc.Process.PID,
			Port:         svc.Endpoint.Port(),
			Cwd:          svc.Process.Cwd,
			RelativePath: svc.Process.RelativePath,
		}
		if subdomain, ok := mappingByCwd[svc.Process.Cwd]; ok {
			fgs.Subdomain = subdomain
			fgs.IsMapped = true
		}
		folderServices = append(folderServices, fgs)
	}

	templatesPath := getTemplatesPath()
	tmpl, err := template.ParseFiles(filepath.Join(templatesPath, "captive.html"))
	if err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, map[string]any{
		"Folder":   folder,
		"Services": folderServices,
	}); err != nil {
		log.Printf("captive portal template error: %v", err)
	}
}

func (s *DashboardServer) handleSubdomainMapping(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.addSubdomainMapping(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		s.removeSubdomainMapping(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *DashboardServer) addSubdomainMapping(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "store not configured", http.StatusInternalServerError)
		return
	}

	var req struct {
		FolderGroup string `json:"folder_group"`
		Subdomain   string `json:"subdomain"`
		Cwd         string `json:"cwd"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Subdomain == "" || req.Cwd == "" || req.FolderGroup == "" {
		http.Error(w, "subdomain, cwd, and folder_group are required", http.StatusBadRequest)
		return
	}

	if !isValidSubdomain(req.Subdomain) {
		http.Error(w, "invalid subdomain format", http.StatusBadRequest)
		return
	}

	if err := s.store.AddSubdomainMappingData(req.FolderGroup, req.Subdomain, req.Cwd); err != nil {
		http.Error(w, fmt.Sprintf("failed to save mapping: %v", err), http.StatusInternalServerError)
		return
	}

	if s.registry != nil {
		s.registry.RefreshRoutes()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *DashboardServer) removeSubdomainMapping(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "store not configured", http.StatusInternalServerError)
		return
	}

	cwd := r.URL.Query().Get("cwd")
	if cwd == "" {
		http.Error(w, "cwd parameter required", http.StatusBadRequest)
		return
	}

	if err := s.store.RemoveSubdomainMapping(cwd); err != nil {
		http.Error(w, fmt.Sprintf("failed to remove mapping: %v", err), http.StatusInternalServerError)
		return
	}

	if s.registry != nil {
		s.registry.RefreshRoutes()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func isValidSubdomain(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i, c := range s {
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '-' && i > 0 && i < len(s)-1 {
			continue
		}
		return false
	}
	return true
}
