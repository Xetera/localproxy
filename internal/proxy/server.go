package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/xetera/localproxy/internal/certs"
	"github.com/xetera/localproxy/internal/discovery"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	httpServer  *http.Server
	httpsServer *http.Server
	tcpProxy    *TCPProxy
	routes      map[string]Route
	routesMu    sync.RWMutex
	certMgr     *certs.CertManager
	logManager  *LogManager
}

func NewServer(certMgr *certs.CertManager) *Server {
	s := &Server{
		routes:     make(map[string]Route),
		certMgr:    certMgr,
		logManager: NewLogManager(),
		tcpProxy:   NewTCPProxy(),
	}

	handler := http.HandlerFunc(s.handleRequest)

	s.httpServer = &http.Server{
		Addr:         ":80",
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if certMgr != nil {
		tlsConfig := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
			GetCertificate: certMgr.GetCertificate,
		}

		s.httpsServer = &http.Server{
			Addr:         ":443",
			Handler:      handler,
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			ErrorLog:     log.New(io.Discard, "", 0),
		}
	}

	return s
}

func (s *Server) UpdateRoutes(routes []Route) {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()

	s.routes = make(map[string]Route)
	for _, r := range routes {
		s.routes[r.Subdomain] = r
	}

	go s.logManager.UpdateRoutes(routes)
	go s.tcpProxy.UpdateRoutes(routes)
}

func (s *Server) Start() error {
	errCh := make(chan error, 2)

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	if s.httpsServer != nil {
		go func() {
			ln, err := tls.Listen("tcp", ":443", s.httpsServer.TLSConfig)
			if err != nil {
				errCh <- fmt.Errorf("https listener: %w", err)
				return
			}
			if err := s.httpsServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("https server: %w", err)
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.logManager.Stop()
	s.tcpProxy.Stop()

	var errs []error
	if err := s.httpServer.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	subdomain := s.extractSubdomain(r.Host)
	if subdomain == "" {
		http.Error(w, "no subdomain specified", http.StatusBadRequest)
		return
	}

	if subdomain == "proxy" {
		if r.URL.Path == "/logs" {
			s.serveLogs(w, r)
			return
		}
		if r.URL.Path == "/api/logs-preview" {
			s.serveLogsPreview(w, r)
			return
		}
		s.serveDashboard(w, r)
		return
	}

	s.routesMu.RLock()
	route, ok := s.routes[subdomain]
	s.routesMu.RUnlock()

	if !ok {
		http.Error(w, fmt.Sprintf("no route for subdomain: %s", subdomain), http.StatusBadGateway)
		return
	}

	if route.Disabled {
		http.Error(w, fmt.Sprintf("route %s is disabled (outside base path)", subdomain), http.StatusForbidden)
		return
	}

	target := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(route.Host, fmt.Sprintf("%d", route.Port)),
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = r.Host
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
}

type RouteWithLogs struct {
	Route
	RecentLogs []string
}

func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
	s.routesMu.RLock()
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

	sort.Slice(enabledRoutes, func(i, j int) bool {
		return enabledRoutes[i].Subdomain < enabledRoutes[j].Subdomain
	})
	sort.Slice(disabledRoutes, func(i, j int) bool {
		return disabledRoutes[i].Subdomain < disabledRoutes[j].Subdomain
	})
	sort.Slice(wellKnownRoutes, func(i, j int) bool {
		return wellKnownRoutes[i].Subdomain < wellKnownRoutes[j].Subdomain
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

	tmpl, err := template.ParseFS(templateFS, "templates/dashboard.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
		return
	}

	logsMap := make(map[string][]string)
	for _, r := range enabledRoutes {
		logsMap[r.Subdomain] = r.RecentLogs
	}
	for _, r := range wellKnownRoutes {
		logsMap[r.Subdomain] = r.RecentLogs
	}

	logsJSON, _ := json.Marshal(logsMap)

	routesMap := make(map[string]Route)
	for _, r := range enabledRoutes {
		routesMap[r.Subdomain] = r.Route
	}
	for _, r := range wellKnownRoutes {
		routesMap[r.Subdomain] = r.Route
	}
	routesJSON, _ := json.Marshal(routesMap)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, map[string]interface{}{
		"EnabledRoutes":     enabledRoutes,
		"DisabledRoutes":    disabledRoutes,
		"WellKnownRoutes":   wellKnownRoutes,
		"InactiveWellKnown": inactiveWellKnown,
		"LogsMapJSON":       template.JS(logsJSON),
		"RoutesJSON":        template.JS(routesJSON),
	})
}

func (s *Server) serveLogsPreview(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) serveLogs(w http.ResponseWriter, r *http.Request) {
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

	tmpl, err := template.ParseFS(templateFS, "templates/logs.html")
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

func (s *Server) streamLogs(w http.ResponseWriter, r *http.Request, subdomain string) {
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

func (s *Server) extractSubdomain(host string) string {
	host = strings.Split(host, ":")[0]

	if !strings.HasSuffix(host, ".localhost") {
		return ""
	}

	subdomain := strings.TrimSuffix(host, ".localhost")
	if subdomain == "" {
		return ""
	}

	return subdomain
}
