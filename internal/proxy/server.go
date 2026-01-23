package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xetera/localproxy/internal/certs"
)

type Server struct {
	httpServer  *http.Server
	httpsServer *http.Server
	routes      map[string]Route
	routesMu    sync.RWMutex
	certMgr     *certs.CertManager
}

func NewServer(certMgr *certs.CertManager) *Server {
	s := &Server{
		routes:  make(map[string]Route),
		certMgr: certMgr,
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

	s.routesMu.RLock()
	route, ok := s.routes[subdomain]
	s.routesMu.RUnlock()

	if !ok {
		http.Error(w, fmt.Sprintf("no route for subdomain: %s", subdomain), http.StatusBadGateway)
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
