package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/miekg/dns"
)

type Server struct {
	port       int
	gatewayIP  net.IP
	gatewayNet *net.IPNet
	hostIP     net.IP
	upstreamNS []string
	udpServer  *dns.Server
	mu         sync.RWMutex
}

func NewServer(port int, dockerClient *client.Client) (*Server, error) {
	gatewayIP, gatewayNet, err := detectGatewayIP(dockerClient)
	if err != nil {
		return nil, fmt.Errorf("failed to detect docker bridge gateway: %w", err)
	}

	hostIP := detectHostIP()

	upstream := readUpstreamNameservers()
	if len(upstream) == 0 {
		upstream = []string{"8.8.8.8:53", "8.8.4.4:53"}
	}

	log.Printf("dns: gateway IP %s, network %v, host IP %s, upstream nameservers %v", gatewayIP, gatewayNet, hostIP, upstream)

	return &Server{
		port:       port,
		gatewayIP:  gatewayIP,
		gatewayNet: gatewayNet,
		hostIP:     hostIP,
		upstreamNS: upstream,
	}, nil
}

func (s *Server) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	s.udpServer = &dns.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", s.port),
		Net:     "udp",
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.udpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("dns server failed to start: %w", err)
	default:
	}

	log.Printf("dns: server listening on 0.0.0.0:%d", s.port)
	return nil
}

func (s *Server) Stop() {
	if s.udpServer != nil {
		s.udpServer.Shutdown()
	}
}

func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	clientIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		log.Printf("dns: failed to parse client address: %v", err)
		s.handleForward(w, r)
		return
	}

	for _, q := range r.Question {
		name := strings.ToLower(q.Name)
		if s.isInternalDomain(name) {
			s.handleInternal(m, q, net.ParseIP(clientIP))
		} else {
			s.handleForward(w, r)
			return
		}
	}

	w.WriteMsg(m)
}

func (s *Server) isInternalDomain(name string) bool {
	return name == "internal." || strings.HasSuffix(name, ".internal.")
}

func (s *Server) handleInternal(m *dns.Msg, q dns.Question, clientIP net.IP) {
	switch q.Qtype {
	case dns.TypeA:
		s.mu.RLock()
		ip := s.hostIP
		s.mu.RUnlock()

		if ip4 := ip.To4(); ip4 != nil {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: ip4,
			})
		}
	case dns.TypeAAAA:
		// no AAAA for docker bridge
	}
}

func (s *Server) handleForward(w dns.ResponseWriter, r *dns.Msg) {
	c := new(dns.Client)

	for _, ns := range s.upstreamNS {
		resp, _, err := c.Exchange(r, ns)
		if err != nil {
			continue
		}
		w.WriteMsg(resp)
		return
	}

	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	w.WriteMsg(m)
}

func detectGatewayIP(dockerClient *client.Client) (net.IP, *net.IPNet, error) {
	ctx := context.Background()
	bridgeNet, err := dockerClient.NetworkInspect(ctx, "bridge", network.InspectOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to inspect bridge network: %w", err)
	}

	for _, cfg := range bridgeNet.IPAM.Config {
		if cfg.Gateway != "" {
			ip := net.ParseIP(cfg.Gateway)
			if ip != nil {
				if cfg.Subnet != "" {
					_, ipNet, err := net.ParseCIDR(cfg.Subnet)
					if err == nil {
						return ip, ipNet, nil
					}
				}
				return ip, nil, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no gateway found in bridge network IPAM config")
}

func detectHostIP() net.IP {
	ips, err := net.InterfaceAddrs()
	if err != nil {
		return net.ParseIP("0.0.0.0")
	}

	for _, addr := range ips {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				if strings.Contains(ipnet.IP.String(), "10.0.") || strings.Contains(ipnet.IP.String(), "192.168.") {
					return ipnet.IP
				}
			}
		}
	}

	return net.ParseIP("0.0.0.0")
}

func readUpstreamNameservers() []string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Printf("dns: failed to read /etc/resolv.conf: %v", err)
		return nil
	}

	var servers []string
	for _, s := range config.Servers {
		if s == "127.0.0.1" || s == "::1" {
			continue
		}
		servers = append(servers, net.JoinHostPort(s, config.Port))
	}
	return servers
}
