package registry

import (
	"fmt"
	"log"
	"sync"

	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/proxy"
)

type RouteRegistry struct {
	services map[string]discovery.DiscoveredService
	mu       sync.RWMutex
	onChange func([]proxy.Route)
}

func NewRouteRegistry(onChange func([]proxy.Route)) *RouteRegistry {
	return &RouteRegistry{
		services: make(map[string]discovery.DiscoveredService),
		onChange: onChange,
	}
}

func (r *RouteRegistry) SetOnChange(fn func([]proxy.Route)) {
	r.onChange = fn
}

func (r *RouteRegistry) UpdateServices(source discovery.RouteSource, services []discovery.DiscoveredService) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key, svc := range r.services {
		if svc.Source == source {
			delete(r.services, key)
		}
	}

	for _, svc := range services {
		subdomain := svc.Subdomain
		if svc.Process != nil && svc.Process.NeedsCustomMapping {
			subdomain = fmt.Sprintf("pid-%d", svc.Process.PID)
		}

		existing, exists := r.services[subdomain]
		if exists && r.priority(existing.Source) > r.priority(svc.Source) {
			continue
		}

		svc.Subdomain = subdomain
		r.services[subdomain] = svc
		log.Printf("registry: %s route %s -> %s:%d protocol=%s", svc.Source, subdomain, svc.IP, svc.Port, func() string {
			if svc.Service != nil {
				return svc.Service.Protocol
			}
			return ""
		}())
	}

	r.notifyChange()
}

func (r *RouteRegistry) priority(source discovery.RouteSource) int {
	switch source {
	case discovery.RouteSourceFile:
		return 4
	case discovery.RouteSourceProcess:
		return 3
	case discovery.RouteSourceDocker:
		return 2
	case discovery.RouteSourceWellKnown:
		return 1
	default:
		return 0
	}
}

func (r *RouteRegistry) GetRoutes() []proxy.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getRoutesLocked()
}

func (r *RouteRegistry) getRoutesLocked() []proxy.Route {
	var routes []proxy.Route
	routes = append(routes, proxy.Route{
		Subdomain: "",
		Host:      "127.0.0.1",
		Port:      proxy.ServerPort,
		PID:       0,
		Source:    discovery.RouteSourceWellKnown,
	})

	for _, svc := range r.services {
		route := proxy.Route{
			Subdomain: svc.Subdomain,
			Host:      svc.IP,
			Port:      svc.Port,
			TCPPort:   svc.TCPPort,
			Source:    svc.Source,
		}

		if svc.Process != nil {
			route.PID = svc.Process.PID
			route.Cwd = svc.Process.Cwd
			route.Disabled = svc.Process.Disabled
			route.NeedsCustomMapping = svc.Process.NeedsCustomMapping
			route.IsDocker = svc.Process.IsDocker
		}

		if svc.Docker != nil {
			route.DockerContainerID = svc.Docker.ID
			route.DockerHasAutoName = !svc.Docker.HasCustomName
			route.DockerPorts = svc.Docker.Ports
		}

		if svc.Service != nil {
			route.ServiceProtocol = svc.Service.Protocol
		}

		routes = append(routes, route)
	}

	return routes
}

func (r *RouteRegistry) notifyChange() {
	if r.onChange != nil {
		routes := r.getRoutesLocked()
		r.onChange(routes)
	}
}

func (r *RouteRegistry) UpdateService(svc discovery.DiscoveredService) {
	r.mu.Lock()
	defer r.mu.Unlock()

	subdomain := svc.Subdomain
	existing, exists := r.services[subdomain]
	if exists && r.priority(existing.Source) > r.priority(svc.Source) {
		return
	}

	r.services[subdomain] = svc
	log.Printf("registry: %s route %s -> %s:%d protocol=%s", svc.Source, subdomain, svc.IP, svc.Port, func() string {
		if svc.Service != nil {
			return svc.Service.Protocol
		}
		return ""
	}())

	r.notifyChange()
}
