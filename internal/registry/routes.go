package registry

import (
	"fmt"
	"log"
	"maps"
	"sync"

	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/proxy"
)

type RouteRegistry struct {
	dockerRoutes    map[string]proxy.Route
	processRoutes   map[string]proxy.Route
	wellKnownRoutes map[string]proxy.Route
	mu              sync.RWMutex
	onChange        func([]proxy.Route)
}

func NewRouteRegistry() *RouteRegistry {
	return &RouteRegistry{
		dockerRoutes:    make(map[string]proxy.Route),
		processRoutes:   make(map[string]proxy.Route),
		wellKnownRoutes: make(map[string]proxy.Route),
	}
}

func (r *RouteRegistry) SetOnChange(fn func([]proxy.Route)) {
	r.onChange = fn
}

func (r *RouteRegistry) UpdateDockerContainers(containers []discovery.DockerContainer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.dockerRoutes = make(map[string]proxy.Route)
	for _, c := range containers {
		route := proxy.Route{
			Subdomain:         c.Subdomain,
			Host:              c.IP,
			Port:              c.Port,
			TCPPort:           c.TCPPort,
			Source:            proxy.RouteSourceDocker,
			DockerHasAutoName: !c.HasCustomName,
			DockerContainerID: c.ID,
		}
		log.Printf("registry: docker route %s - HasCustomName=%v, DockerHasAutoName=%v, TCPPort=%d", c.Subdomain, c.HasCustomName, route.DockerHasAutoName, c.TCPPort)
		r.dockerRoutes[c.Subdomain] = route
	}

	r.notifyChange()
}

func (r *RouteRegistry) UpdateProcesses(processes []discovery.ListeningProcess) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.processRoutes = make(map[string]proxy.Route)
	for _, p := range processes {
		subdomain := p.Subdomain
		if p.NeedsCustomMapping {
			subdomain = fmt.Sprintf("pid-%d", p.PID)
		}
		r.processRoutes[subdomain] = proxy.Route{
			Subdomain:          subdomain,
			Host:               "127.0.0.1",
			Port:               p.Port,
			PID:                p.PID,
			Cwd:                p.Cwd,
			Disabled:           p.Disabled,
			Source:             proxy.RouteSourceProcess,
			NeedsCustomMapping: p.NeedsCustomMapping,
		}
	}

	r.notifyChange()
}

func (r *RouteRegistry) UpdateWellKnownPorts(ports []discovery.WellKnownProcess) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.wellKnownRoutes = make(map[string]proxy.Route)
	for _, p := range ports {
		r.wellKnownRoutes[p.Subdomain] = proxy.Route{
			Subdomain: p.Subdomain,
			Host:      "127.0.0.1",
			Port:      p.Port,
			TCPPort:   p.TCPPort,
			PID:       p.PID,
			Source:    proxy.RouteSourceWellKnown,
			IsDocker:  p.IsDocker,
		}
	}

	r.notifyChange()
}

func (r *RouteRegistry) GetRoutes() []proxy.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getRoutesLocked()
}

func (r *RouteRegistry) getRoutesLocked() []proxy.Route {
	merged := make(map[string]proxy.Route)
	maps.Copy(merged, r.wellKnownRoutes)
	maps.Copy(merged, r.dockerRoutes)
	maps.Copy(merged, r.processRoutes)

	var routes []proxy.Route
	routes = append(routes, proxy.Route{
		Subdomain: "",
		Host:      "127.0.0.1",
		Port:      proxy.ServerPort,
		PID:       0,
		Source:    proxy.RouteSourceWellKnown,
	})
	for _, v := range merged {
		routes = append(routes, v)
	}
	return routes
}

func (r *RouteRegistry) notifyChange() {
	if r.onChange != nil {
		routes := r.getRoutesLocked()
		r.onChange(routes)
	}
}
