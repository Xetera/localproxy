package registry

import (
	"sync"

	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/proxy"
)

type RouteRegistry struct {
	dockerRoutes     map[string]proxy.Route
	processRoutes    map[string]proxy.Route
	wellKnownRoutes  map[string]proxy.Route
	mu               sync.RWMutex
	onChange         func([]proxy.Route)
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
		r.dockerRoutes[c.Subdomain] = proxy.Route{
			Subdomain: c.Subdomain,
			Host:      c.IP,
			Port:      c.Port,
			Source:    proxy.RouteSourceDocker,
		}
	}

	r.notifyChange()
}

func (r *RouteRegistry) UpdateProcesses(processes []discovery.ListeningProcess) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.processRoutes = make(map[string]proxy.Route)
	for _, p := range processes {
		r.processRoutes[p.Subdomain] = proxy.Route{
			Subdomain: p.Subdomain,
			Host:      "localhost",
			Port:      p.Port,
			PID:       p.PID,
			Cwd:       p.Cwd,
			Disabled:  p.Disabled,
			Source:    proxy.RouteSourceProcess,
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
			Host:      "localhost",
			Port:      p.Port,
			PID:       p.PID,
			Source:    proxy.RouteSourceWellKnown,
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
	for k, v := range r.wellKnownRoutes {
		merged[k] = v
	}
	for k, v := range r.dockerRoutes {
		merged[k] = v
	}
	for k, v := range r.processRoutes {
		merged[k] = v
	}

	var routes []proxy.Route
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
