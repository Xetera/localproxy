package registry

import (
	"fmt"
	"log"
	"net/netip"
	"sync"

	"github.com/xetera/localproxy/internal/dashboard"
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/proxy"
)

type RouteRegistry struct {
	services     map[string]discovery.DiscoveredService
	folderGroups map[string][]discovery.DiscoveredService
	store        *Store
	mu           sync.RWMutex
	onChange     func([]proxy.Route, []dashboard.Backend)
}

func NewRouteRegistry(onChange func([]proxy.Route, []dashboard.Backend), store *Store) *RouteRegistry {
	return &RouteRegistry{
		services:     make(map[string]discovery.DiscoveredService),
		folderGroups: make(map[string][]discovery.DiscoveredService),
		store:        store,
		onChange:     onChange,
	}
}

func (r *RouteRegistry) SetOnChange(fn func([]proxy.Route, []dashboard.Backend)) {
	r.onChange = fn
}

func (r *RouteRegistry) isFolderGroup(name string) bool {
	return len(r.folderGroups[name]) >= 2
}

func (r *RouteRegistry) UpdateServices(source discovery.RouteSource, services []discovery.DiscoveredService) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.removeBySource(source)
	if source == discovery.RouteSourceProcess {
		r.rebuildFolderGroups(services)
	}

	for _, svc := range services {
		subdomain := r.resolveSubdomain(&svc)

		existing, exists := r.services[subdomain]
		if exists && r.priority(existing.Source) > r.priority(svc.Source) {
			continue
		}

		svc.Subdomain = subdomain
		r.services[subdomain] = svc
		log.Printf("registry: %s route %s -> %s protocol=%s", svc.Source, subdomain, svc.Endpoint.String(), func() string {
			if svc.Service != nil {
				return svc.Service.Protocol
			}
			return ""
		}())
	}

	r.notifyChange()
}

func (r *RouteRegistry) removeBySource(source discovery.RouteSource) {
	for key, svc := range r.services {
		if svc.Source == source {
			delete(r.services, key)
		}
	}
}

func (r *RouteRegistry) rebuildFolderGroups(services []discovery.DiscoveredService) {
	r.folderGroups = make(map[string][]discovery.DiscoveredService)
	for _, svc := range services {
		if svc.Process != nil && svc.Process.TopLevelFolder != "" {
			folder := svc.Process.TopLevelFolder
			r.folderGroups[folder] = append(r.folderGroups[folder], svc)
		}
	}
}

func (r *RouteRegistry) resolveSubdomain(svc *discovery.DiscoveredService) string {
	subdomain := svc.Subdomain

	if svc.Process != nil {
		switch svc.Source {
		case discovery.RouteSourceProcess:
			subdomain = svc.Process.TopLevelFolder
		case discovery.RouteSourceWellKnown:
			if info, ok := discovery.WellKnownPorts[svc.Endpoint.Port()]; ok {
				subdomain = info.Subdomain
			}
		}
	}

	if !r.needsMapping(svc) {
		return subdomain
	}

	if r.store != nil {
		if mapping, err := r.store.GetMappingByCwd(svc.Process.Cwd); err == nil {
			svc.Process.Disabled = false
			svc.Process.NeedsCustomMapping = false
			return mapping.Subdomain + "." + mapping.FolderGroup
		}
	}

	svc.Process.Disabled = true
	svc.Process.NeedsCustomMapping = true
	return fmt.Sprintf("pid-%d", svc.Process.PID)
}

func (r *RouteRegistry) needsMapping(svc *discovery.DiscoveredService) bool {
	if svc.Process == nil {
		return false
	}
	if svc.Process.NeedsCustomMapping {
		return true
	}
	if svc.Process.TopLevelFolder != "" && r.isFolderGroup(svc.Process.TopLevelFolder) {
		return true
	}
	return false
}

func (r *RouteRegistry) priority(source discovery.RouteSource) int {
	switch source {
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

func (r *RouteRegistry) GetRoutes() ([]proxy.Route, []dashboard.Backend) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getRoutesLocked()
}

func (r *RouteRegistry) getRoutesLocked() ([]proxy.Route, []dashboard.Backend) {
	var routes []proxy.Route
	var backends []dashboard.Backend
	dashboardEndpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), dashboard.ServerPort)

	rootRoute := proxy.Route{
		Subdomain: "",
		Endpoint:  dashboardEndpoint,
	}
	routes = append(routes, rootRoute)
	backends = append(backends, dashboard.Backend{
		Route:  rootRoute,
		Source: discovery.RouteSourceWellKnown,
	})

	for folderName := range r.folderGroups {
		if !r.isFolderGroup(folderName) {
			continue
		}
		folderRoute := proxy.Route{
			Subdomain:   folderName,
			Endpoint:    dashboardEndpoint,
			HasWildcard: true,
			FolderGroup: folderName,
		}
		routes = append(routes, folderRoute)
		backends = append(backends, dashboard.Backend{
			Route:  folderRoute,
			Source: discovery.RouteSourceProcess,
		})
	}

	for _, svc := range r.services {
		route := proxy.Route{
			Subdomain: svc.Subdomain,
			Endpoint:  svc.Endpoint,
			TCPPort:   svc.TCPPort,
		}

		if svc.Service != nil {
			route.ServiceProtocol = svc.Service.Protocol
		}

		backend := dashboard.Backend{
			Route:  route,
			Source: svc.Source,
		}

		if svc.Process != nil {
			backend.PID = svc.Process.PID
			backend.Cwd = svc.Process.Cwd
			backend.Disabled = svc.Process.Disabled
			backend.NeedsCustomMapping = svc.Process.NeedsCustomMapping
			backend.TopLevelFolder = svc.Process.TopLevelFolder
			backend.RelativePath = svc.Process.RelativePath
			if svc.Process.TopLevelFolder != "" && r.isFolderGroup(svc.Process.TopLevelFolder) {
				route.FolderGroup = svc.Process.TopLevelFolder
				backend.FolderGroup = svc.Process.TopLevelFolder
			}
		}

		if svc.Docker != nil {
			backend.IsDocker = true
			backend.DockerContainerID = svc.Docker.ID
			backend.DockerHasAutoName = !svc.Docker.HasCustomName
			backend.DockerPorts = svc.Docker.Ports
		}

		routes = append(routes, route)
		backends = append(backends, backend)
	}

	return routes, backends
}

func (r *RouteRegistry) notifyChange() {
	if r.onChange != nil {
		routes, backends := r.getRoutesLocked()
		r.onChange(routes, backends)
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
	log.Printf("registry: %s route %s -> %s protocol=%s", svc.Source, subdomain, svc.Endpoint, func() string {
		if svc.Service != nil {
			return svc.Service.Protocol
		}
		return ""
	}())

	r.notifyChange()
}

func (r *RouteRegistry) GetFolderGroups() map[string][]discovery.DiscoveredService {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string][]discovery.DiscoveredService)
	for k, v := range r.folderGroups {
		if r.isFolderGroup(k) {
			result[k] = append([]discovery.DiscoveredService{}, v...)
		}
	}
	return result
}

func (r *RouteRegistry) RefreshRoutes() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notifyChange()
}
