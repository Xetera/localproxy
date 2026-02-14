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

var reservedFolders = map[string]bool{
	"localproxy": true,
	"proxy":      true,
}

type FolderGroup struct {
	Name     string
	Services []discovery.DiscoveredService
}

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

func (r *RouteRegistry) UpdateServices(source discovery.RouteSource, services []discovery.DiscoveredService) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key, svc := range r.services {
		if svc.Source == source {
			delete(r.services, key)
		}
	}

	if source == discovery.RouteSourceProcess {
		r.folderGroups = make(map[string][]discovery.DiscoveredService)
	}

	for _, svc := range services {
		if svc.Process != nil && svc.Process.TopLevelFolder != "" {
			r.folderGroups[svc.Process.TopLevelFolder] = append(
				r.folderGroups[svc.Process.TopLevelFolder],
				svc,
			)
		}
	}

	for _, svc := range services {
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

		needsMapping := svc.Process != nil && svc.Process.NeedsCustomMapping
		if svc.Process != nil && svc.Process.TopLevelFolder != "" {
			folderServices := r.folderGroups[svc.Process.TopLevelFolder]
			if len(folderServices) >= 2 && !reservedFolders[svc.Process.TopLevelFolder] {
				needsMapping = true
			}
		}

		if needsMapping {
			if r.store != nil {
				if mapping, err := r.store.GetMappingByCwd(svc.Process.Cwd); err == nil {
					subdomain = mapping.Subdomain + "." + mapping.FolderGroup
					svc.Process.Disabled = false
					svc.Process.NeedsCustomMapping = false
				} else {
					subdomain = fmt.Sprintf("pid-%d", svc.Process.PID)
					svc.Process.Disabled = true
					svc.Process.NeedsCustomMapping = true
				}
			} else {
				subdomain = fmt.Sprintf("pid-%d", svc.Process.PID)
				svc.Process.Disabled = true
				svc.Process.NeedsCustomMapping = true
			}
		}

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

	for folderName, services := range r.folderGroups {
		if len(services) >= 2 && !reservedFolders[folderName] {
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
			topFolder := svc.Process.TopLevelFolder
			if topFolder != "" && len(r.folderGroups[topFolder]) >= 2 && !reservedFolders[topFolder] {
				route.FolderGroup = topFolder
				backend.FolderGroup = topFolder
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
		result[k] = append([]discovery.DiscoveredService{}, v...)
	}
	return result
}

func (r *RouteRegistry) RefreshRoutes() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notifyChange()
}
