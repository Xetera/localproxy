package registry

import (
	"fmt"
	"log"
	"net/netip"
	"sync"

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
	onChange     func([]proxy.Route)
}

func NewRouteRegistry(onChange func([]proxy.Route), store *Store) *RouteRegistry {
	return &RouteRegistry{
		services:     make(map[string]discovery.DiscoveredService),
		folderGroups: make(map[string][]discovery.DiscoveredService),
		store:        store,
		onChange:     onChange,
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

func (r *RouteRegistry) GetRoutes() []proxy.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getRoutesLocked()
}

func (r *RouteRegistry) getRoutesLocked() []proxy.Route {
	var routes []proxy.Route
	dashboardEndpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), proxy.ServerPort)
	routes = append(routes, proxy.Route{
		Subdomain: "",
		Endpoint:  dashboardEndpoint,
		PID:       0,
		Source:    discovery.RouteSourceWellKnown,
	})

	for folderName, services := range r.folderGroups {
		if len(services) >= 2 && !reservedFolders[folderName] {
			routes = append(routes, proxy.Route{
				Subdomain:   folderName,
				Endpoint:    dashboardEndpoint,
				Source:      discovery.RouteSourceProcess,
				HasWildcard: true,
				FolderGroup: folderName,
			})
		}
	}

	for _, svc := range r.services {
		route := proxy.Route{
			Subdomain: svc.Subdomain,
			Endpoint:  svc.Endpoint,
			TCPPort:   svc.TCPPort,
			Source:    svc.Source,
		}

		if svc.Process != nil {
			route.PID = svc.Process.PID
			route.Cwd = svc.Process.Cwd
			route.Disabled = svc.Process.Disabled
			route.NeedsCustomMapping = svc.Process.NeedsCustomMapping
			route.IsDocker = svc.Process.IsDocker
			route.TopLevelFolder = svc.Process.TopLevelFolder
			route.RelativePath = svc.Process.RelativePath
			topFolder := svc.Process.TopLevelFolder
			if topFolder != "" && len(r.folderGroups[topFolder]) >= 2 && !reservedFolders[topFolder] {
				route.FolderGroup = topFolder
			}
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
