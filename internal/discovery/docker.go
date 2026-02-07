package discovery

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	LabelDomain  = "localproxy.subdomain"
	LabelPort    = "localproxy.port"
	LabelTCPPort = "localproxy.tcpport"
)

type UnroutedContainer struct {
	ID     string
	Name   string
	Reason string
}

type DockerWatcher struct {
	client            *client.Client
	onChange          func([]DiscoveredService)
	onHealthy         func(DiscoveredService)
	onUnroutedChanged func([]UnroutedContainer)
	ctx               context.Context
	cancel            context.CancelFunc
}

func NewDockerWatcher() (*DockerWatcher, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &DockerWatcher{
		client: cli,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (w *DockerWatcher) SetOnChange(fn func([]DiscoveredService)) {
	w.onChange = fn
}

func (w *DockerWatcher) SetOnHealthy(fn func(DiscoveredService)) {
	w.onHealthy = fn
}

func (w *DockerWatcher) SetOnUnroutedChanged(fn func([]UnroutedContainer)) {
	w.onUnroutedChanged = fn
}

func (w *DockerWatcher) Start() error {
	containers, unrouted, err := w.listContainers()
	if err != nil {
		return err
	}
	if w.onChange != nil {
		w.onChange(containers)
	}
	if w.onUnroutedChanged != nil {
		w.onUnroutedChanged(unrouted)
	}

	go w.watchEvents()
	return nil
}

func (w *DockerWatcher) Stop() {
	w.cancel()
	w.client.Close()
}

func (w *DockerWatcher) listContainers() ([]DiscoveredService, []UnroutedContainer, error) {
	containers, err := w.client.ContainerList(w.ctx, container.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	var result []DiscoveredService
	var unrouted []UnroutedContainer
	for _, c := range containers {
		dc, reason := w.parseContainer(c)
		if dc != nil {
			result = append(result, *dc)
		} else if reason != "" {
			name := ""
			if len(c.Names) > 0 {
				name = strings.TrimPrefix(c.Names[0], "/")
			}
			unrouted = append(unrouted, UnroutedContainer{
				ID:     c.ID,
				Name:   name,
				Reason: reason,
			})
		}
	}
	return result, unrouted, nil
}

func (w *DockerWatcher) parseContainer(c container.Summary) (*DiscoveredService, string) {
	if len(c.Names) == 0 {
		return nil, ""
	}

	name := strings.TrimPrefix(c.Names[0], "/")

	hasCustomName := true
	parts := strings.Split(name, "_")
	if len(parts) == 2 && !strings.Contains(name, "-") {
		hasCustomName = false
	}
	log.Printf("docker: container %s hasCustomName=%v", name, hasCustomName)

	subdomain, ok := c.Labels[LabelDomain]
	if !ok || subdomain == "" {
		subdomain = name
	}

	var port int
	var tcpPort int
	var ip string

	for _, net := range c.NetworkSettings.Networks {
		if net.IPAddress != "" {
			ip = net.IPAddress
			break
		}
	}
	if ip == "" {
		ip = "127.0.0.1"
	}

	var allPorts []DockerListener
	for _, p := range c.Ports {
		dp := DockerListener{
			PrivatePort: int(p.PrivatePort),
			Type:        p.Type,
		}
		var portValue uint16
		if p.PublicPort > 0 {
			portValue = p.PublicPort
		} else {
			portValue = p.PrivatePort
		}
		endpoint, _ := netip.ParseAddrPort(fmt.Sprintf("%s:%d", ip, portValue))
		dp.Endpoint = endpoint
		log.Println(dp.Endpoint)
		allPorts = append(allPorts, dp)
	}

	if portStr, ok := c.Labels[LabelPort]; ok {
		port, _ = strconv.Atoi(portStr)
	}

	if tcpPortStr, ok := c.Labels[LabelTCPPort]; ok {
		tcpPort, _ = strconv.Atoi(tcpPortStr)
	}

	if port == 0 {
		for _, p := range c.Ports {
			if p.PublicPort > 0 {
				port = int(p.PublicPort)
				ip = "127.0.0.1"
				break
			}
		}

		if port == 0 && len(c.Ports) > 0 {
			port = int(c.Ports[0].PrivatePort)
		}
	}

	if port == 0 && tcpPort == 0 {
		return nil, "no exposed ports"
	}

	rawEndpoint := fmt.Sprintf("%s:%d", ip, port)
	endpoint, err := netip.ParseAddrPort(rawEndpoint)
	if err != nil {
		log.Printf("docker: invalid endpoint %s: %v", rawEndpoint, err)
		return nil, fmt.Sprintf("invalid endpoint: %s", rawEndpoint)
	}

	return &DiscoveredService{
		Subdomain: subdomain,
		Endpoint:  endpoint,
		TCPPort:   tcpPort,
		Source:    RouteSourceDocker,
		Docker: &DockerInfo{
			ID:            c.ID,
			Name:          name,
			HasCustomName: hasCustomName,
			Ports:         allPorts,
		},
	}, ""
}

func (w *DockerWatcher) watchEvents() {
	for {
		eventsChan, errChan := w.client.Events(w.ctx, events.ListOptions{
			Filters: filters.NewArgs(
				filters.Arg("type", "container"),
				filters.Arg("event", "start"),
				filters.Arg("event", "stop"),
				filters.Arg("event", "die"),
			),
		})

		if err := w.handleEventStream(eventsChan, errChan); err != nil {
			select {
			case <-w.ctx.Done():
				return
			default:
				log.Printf("docker: event stream error, reconnecting: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
		}
		return
	}
}

func (w *DockerWatcher) handleEventStream(eventsChan <-chan events.Message, errChan <-chan error) error {
	for {
		select {
		case <-w.ctx.Done():
			return nil
		case event, ok := <-eventsChan:
			if !ok {
				return fmt.Errorf("event channel closed")
			}
			switch event.Action {
			case "start":
				if w.onHealthy != nil {
					go w.waitForHealthy(event.Actor.ID)
				}
			case "stop", "die":
				containers, unrouted, err := w.listContainers()
				if err != nil {
					log.Printf("docker: failed to list containers after %s: %v", event.Action, err)
					continue
				}
				if w.onChange != nil {
					w.onChange(containers)
				}
				if w.onUnroutedChanged != nil {
					w.onUnroutedChanged(unrouted)
				}
			}
		case err := <-errChan:
			return fmt.Errorf("event stream: %w", err)
		}
	}
}

func (w *DockerWatcher) waitForHealthy(containerID string) {
	inspect, err := w.client.ContainerInspect(w.ctx, containerID)
	if err != nil {
		log.Printf("docker: failed to inspect container %s: %v", containerID, err)
		return
	}

	if inspect.State.Health == nil {
		containers, _, err := w.listContainers()
		if err != nil {
			return
		}
		for _, c := range containers {
			if c.Docker != nil && c.Docker.ID == containerID {
				w.onHealthy(c)
				return
			}
		}
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.After(5 * time.Minute)

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-timeout:
			log.Printf("docker: health check timeout for container %s", containerID)
			return
		case <-ticker.C:
			inspect, err := w.client.ContainerInspect(w.ctx, containerID)
			if err != nil {
				log.Printf("docker: failed to inspect container %s: %v", containerID, err)
				return
			}

			if inspect.State.Health == nil {
				return
			}

			if inspect.State.Health.Status == "healthy" {
				containers, _, err := w.listContainers()
				if err != nil {
					return
				}
				for _, c := range containers {
					if c.Docker != nil && c.Docker.ID == containerID {
						w.onHealthy(c)
						return
					}
				}
				return
			}
		}
	}
}

func (w *DockerWatcher) DiscoverServiceInfo(svc DiscoveredService, onDiscovered func(DiscoveredService)) {
	if svc.Docker == nil {
		return
	}

	var targets []netip.AddrPort
	portToIndex := make(map[uint16][]int)

	for i, dp := range svc.Docker.Ports {
		if dp.Type != "tcp" {
			continue
		}
		port := dp.Endpoint.Port()
		targets = append(targets, dp.Endpoint)
		portToIndex[port] = append(portToIndex[port], i)
	}

	if len(targets) == 0 {
		return
	}

	log.Printf("docker: starting service discovery for %s on %d ports", svc.Subdomain, len(targets))
	results := make(chan []ServiceInfo, 1)
	ProbeEndpoints(w.ctx, targets, results)

	go w.onServiceDiscovered(svc, results, portToIndex, onDiscovered)
}

func (w *DockerWatcher) onServiceDiscovered(svc DiscoveredService, results chan []ServiceInfo, portToIndex map[uint16][]int, onDiscovered func(DiscoveredService)) {
	services, ok := <-results
	if !ok {
		log.Printf("docker: service discovery channel closed for %s", svc.Subdomain)
		return
	}
	if len(services) == 0 {
		log.Printf("docker: no services discovered for %s", svc.Subdomain)
		return
	}

	for _, s := range services {
		port := s.Endpoint.Port()
		if indices, ok := portToIndex[port]; ok {
			for _, idx := range indices {
				svc.Docker.Ports[idx].ServiceProtocol = s.Protocol
			}
		}
		if s.Endpoint.Port() == svc.Endpoint.Port() {
			svc.Service = &s
		}
	}

	if svc.Service == nil && len(services) > 0 {
		svc.Service = &services[0]
	}

	log.Printf("docker: before port selection for %s: port=%d, service=%v", svc.Subdomain, svc.Endpoint.Port(), svc.Service)
	derivedPort := w.derivePorts(&svc, services)
	if derivedPort == 0 {
		log.Printf("docker: no port derived for %s, continuing to use %d", svc.Subdomain, svc.Endpoint.Port())
	} else {
		log.Printf("docker: after port selection for %s: port=%d, service=%v", svc.Subdomain, svc.Endpoint.Port(), svc.Service)
	}
	log.Printf("docker: discovered %d services for %s", len(services), svc.Subdomain)
	onDiscovered(svc)
}

func (*DockerWatcher) derivePorts(svc *DiscoveredService, services []ServiceInfo) uint16 {
	var port uint16

	if len(svc.Docker.Ports) > 1 {
		for _, s := range services {
			if s.Protocol == "http" || s.Protocol == "https" {
				oldPort := svc.Endpoint
				svc.Endpoint = s.Endpoint
				svc.Service = &s
				log.Printf("docker: using HTTP %s instead of %s for %s", s.Endpoint.String(), oldPort.String(), svc.Subdomain)
				port = svc.Endpoint.Port()
				break
			}
		}
	}
	return port
}
