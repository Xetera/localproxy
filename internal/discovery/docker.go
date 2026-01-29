package discovery

import (
	"context"
	"fmt"
	"log"
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

type DockerWatcher struct {
	client    *client.Client
	onChange  func([]DiscoveredService)
	onHealthy func(DiscoveredService)
	ctx       context.Context
	cancel    context.CancelFunc
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

func (w *DockerWatcher) Start() error {
	containers, err := w.listContainers()
	if err != nil {
		return err
	}
	if w.onChange != nil {
		w.onChange(containers)
	}

	go w.watchEvents()
	return nil
}

func (w *DockerWatcher) Stop() {
	w.cancel()
	w.client.Close()
}

func (w *DockerWatcher) listContainers() ([]DiscoveredService, error) {
	containers, err := w.client.ContainerList(w.ctx, container.ListOptions{})
	if err != nil {
		return nil, err
	}

	var result []DiscoveredService
	for _, c := range containers {
		dc := w.parseContainer(c)
		if dc != nil {
			result = append(result, *dc)
		}
	}
	return result, nil
}

func (w *DockerWatcher) parseContainer(c container.Summary) *DiscoveredService {
	if len(c.Names) == 0 {
		return nil
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
		return nil
	}

	return &DiscoveredService{
		Subdomain: subdomain,
		Port:      port,
		IP:        ip,
		TCPPort:   tcpPort,
		Source:    RouteSourceDocker,
		Docker: &DockerInfo{
			ID:            c.ID,
			Name:          name,
			HasCustomName: hasCustomName,
		},
	}
}

func (w *DockerWatcher) watchEvents() {
	resyncTicker := time.NewTicker(30 * time.Second)
	defer resyncTicker.Stop()

	for {
		eventsChan, errChan := w.client.Events(w.ctx, events.ListOptions{
			Filters: filters.NewArgs(
				filters.Arg("type", "container"),
				filters.Arg("event", "start"),
				filters.Arg("event", "stop"),
				filters.Arg("event", "die"),
			),
		})

		if err := w.handleEventStream(eventsChan, errChan, resyncTicker.C); err != nil {
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

func (w *DockerWatcher) handleEventStream(eventsChan <-chan events.Message, errChan <-chan error, resync <-chan time.Time) error {
	for {
		select {
		case <-w.ctx.Done():
			return nil
		case event, ok := <-eventsChan:
			if !ok {
				return fmt.Errorf("event channel closed")
			}
			w.resync()
			if event.Action == "start" && w.onHealthy != nil {
				go w.waitForHealthy(event.Actor.ID)
			}
		case err := <-errChan:
			return fmt.Errorf("event stream: %w", err)
		case <-resync:
			w.resync()
		}
	}
}

func (w *DockerWatcher) resync() {
	containers, err := w.listContainers()
	if err != nil {
		log.Printf("docker: failed to list containers: %v", err)
		return
	}
	if w.onChange != nil {
		w.onChange(containers)
	}
}

func (w *DockerWatcher) waitForHealthy(containerID string) {
	inspect, err := w.client.ContainerInspect(w.ctx, containerID)
	if err != nil {
		log.Printf("docker: failed to inspect container %s: %v", containerID, err)
		return
	}

	if inspect.State.Health == nil {
		containers, err := w.listContainers()
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
				containers, err := w.listContainers()
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
	log.Printf("docker: starting service discovery for %s at %s:%d", svc.Subdomain, svc.IP, svc.Port)
	targets := []ScanTarget{{IP: svc.IP, Port: svc.Port}}
	results := make(chan []ServiceInfo, 1)
	DiscoverServices(w.ctx, targets, results)

	go func() {
		services, ok := <-results
		if !ok {
			log.Printf("docker: service discovery channel closed for %s", svc.Subdomain)
			return
		}
		if len(services) == 0 {
			log.Printf("docker: no services discovered for %s", svc.Subdomain)
			return
		}
		log.Printf("docker: discovered service for %s: protocol=%s", svc.Subdomain, services[0].Protocol)
		svc.Service = &services[0]
		onDiscovered(svc)
	}()
}
