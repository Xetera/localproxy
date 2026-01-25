package discovery

import (
	"context"
	"log"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
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

type DockerContainer struct {
	ID            string
	Name          string
	Subdomain     string
	Port          int
	TCPPort       int
	IP            string
	HasCustomName bool
}

type DockerWatcher struct {
	client   *client.Client
	onChange func([]DockerContainer)
	ctx      context.Context
	cancel   context.CancelFunc
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

func (w *DockerWatcher) SetOnChange(fn func([]DockerContainer)) {
	w.onChange = fn
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

func (w *DockerWatcher) listContainers() ([]DockerContainer, error) {
	containers, err := w.client.ContainerList(w.ctx, container.ListOptions{})
	if err != nil {
		return nil, err
	}

	var result []DockerContainer
	for _, c := range containers {
		dc := w.parseContainer(c)
		if dc != nil {
			result = append(result, *dc)
		}
	}
	return result, nil
}

func (w *DockerWatcher) parseContainer(c types.Container) *DockerContainer {
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
	var ip string = "127.0.0.1"

	if portStr, ok := c.Labels[LabelPort]; ok {
		port, _ = strconv.Atoi(portStr)
	}

	if tcpPortStr, ok := c.Labels[LabelTCPPort]; ok {
		tcpPort, _ = strconv.Atoi(tcpPortStr)
	}

	if port == 0 && len(c.Ports) > 0 {
		for _, p := range c.Ports {
			if p.PublicPort > 0 {
				port = int(p.PublicPort)
				break
			}
		}

		if port == 0 {
			for _, net := range c.NetworkSettings.Networks {
				if net.IPAddress != "" {
					ip = net.IPAddress
					port = int(c.Ports[0].PrivatePort)
					break
				}
			}
		}
	}

	if port == 0 && tcpPort == 0 {
		return nil
	}

	return &DockerContainer{
		ID:            c.ID,
		Name:          name,
		Subdomain:     subdomain,
		Port:          port,
		TCPPort:       tcpPort,
		IP:            ip,
		HasCustomName: hasCustomName,
	}
}

func (w *DockerWatcher) watchEvents() {
	eventsChan, errChan := w.client.Events(w.ctx, events.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("type", "container"),
			filters.Arg("event", "start"),
			filters.Arg("event", "stop"),
			filters.Arg("event", "die"),
		),
	})

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-eventsChan:
			containers, err := w.listContainers()
			if err == nil && w.onChange != nil {
				w.onChange(containers)
			}
		case <-errChan:
			return
		}
	}
}
