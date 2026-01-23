package discovery

import (
	"context"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	LabelSubdomain = "localproxy.subdomain"
	LabelPort      = "localproxy.port"
)

type DockerContainer struct {
	ID        string
	Name      string
	Subdomain string
	Port      int
	IP        string
}

type DockerWatcher struct {
	client    *client.Client
	onChange  func([]DockerContainer)
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
	containers, err := w.client.ContainerList(w.ctx, container.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("label", LabelSubdomain),
		),
	})
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
	subdomain, ok := c.Labels[LabelSubdomain]
	if !ok || subdomain == "" {
		return nil
	}

	var port int
	if portStr, ok := c.Labels[LabelPort]; ok {
		port, _ = strconv.Atoi(portStr)
	}

	if port == 0 && len(c.Ports) > 0 {
		port = int(c.Ports[0].PrivatePort)
	}

	if port == 0 {
		return nil
	}

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

	name := strings.TrimPrefix(c.Names[0], "/")

	return &DockerContainer{
		ID:        c.ID,
		Name:      name,
		Subdomain: subdomain,
		Port:      port,
		IP:        ip,
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
