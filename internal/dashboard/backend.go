package dashboard

import (
	"github.com/xetera/localproxy/internal/discovery"
	"github.com/xetera/localproxy/internal/proxy"
)

type Backend struct {
	proxy.Route
	PID                int
	Cwd                string
	Disabled           bool
	Source             discovery.RouteSource
	DockerContainerID  string
	DockerHasAutoName  bool
	DockerPorts        []discovery.DockerListener
	NeedsCustomMapping bool
	IsDocker           bool
	TopLevelFolder     string
	RelativePath       string
}
