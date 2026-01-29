package proxy

import "github.com/xetera/localproxy/internal/discovery"

type Route struct {
	Subdomain          string
	Host               string
	Port               int
	TCPPort            int
	PID                int
	Cwd                string
	Disabled           bool
	Source             discovery.RouteSource
	DockerHasAutoName  bool
	DockerContainerID  string
	DockerPorts        []discovery.DockerPort
	NeedsCustomMapping bool
	IsDocker           bool
	ServiceProtocol    string
}
