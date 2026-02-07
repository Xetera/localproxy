package proxy

import (
	"net/netip"

	"github.com/xetera/localproxy/internal/discovery"
)

type Route struct {
	Subdomain          string
	Endpoint           netip.AddrPort
	TCPPort            int
	PID                int
	Cwd                string
	Disabled           bool
	Source             discovery.RouteSource
	DockerHasAutoName  bool
	DockerContainerID  string
	DockerPorts        []discovery.DockerListener
	NeedsCustomMapping bool
	IsDocker           bool
	ServiceProtocol    string
	HasWildcard        bool
	FolderGroup        string
	TopLevelFolder     string
	RelativePath       string
}
