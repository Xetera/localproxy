package discovery

import "net/netip"

type RouteSource string

const (
	RouteSourceProcess   RouteSource = "process"
	RouteSourceDocker    RouteSource = "docker"
	RouteSourceWellKnown RouteSource = "wellknown"
)

type DiscoveredService struct {
	Subdomain string
	Endpoint  netip.AddrPort
	TCPPort   int
	Source    RouteSource

	Process *ProcessInfo
	Docker  *DockerInfo
	Folder  *FolderInfo
	Service *ServiceInfo
}

type ProcessInfo struct {
	PID                int
	Cwd                string
	Disabled           bool
	NeedsCustomMapping bool
	IsWellKnown        bool
	IsDocker           bool
}

type DockerListener struct {
	Endpoint    netip.AddrPort
	PrivatePort int
	Type        string
	/**
	 * tcp/udp/http/postgres etc
	 */
	ServiceProtocol string
}

type DockerInfo struct {
	ID            string
	Name          string
	HasCustomName bool
	Ports         []DockerListener
}

type FolderInfo struct {
	Path string
	Name string
}
