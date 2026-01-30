package discovery

type RouteSource string

const (
	RouteSourceProcess   RouteSource = "process"
	RouteSourceDocker    RouteSource = "docker"
	RouteSourceWellKnown RouteSource = "wellknown"
)

type DiscoveredService struct {
	Subdomain string
	Port      int
	IP        string
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

type DockerPort struct {
	Port            int
	PrivatePort     int
	IP              string
	Type            string
	ServiceProtocol string
}

type DockerInfo struct {
	ID            string
	Name          string
	HasCustomName bool
	Ports         []DockerPort
}

type FolderInfo struct {
	Path string
	Name string
}
