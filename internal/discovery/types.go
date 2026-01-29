package discovery

type RouteSource string

const (
	RouteSourceProcess   RouteSource = "process"
	RouteSourceDocker    RouteSource = "docker"
	RouteSourceWellKnown RouteSource = "wellknown"
	RouteSourceFile      RouteSource = "file"
)

type DiscoveredService struct {
	Subdomain string
	Port      int
	IP        string
	TCPPort   int
	Source    RouteSource

	Process *ProcessInfo
	Docker  *DockerInfo
	File    *FileInfo
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
	Port       int
	PrivatePort int
	IP         string
	Type       string
}

type DockerInfo struct {
	ID            string
	Name          string
	HasCustomName bool
	Ports         []DockerPort
}

type FileInfo struct {
	Path string
	Name string
}
