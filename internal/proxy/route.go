package proxy

type RouteSource string

const (
	RouteSourceProcess   RouteSource = "process"
	RouteSourceDocker    RouteSource = "docker"
	RouteSourceWellKnown RouteSource = "wellknown"
)

type Route struct {
	Subdomain          string
	Host               string
	Port               int
	TCPPort            int
	PID                int
	Cwd                string
	Disabled           bool
	Source             RouteSource
	DockerHasAutoName  bool
	DockerContainerID  string
}
