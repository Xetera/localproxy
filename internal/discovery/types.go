package discovery

type ListeningProcess struct {
	PID                int
	Port               int
	IP                 string
	Subdomain          string
	Cwd                string
	Disabled           bool
	NeedsCustomMapping bool
	Service            *ServiceInfo
}

type WellKnownProcess struct {
	PID       int
	Port      int
	IP        string
	Subdomain string
	TCPPort   int
	IsDocker  bool
	Service   *ServiceInfo
}
