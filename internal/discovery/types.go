package discovery

type ListeningProcess struct {
	PID                int
	Port               int
	Subdomain          string
	Cwd                string
	Disabled           bool
	NeedsCustomMapping bool
}

type WellKnownProcess struct {
	PID       int
	Port      int
	Subdomain string
	TCPPort   int
}
