package hosts

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/txn2/txeh"
)

const comment = "localproxy-managed"

type Manager struct {
	hosts *txeh.Hosts
	mu    sync.Mutex
}

func NewManager() (*Manager, error) {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return nil, fmt.Errorf("failed to load hosts file: %w", err)
	}
	return &Manager{hosts: hosts}, nil
}

func (m *Manager) Update(subdomains []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return fmt.Errorf("failed to reload hosts file: %w", err)
	}
	m.hosts = hosts

	m.hosts.RemoveByComment(comment)

	var hostnames []string
	for _, sub := range subdomains {
		hostnames = append(hostnames, fmt.Sprintf("%s.proxy.localhost", sub))
	}

	if len(hostnames) > 0 {
		m.hosts.AddHostsWithComment("127.0.0.1", hostnames, comment)
	}

	if err := m.hosts.Save(); err != nil {
		return fmt.Errorf("failed to save hosts file: %w", err)
	}

	log.Printf("hosts: updated %d entries", len(hostnames))
	return nil
}

func (m *Manager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return fmt.Errorf("failed to reload hosts file: %w", err)
	}
	m.hosts = hosts

	m.hosts.RemoveByComment(comment)

	if err := m.hosts.Save(); err != nil {
		return fmt.Errorf("failed to save hosts file: %w", err)
	}

	log.Printf("hosts: cleaned up managed entries")
	return nil
}

func isLocalhost(hostname string) bool {
	return strings.HasSuffix(hostname, ".localhost")
}
