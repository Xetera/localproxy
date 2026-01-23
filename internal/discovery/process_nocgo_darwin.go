//go:build darwin && !cgo

package discovery

import (
	"bufio"
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ListeningProcess struct {
	PID       int
	Port      int
	Subdomain string
	Cwd       string
}

type ProcessWatcher struct {
	basePath string
	onChange func([]ListeningProcess)
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	current  map[int]ListeningProcess
}

func NewProcessWatcher(basePath string) (*ProcessWatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())
	absPath, err := filepath.Abs(basePath)
	if err != nil {
		cancel()
		return nil, err
	}

	return &ProcessWatcher{
		basePath: absPath,
		ctx:      ctx,
		cancel:   cancel,
		current:  make(map[int]ListeningProcess),
	}, nil
}

func (w *ProcessWatcher) SetOnChange(fn func([]ListeningProcess)) {
	w.onChange = fn
}

func (w *ProcessWatcher) Start() error {
	processes, err := w.scan()
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.current = make(map[int]ListeningProcess)
	for _, p := range processes {
		w.current[p.PID] = p
	}
	w.mu.Unlock()

	if w.onChange != nil {
		w.onChange(processes)
	}

	go w.watchLoop()
	return nil
}

func (w *ProcessWatcher) Stop() {
	w.cancel()
}

func (w *ProcessWatcher) watchLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			processes, err := w.scan()
			if err != nil {
				continue
			}

			w.mu.Lock()
			changed := len(processes) != len(w.current)
			if !changed {
				for _, p := range processes {
					if existing, ok := w.current[p.PID]; !ok || existing.Port != p.Port {
						changed = true
						break
					}
				}
			}

			if changed {
				w.current = make(map[int]ListeningProcess)
				for _, p := range processes {
					w.current[p.PID] = p
				}
				w.mu.Unlock()

				if w.onChange != nil {
					w.onChange(processes)
				}
			} else {
				w.mu.Unlock()
			}
		}
	}
}

func (w *ProcessWatcher) scan() ([]ListeningProcess, error) {
	listeners, err := w.getListeningPorts()
	if err != nil {
		return nil, err
	}

	var results []ListeningProcess

	for pid, port := range listeners {
		cwd := w.getProcCwd(pid)
		if cwd == "" || !strings.HasPrefix(cwd, w.basePath) {
			continue
		}

		rel, err := filepath.Rel(w.basePath, cwd)
		if err != nil {
			continue
		}

		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) == 0 || parts[0] == "" || parts[0] == "." {
			continue
		}

		ignoredDirs := map[string]bool{"apps": true, "packages": true}

		var filteredParts []string
		for _, p := range parts {
			if p != "" && p != "." && !ignoredDirs[p] {
				filteredParts = append(filteredParts, p)
			}
		}

		if len(filteredParts) == 0 {
			continue
		}

		var subdomainParts []string
		for i := len(filteredParts) - 1; i >= 0; i-- {
			subdomainParts = append(subdomainParts, filteredParts[i])
		}
		subdomain := strings.Join(subdomainParts, ".")

		results = append(results, ListeningProcess{
			PID:       pid,
			Port:      port,
			Subdomain: subdomain,
			Cwd:       cwd,
		})
	}

	return results, nil
}

func (w *ProcessWatcher) getListeningPorts() (map[int]int, error) {
	cmd := exec.CommandContext(w.ctx, "lsof", "-i", "-P", "-n", "-sTCP:LISTEN")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) == 0 {
			return make(map[int]int), nil
		}
		return nil, err
	}

	result := make(map[int]int)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		if fields[0] == "COMMAND" {
			continue
		}

		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		addr := fields[8]
		colonIdx := strings.LastIndex(addr, ":")
		if colonIdx == -1 {
			continue
		}

		portStr := addr[colonIdx+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		if port < 1024 {
			continue
		}

		if _, exists := result[pid]; !exists {
			result[pid] = port
		}
	}

	return result, nil
}

func (w *ProcessWatcher) getProcCwd(pid int) string {
	cmd := exec.CommandContext(w.ctx, "lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "n") && len(line) > 1 {
			return line[1:]
		}
	}

	return ""
}
