//go:build darwin && cgo

package discovery

/*
#cgo LDFLAGS: -lproc
#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

int get_proc_cwd(int pid, char *buffer, int bufsize) {
    struct proc_vnodepathinfo vpi;
    int ret = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi));
    if (ret <= 0) {
        return -1;
    }
    strncpy(buffer, vpi.pvi_cdir.vip_path, bufsize - 1);
    buffer[bufsize - 1] = '\0';
    return 0;
}
*/
import "C"

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type ListeningProcess struct {
	PID       int
	Port      int
	Subdomain string
	Cwd       string
	Disabled  bool
}

type WellKnownProcess struct {
	PID       int
	Port      int
	Subdomain string
}

type ProcessWatcher struct {
	basePath          string
	onChange          func([]ListeningProcess)
	onWellKnownChange func([]WellKnownProcess)
	ctx               context.Context
	cancel            context.CancelFunc
	mu                sync.RWMutex
	current           map[int]ListeningProcess
	currentWellKnown  map[int]WellKnownProcess
}

func NewProcessWatcher(basePath string) (*ProcessWatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())
	absPath, err := filepath.Abs(basePath)
	if err != nil {
		cancel()
		return nil, err
	}

	return &ProcessWatcher{
		basePath:         absPath,
		ctx:              ctx,
		cancel:           cancel,
		current:          make(map[int]ListeningProcess),
		currentWellKnown: make(map[int]WellKnownProcess),
	}, nil
}

func (w *ProcessWatcher) SetOnChange(fn func([]ListeningProcess)) {
	w.onChange = fn
}

func (w *ProcessWatcher) SetOnWellKnownChange(fn func([]WellKnownProcess)) {
	w.onWellKnownChange = fn
}

func (w *ProcessWatcher) Start() error {
	processes, wellKnown, err := w.scan()
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.current = make(map[int]ListeningProcess)
	for _, p := range processes {
		w.current[p.PID] = p
	}
	w.currentWellKnown = make(map[int]WellKnownProcess)
	for _, p := range wellKnown {
		w.currentWellKnown[p.PID] = p
	}
	w.mu.Unlock()

	if w.onChange != nil {
		w.onChange(processes)
	}
	if w.onWellKnownChange != nil {
		w.onWellKnownChange(wellKnown)
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
			processes, wellKnown, err := w.scan()
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

			wellKnownChanged := len(wellKnown) != len(w.currentWellKnown)
			if !wellKnownChanged {
				for _, p := range wellKnown {
					if existing, ok := w.currentWellKnown[p.PID]; !ok || existing.Port != p.Port {
						wellKnownChanged = true
						break
					}
				}
			}

			if changed {
				w.current = make(map[int]ListeningProcess)
				for _, p := range processes {
					w.current[p.PID] = p
				}
			}

			if wellKnownChanged {
				w.currentWellKnown = make(map[int]WellKnownProcess)
				for _, p := range wellKnown {
					w.currentWellKnown[p.PID] = p
				}
			}

			w.mu.Unlock()

			if changed && w.onChange != nil {
				w.onChange(processes)
			}
			if wellKnownChanged && w.onWellKnownChange != nil {
				w.onWellKnownChange(wellKnown)
			}
		}
	}
}

func (w *ProcessWatcher) scan() ([]ListeningProcess, []WellKnownProcess, error) {
	listeners, err := w.getListeningPorts()
	if err != nil {
		return nil, nil, err
	}

	var results []ListeningProcess
	var wellKnownResults []WellKnownProcess
	seen := make(map[string]bool)
	usedPorts := make(map[int]bool)
	cwdCache := make(map[int]string)

	ownPid := os.Getpid()
	for _, entry := range listeners {
		pid := entry.PID
		if pid == ownPid {
			continue
		}

		port := entry.Port

		cwd, cached := cwdCache[pid]
		if !cached {
			cwd = w.getProcCwd(pid)
			cwdCache[pid] = cwd
		}

		if cwd == "" {
			if wk, ok := WellKnownPorts[port]; ok && !usedPorts[port] {
				wellKnownResults = append(wellKnownResults, WellKnownProcess{
					PID:       pid,
					Port:      port,
					Subdomain: wk.Subdomain,
				})
				usedPorts[port] = true
			}
			continue
		}

		if !strings.HasPrefix(cwd, w.basePath) {
			if wk, ok := WellKnownPorts[port]; ok && !usedPorts[port] {
				wellKnownResults = append(wellKnownResults, WellKnownProcess{
					PID:       pid,
					Port:      port,
					Subdomain: wk.Subdomain,
				})
				usedPorts[port] = true
			}
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

		subdomain := parts[0]

		key := subdomain
		if seen[key] {
			continue
		}
		seen[key] = true

		results = append(results, ListeningProcess{
			PID:       pid,
			Port:      port,
			Subdomain: subdomain,
			Cwd:       cwd,
		})
		usedPorts[port] = true
	}

	return results, wellKnownResults, nil
}

type portEntry struct {
	PID  int
	Port int
}

func (w *ProcessWatcher) getListeningPorts() ([]portEntry, error) {
	cmd := exec.CommandContext(w.ctx, "lsof", "-i", "-P", "-n", "-sTCP:LISTEN")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) == 0 {
			return nil, nil
		}
		return nil, err
	}

	var result []portEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		if fields[0] == "COMMAND" {
			continue
		}

		if fields[7] != "TCP" {
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

		result = append(result, portEntry{PID: pid, Port: port})
	}

	return result, nil
}

func (w *ProcessWatcher) getProcCwd(pid int) string {
	buf := make([]byte, 4096)
	ret := C.get_proc_cwd(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if ret != 0 {
		return ""
	}

	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}

	return string(buf[:n])
}
