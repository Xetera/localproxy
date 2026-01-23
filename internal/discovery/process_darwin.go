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
}

type ProcessWatcher struct {
	basePath  string
	onChange  func([]ListeningProcess)
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	current   map[int]ListeningProcess
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
	seen := make(map[string]bool)

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
