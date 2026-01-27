//go:build linux

package discovery

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (w *ProcessWatcher) getListeningPorts() ([]portEntry, error) {
	entries, err := w.parseProcNet("/proc/net/tcp")
	if err != nil {
		return nil, err
	}

	entries6, err := w.parseProcNet("/proc/net/tcp6")
	if err == nil {
		entries = append(entries, entries6...)
	}

	return entries, nil
}

func (w *ProcessWatcher) parseProcNet(path string) ([]portEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	inodeToPID := make(map[string]int)
	procDirs, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fdPath := range procDirs {
		link, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(link, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
		parts := strings.Split(fdPath, "/")
		if len(parts) < 3 {
			continue
		}
		pid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		inodeToPID[inode] = pid
	}

	var result []portEntry
	scanner := bufio.NewScanner(file)
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		state := fields[3]
		if state != "0A" {
			continue
		}

		localAddr := fields[1]
		addrParts := strings.Split(localAddr, ":")
		if len(addrParts) != 2 {
			continue
		}

		portHex := addrParts[1]
		port64, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)

		if port < 1024 {
			continue
		}

		inode := fields[9]
		pid, ok := inodeToPID[inode]
		if !ok {
			continue
		}

		result = append(result, portEntry{PID: pid, Port: port})
	}

	return result, nil
}

func (w *ProcessWatcher) getProcCwd(pid int) string {
	cwdPath := fmt.Sprintf("/proc/%d/cwd", pid)
	cwd, err := os.Readlink(cwdPath)
	if err != nil {
		return ""
	}
	return cwd
}
