//go:build darwin && !cgo

package discovery

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
)

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

		ipStr := addr[:colonIdx]
		if ipStr == "*" {
			ipStr = "127.0.0.1"
		} else if strings.HasPrefix(ipStr, "[") && strings.HasSuffix(ipStr, "]") {
			ipStr = ipStr[1 : len(ipStr)-1]
		}

		result = append(result, portEntry{PID: pid, Port: port, IP: ipStr})
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
