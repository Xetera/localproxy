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
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
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
