//go:build linux

package discovery

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func hexByte(s string) int {
	i, _ := strconv.ParseInt(s, 16, 32)
	return int(i)
}

func (w *ProcessWatcher) getListeningPorts() ([]portEntry, error) {
	entries, err := w.parseProcNet("/proc/net/tcp")
	if err != nil {
		fmt.Printf("Error parsing /proc/net/tcp: %v\n", err)
		return nil, err
	}
	fmt.Printf("Found %d entries from /proc/net/tcp\n", len(entries))

	entries6, err := w.parseProcNet("/proc/net/tcp6")
	if err == nil {
		entries = append(entries, entries6...)
		fmt.Printf("Found %d entries from /proc/net/tcp6\n", len(entries6))
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
	fmt.Printf("Found %d fd paths\n", len(procDirs))
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
	fmt.Printf("Mapped %d inodes to PIDs\n", len(inodeToPID))

	var result []portEntry
	scanner := bufio.NewScanner(file)
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			fmt.Printf("Skipping line with %d fields: %s\n", len(fields), line)
			continue
		}

		state := fields[3]
		if state != "0A" {
			continue
		}

		localAddr := fields[1]
		addrParts := strings.Split(localAddr, ":")
		if len(addrParts) != 2 {
			fmt.Printf("Skipping bad address format: %s\n", localAddr)
			continue
		}

		addrHex := addrParts[0]
		portHex := addrParts[1]
		port64, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			fmt.Printf("Skipping bad port %s: %v\n", portHex, err)
			continue
		}
		port := int(port64)

		if port < 1024 {
			fmt.Printf("Skipping port < 1024: %d\n", port)
			continue
		}

		var ipStr string
		if len(addrHex) == 8 {
			ipStr = fmt.Sprintf("%d.%d.%d.%d",
				hexByte(addrHex[6:8]),
				hexByte(addrHex[4:6]),
				hexByte(addrHex[2:4]),
				hexByte(addrHex[0:2]))
		} else {
			ipStr = "::1"
		}

		inode := fields[9]
		pid, ok := inodeToPID[inode]
		if !ok {
			fmt.Printf("No PID for inode %s, port %d, ip %s\n", inode, port, ipStr)
			continue
		}

		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			fmt.Printf("Skipping invalid IP %s: %v\n", ipStr, err)
			continue
		}
		result = append(result, portEntry{PID: pid, Endpoint: netip.AddrPortFrom(addr, uint16(port))})
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
