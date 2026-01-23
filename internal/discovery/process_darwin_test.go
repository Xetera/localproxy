package discovery

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessWatcher_Scan(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "localproxy-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	projectDir := filepath.Join(tmpDir, "myapp")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	script := filepath.Join(projectDir, "server.sh")
	if err := os.WriteFile(script, []byte("#!/bin/bash\nwhile true; do nc -l "+string(rune(port))+" || true; done"), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("python3", "-c", `
import socket
import time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', `+itoa(port)+`))
s.listen(1)
time.sleep(30)
`)
	cmd.Dir = projectDir

	listener.Close()

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	time.Sleep(500 * time.Millisecond)

	watcher, err := NewProcessWatcher(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	processes, err := watcher.scan()
	if err != nil {
		t.Fatal(err)
	}

	var found *ListeningProcess
	for _, p := range processes {
		if p.Port == port {
			found = &p
			break
		}
	}

	if found == nil {
		t.Fatalf("expected to find process listening on port %d, got processes: %+v", port, processes)
	}

	if found.Subdomain != "myapp" {
		t.Errorf("expected subdomain 'myapp', got %q", found.Subdomain)
	}

	if found.Cwd != projectDir {
		t.Errorf("expected cwd %q, got %q", projectDir, found.Cwd)
	}
}

func itoa(i int) string {
	return string(rune('0'+i/10000%10)) + string(rune('0'+i/1000%10)) + string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}
