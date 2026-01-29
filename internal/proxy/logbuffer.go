package proxy

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/xetera/localproxy/internal/discovery"
)

//go:embed trace.d
var dtraceScript string

type LogBuffer struct {
	lines []string
	mu    sync.RWMutex
	max   int
}

func NewLogBuffer(max int) *LogBuffer {
	return &LogBuffer{
		lines: make([]string, 0, max),
		max:   max,
	}
}

func (lb *LogBuffer) Add(line string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.lines = append(lb.lines, line)
	if len(lb.lines) > lb.max {
		lb.lines = lb.lines[1:]
	}
}

func (lb *LogBuffer) GetLines() []string {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	result := make([]string, len(lb.lines))
	copy(result, lb.lines)
	return result
}

type LogManager struct {
	buffers          map[string]*LogBuffer
	mu               sync.RWMutex
	tracers          map[string]context.CancelFunc
	tracerMu         sync.Mutex
	dockerClient     *client.Client
	traceProcessLogs bool
}

func NewLogManager(traceProcessLogs bool) *LogManager {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("docker client init failed for logs: %v", err)
		dockerClient = nil
	}

	return &LogManager{
		buffers:          make(map[string]*LogBuffer),
		tracers:          make(map[string]context.CancelFunc),
		dockerClient:     dockerClient,
		traceProcessLogs: traceProcessLogs,
	}
}

func (lm *LogManager) GetBuffer(key string) *LogBuffer {
	lm.mu.RLock()
	buffer, exists := lm.buffers[key]
	lm.mu.RUnlock()

	if exists {
		return buffer
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if buffer, exists := lm.buffers[key]; exists {
		return buffer
	}

	buffer = NewLogBuffer(10)
	lm.buffers[key] = buffer
	return buffer
}

func (lm *LogManager) GetBufferByPID(pid int) *LogBuffer {
	return lm.GetBuffer("pid:" + strconv.Itoa(pid))
}

func (lm *LogManager) GetBufferByContainerID(containerID string) *LogBuffer {
	return lm.GetBuffer("docker:" + containerID)
}

func (lm *LogManager) StartTracing(key string, pid int) {
	lm.tracerMu.Lock()
	if _, exists := lm.tracers[key]; exists {
		lm.tracerMu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	lm.tracers[key] = cancel
	lm.tracerMu.Unlock()

	go lm.traceProcess(ctx, key, pid)
}

func (lm *LogManager) StartDockerLogs(containerID string) {
	if lm.dockerClient == nil {
		return
	}

	key := "docker:" + containerID
	lm.tracerMu.Lock()
	if _, exists := lm.tracers[key]; exists {
		lm.tracerMu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	lm.tracers[key] = cancel
	lm.tracerMu.Unlock()

	go lm.tailDockerLogs(ctx, containerID)
}

func (lm *LogManager) StopTracing(key string) {
	lm.tracerMu.Lock()
	defer lm.tracerMu.Unlock()

	if cancel, exists := lm.tracers[key]; exists {
		cancel()
		delete(lm.tracers, key)
	}
}

func (lm *LogManager) traceProcess(ctx context.Context, key string, pid int) {
	buffer := lm.GetBuffer(key)
	pidStr := strconv.Itoa(pid)

	dtrace := exec.CommandContext(ctx, "sudo", "dtrace", "-p", pidStr, "-C", "-s", "/dev/stdin", pidStr)
	stdin, err := dtrace.StdinPipe()
	if err != nil {
		log.Printf("dtrace: failed to create stdin pipe for pid %d: %v", pid, err)
		return
	}

	stdout, err := dtrace.StdoutPipe()
	if err != nil {
		stdin.Close()
		log.Printf("dtrace: failed to create stdout pipe for pid %d: %v", pid, err)
		return
	}

	if err := dtrace.Start(); err != nil {
		stdin.Close()
		log.Printf("dtrace: failed to start for pid %d: %v", pid, err)
		return
	}

	if _, err := stdin.Write([]byte(dtraceScript)); err != nil {
		log.Printf("dtrace: failed to write script for pid %d: %v", pid, err)
		stdin.Close()
		return
	}
	stdin.Close()

	log.Printf("dtrace: started tracing pid %d", pid)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			line := scanner.Text()
			buffer.Add(line)
		}
	}
}

func (lm *LogManager) tailDockerLogs(ctx context.Context, containerID string) {
	buffer := lm.GetBufferByContainerID(containerID)

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "10",
	}

	reader, err := lm.dockerClient.ContainerLogs(ctx, containerID, options)
	if err != nil {
		log.Printf("docker logs: failed to start for container %s: %v", containerID[:12], err)
		return
	}
	defer reader.Close()

	log.Printf("docker logs: started tailing container %s", containerID[:12])

	var stdoutBuf, stderrBuf bytes.Buffer
	outputDone := make(chan error)

	go func() {
		_, err := stdcopy.StdCopy(&stdoutBuf, &stderrBuf, reader)
		outputDone <- err
	}()

	ticker := lm.processLogBuffers(ctx, buffer, &stdoutBuf, &stderrBuf)
	defer ticker.Stop()

	select {
	case <-ctx.Done():
		return
	case <-outputDone:
		return
	}
}

func (lm *LogManager) processLogBuffers(ctx context.Context, buffer *LogBuffer, stdout, stderr *bytes.Buffer) *time.Ticker {
	ticker := time.NewTicker(100 * time.Millisecond)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lm.drainBuffer(buffer, stdout)
				lm.drainBuffer(buffer, stderr)
			}
		}
	}()

	return ticker
}

func (lm *LogManager) drainBuffer(buffer *LogBuffer, src *bytes.Buffer) {
	for {
		line, err := src.ReadString('\n')
		if err == io.EOF {
			if line != "" {
				src.WriteString(line)
			}
			break
		}
		line = strings.TrimSpace(line)
		if line != "" {
			buffer.Add(line)
		}
	}
}

func (lm *LogManager) UpdateRoutes(routes []Route) {
	activeKeys := make(map[string]bool)

	for _, route := range routes {
		if route.Source == discovery.RouteSourceDocker && route.DockerContainerID != "" {
			key := "docker:" + route.DockerContainerID
			activeKeys[key] = true
			lm.StartDockerLogs(route.DockerContainerID)
		} else if route.PID > 0 {
			key := "pid:" + strconv.Itoa(route.PID)
			activeKeys[key] = true
			if !lm.traceProcessLogs {
				fmt.Println("Skipping process tracing because it wasn't turned on with `--process-logs`")
				continue
			}
			lm.StartTracing(key, route.PID)
		}
	}

	lm.tracerMu.Lock()
	for key := range lm.tracers {
		if !activeKeys[key] {
			if cancel, exists := lm.tracers[key]; exists {
				cancel()
				delete(lm.tracers, key)
			}
		}
	}
	lm.tracerMu.Unlock()

	lm.mu.Lock()
	for key := range lm.buffers {
		if !activeKeys[key] {
			delete(lm.buffers, key)
		}
	}
	lm.mu.Unlock()
}

func (lm *LogManager) Stop() {
	lm.tracerMu.Lock()
	defer lm.tracerMu.Unlock()

	for _, cancel := range lm.tracers {
		cancel()
	}
	lm.tracers = make(map[string]context.CancelFunc)
}
