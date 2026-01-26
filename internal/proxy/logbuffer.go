package proxy

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

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
	buffers      map[string]*LogBuffer
	mu           sync.RWMutex
	tracers      map[string]context.CancelFunc
	tracerMu     sync.Mutex
	dockerClient *client.Client
}

func NewLogManager() *LogManager {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("docker client init failed for logs: %v", err)
		dockerClient = nil
	}

	return &LogManager{
		buffers:      make(map[string]*LogBuffer),
		tracers:      make(map[string]context.CancelFunc),
		dockerClient: dockerClient,
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

	_, cancel := context.WithCancel(context.Background())
	lm.tracers[key] = cancel
	lm.tracerMu.Unlock()

	// go lm.traceProcess(ctx, key, pid)
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

	dtrace := exec.CommandContext(ctx, "sudo", "dtrace", "-p", pidStr, "-qn",
		`syscall::write*:entry
		/pid == $target && arg0 == 1/ {
			printf("%s", copyinstr(arg1, arg2));
		}`)

	stdout, err := dtrace.StdoutPipe()
	if err != nil {
		log.Printf("dtrace: failed to create stdout pipe for pid %d: %v", pid, err)
		return
	}

	if err := dtrace.Start(); err != nil {
		log.Printf("dtrace: failed to start for pid %d: %v", pid, err)
		return
	}

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

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			line := scanner.Text()
			if len(line) > 8 {
				line = line[8:]
			}
			line = strings.TrimSpace(line)
			if line != "" {
				buffer.Add(line)
			}
		}
	}
}

func (lm *LogManager) UpdateRoutes(routes []Route) {
	activeKeys := make(map[string]bool)

	for _, route := range routes {
		if route.Source == RouteSourceDocker && route.DockerContainerID != "" {
			key := "docker:" + route.DockerContainerID
			activeKeys[key] = true
			lm.StartDockerLogs(route.DockerContainerID)
		} else if route.PID > 0 {
			key := "pid:" + strconv.Itoa(route.PID)
			activeKeys[key] = true
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
