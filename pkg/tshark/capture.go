package tshark

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

type CaptureConfig struct {
	Interface     string
	Port          uint16
	Protocol      Protocol
	BPFFilter     string
	DisplayFilter string
	DecodeAs      []string
	MaxPackets    int
	Snaplen       int
	BufferSize    int
	ExtraArgs     []string
}

type Capture struct {
	cfg     CaptureConfig
	cmd     *exec.Cmd
	packets chan *Packet
	done    chan struct{}
	err     error
	mu      sync.Mutex
}

func FindTshark() (string, error) {
	path, err := exec.LookPath("tshark")
	if err != nil {
		return "", fmt.Errorf("tshark not found in PATH: %w", err)
	}
	return path, nil
}

func NewCapture(cfg CaptureConfig) *Capture {
	return &Capture{
		cfg:     cfg,
		packets: make(chan *Packet, 64),
		done:    make(chan struct{}),
	}
}

func (c *Capture) BPFFilter() string {
	if c.cfg.BPFFilter != "" {
		return c.cfg.BPFFilter
	}
	if c.cfg.Port == 0 {
		return ""
	}
	return fmt.Sprintf("port %d", c.cfg.Port)
}

func (c *Capture) buildArgs() ([]string, error) {
	tsharkPath, err := FindTshark()
	if err != nil {
		return nil, err
	}

	args := []string{tsharkPath, "-T", "ek", "-l", "-x"}

	if c.cfg.Interface != "" {
		args = append(args, "-i", c.cfg.Interface)
	}

	if filter := c.BPFFilter(); filter != "" {
		args = append(args, "-f", filter)
	}

	if c.cfg.DisplayFilter != "" {
		args = append(args, "-Y", c.cfg.DisplayFilter)
	}

	for _, d := range c.cfg.DecodeAs {
		args = append(args, "-d", d)
	}

	if c.cfg.MaxPackets > 0 {
		args = append(args, "-c", strconv.Itoa(c.cfg.MaxPackets))
	}

	if c.cfg.Snaplen > 0 {
		args = append(args, "-s", strconv.Itoa(c.cfg.Snaplen))
	}

	if c.cfg.BufferSize > 0 {
		args = append(args, "-B", strconv.Itoa(c.cfg.BufferSize))
	}

	args = append(args, c.cfg.ExtraArgs...)

	return args, nil
}

func (c *Capture) Start(ctx context.Context) error {
	args, err := c.buildArgs()
	if err != nil {
		return err
	}

	c.cmd = exec.Command(args[0], args[1:]...)
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("starting tshark: %w", err)
	}

	go func() {
		<-ctx.Done()
		c.Stop()

		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			c.cmd.Process.Kill()
		}
	}()

	go func() {
		defer close(c.done)
		defer close(c.packets)

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()
			if IsIndexLine(line) {
				continue
			}

			pkt, err := ParseEKPacket(line)
			if err != nil {
				continue
			}
			select {
			case c.packets <- pkt:
			case <-ctx.Done():
				return
			}
		}

		c.mu.Lock()
		c.err = c.cmd.Wait()
		c.mu.Unlock()
	}()

	return nil
}

func (c *Capture) Packets() <-chan *Packet {
	return c.packets
}

func (c *Capture) Stop() error {
	if c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	return c.cmd.Process.Signal(syscall.SIGINT)
}

func (c *Capture) Wait() error {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Capture) Done() <-chan struct{} {
	return c.done
}
