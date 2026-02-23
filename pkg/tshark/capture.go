package tshark

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type CaptureConfig struct {
	Interface     string
	BPFFilter     string
	DisplayFilter string
	DecodeAs      []string
	MaxPackets    int
	Snaplen       int
	BufferSize    int
	ExtraArgs     []string
}

type Capture struct {
	cfg  CaptureConfig
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	mu   sync.Mutex

	subs   map[netip.AddrPort][]*Subscription
	subsMu sync.RWMutex
}

type Subscription struct {
	C      <-chan *Packet
	ch     chan *Packet
	target netip.AddrPort
	cap    *Capture
}

func (s *Subscription) Close() {
	s.cap.unsubscribe(s)
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
		cfg:  cfg,
		done: make(chan struct{}),
		subs: make(map[netip.AddrPort][]*Subscription),
	}
}

var (
	discoveryMu sync.Mutex
	discovering map[netip.AddrPort]bool = make(map[netip.AddrPort]bool)
)

func MarkDiscovery(endpoint netip.AddrPort) {
	discoveryMu.Lock()
	discovering[endpoint] = true
	discoveryMu.Unlock()
}

func ClearDiscovery(endpoint netip.AddrPort) {
	discoveryMu.Lock()
	delete(discovering, endpoint)
	discoveryMu.Unlock()
}

func IsDiscovering(endpoint netip.AddrPort) bool {
	discoveryMu.Lock()
	defer discoveryMu.Unlock()
	return discovering[endpoint]
}

func (c *Capture) Subscribe(target netip.AddrPort) *Subscription {
	ch := make(chan *Packet, 64)
	sub := &Subscription{
		C:      ch,
		ch:     ch,
		target: target,
		cap:    c,
	}
	c.subsMu.Lock()
	c.subs[target] = append(c.subs[target], sub)
	c.subsMu.Unlock()
	return sub
}

func (c *Capture) unsubscribe(sub *Subscription) {
	c.subsMu.Lock()
	subs := c.subs[sub.target]
	for i, s := range subs {
		if s == sub {
			c.subs[sub.target] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
	if len(c.subs[sub.target]) == 0 {
		delete(c.subs, sub.target)
	}
	c.subsMu.Unlock()
	close(sub.ch)
}

func (c *Capture) deliver(pkt *Packet) {
	discoveryMu.Lock()
	isDiscoveringSrc := discovering[pkt.Src]
	isDiscoveringDst := discovering[pkt.Dst]
	discoveryMu.Unlock()

	if isDiscoveringSrc || isDiscoveringDst {
		return
	}

	c.subsMu.RLock()
	defer c.subsMu.RUnlock()

	targets := [2]netip.AddrPort{pkt.Src, pkt.Dst}
	sent := make(map[*Subscription]bool)

	for _, addr := range targets {
		if !addr.IsValid() {
			continue
		}
		for _, sub := range c.subs[addr] {
			if sent[sub] {
				continue
			}
			select {
			case sub.ch <- pkt:
			default:
			}
			sent[sub] = true
		}
	}
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

	if c.cfg.BPFFilter != "" {
		args = append(args, "-f", c.cfg.BPFFilter)
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
		defer c.closeAllSubs()

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

			c.deliver(pkt)
		}

		c.mu.Lock()
		c.err = c.cmd.Wait()
		c.mu.Unlock()
	}()

	return nil
}

func (c *Capture) closeAllSubs() {
	c.subsMu.Lock()
	defer c.subsMu.Unlock()
	for addr, subs := range c.subs {
		for _, sub := range subs {
			close(sub.ch)
		}
		delete(c.subs, addr)
	}
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
