package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type TsharkProtocol string

const (
	TsharkTCP TsharkProtocol = "tcp"
	TsharkUDP TsharkProtocol = "udp"
)

type CaptureConfig struct {
	Interface     string
	Port          uint16
	Protocol      TsharkProtocol
	BPFFilter     string
	DisplayFilter string
	DecodeAs      []string
	MaxPackets    int
	Snaplen       int
	BufferSize    int
	ExtraArgs     []string
}

type Packet struct {
	Number    uint64          `json:"number"`
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
	Dest      string          `json:"dest"`
	Protocol  string          `json:"protocol"`
	Length    int             `json:"length"`
	Info      string          `json:"info"`
	Layers    json.RawMessage `json:"layers"`
	Raw       json.RawMessage `json:"-"`
}

type PacketHandler func(Packet)

type Capture interface {
	Start(ctx context.Context) error
	Packets() <-chan Packet
	Stop() error
	Wait() error
	BPFFilter() string
}

type tsharkCapture struct {
	cfg     CaptureConfig
	cmd     *exec.Cmd
	packets chan Packet
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

func NewCapture(cfg CaptureConfig) Capture {
	return &tsharkCapture{
		cfg:     cfg,
		packets: make(chan Packet, 64),
		done:    make(chan struct{}),
	}
}

func (c *tsharkCapture) BPFFilter() string {
	return c.buildBPFFilter()
}

func (c *tsharkCapture) buildBPFFilter() string {
	if c.cfg.BPFFilter != "" {
		return c.cfg.BPFFilter
	}
	if c.cfg.Port == 0 {
		return ""
	}
	proto := string(c.cfg.Protocol)
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%s port %d", proto, c.cfg.Port)
}

func (c *tsharkCapture) buildArgs() ([]string, error) {
	tsharkPath, err := FindTshark()
	if err != nil {
		return nil, err
	}

	args := []string{tsharkPath, "-T", "ek", "-l"}

	if c.cfg.Interface != "" {
		args = append(args, "-i", c.cfg.Interface)
	}

	if filter := c.buildBPFFilter(); filter != "" {
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

func (c *tsharkCapture) Start(ctx context.Context) error {
	args, err := c.buildArgs()
	if err != nil {
		return err
	}

	c.cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("starting tshark: %w", err)
	}

	go func() {
		defer close(c.done)
		defer close(c.packets)

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()
			if isIndexLine(line) {
				continue
			}

			raw := make(json.RawMessage, len(line))
			copy(raw, line)

			pkt := parseEKPacket(raw)
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

func (c *tsharkCapture) Packets() <-chan Packet {
	return c.packets
}

func (c *tsharkCapture) Stop() error {
	if c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	return c.cmd.Process.Signal(syscall.SIGINT)
}

func (c *tsharkCapture) Wait() error {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func isIndexLine(line []byte) bool {
	if len(line) < 10 {
		return true
	}
	return line[1] == '"' && line[2] == 'i' && line[3] == 'n' && line[4] == 'd' && line[5] == 'e' && line[6] == 'x'
}

func parseEKPacket(raw json.RawMessage) Packet {
	pkt := Packet{Raw: raw}

	var obj struct {
		Timestamp string                     `json:"timestamp"`
		Layers    map[string]json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return pkt
	}

	if obj.Timestamp != "" {
		if ms, err := strconv.ParseInt(obj.Timestamp, 10, 64); err == nil {
			pkt.Timestamp = time.UnixMilli(ms)
		}
	}

	pkt.Layers, _ = json.Marshal(obj.Layers)

	if frameRaw, ok := obj.Layers["frame"]; ok {
		var frame map[string]any
		if err := json.Unmarshal(frameRaw, &frame); err == nil {
			if num := ekStringField(frame, "frame_frame_number"); num != "" {
				pkt.Number, _ = strconv.ParseUint(num, 10, 64)
			}
			if length := ekStringField(frame, "frame_frame_len"); length != "" {
				pkt.Length, _ = strconv.Atoi(length)
			}
			if proto := ekStringField(frame, "frame_frame_protocols"); proto != "" {
				parts := strings.Split(proto, ":")
				if len(parts) > 0 {
					pkt.Protocol = parts[len(parts)-1]
				}
			}
		}
	}

	if ipRaw, ok := obj.Layers["ip"]; ok {
		var ip map[string]any
		if err := json.Unmarshal(ipRaw, &ip); err == nil {
			pkt.Source = ekStringField(ip, "ip_ip_src")
			pkt.Dest = ekStringField(ip, "ip_ip_dst")
		}
	} else if ip6Raw, ok := obj.Layers["ipv6"]; ok {
		var ip6 map[string]any
		if err := json.Unmarshal(ip6Raw, &ip6); err == nil {
			pkt.Source = ekStringField(ip6, "ipv6_ipv6_src")
			pkt.Dest = ekStringField(ip6, "ipv6_ipv6_dst")
		}
	}

	return pkt
}

func ekStringField(obj map[string]any, key string) string {
	switch v := obj[key].(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}
