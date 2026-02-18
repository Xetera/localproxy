package protocol

import (
	"bufio"
	"context"
	"encoding/hex"
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
	SrcPort   uint16          `json:"src_port"`
	DstPort   uint16          `json:"dst_port"`
	Protocol  string          `json:"protocol"`
	Length    int             `json:"length"`
	Info      string          `json:"info"`
	PgSQL     []PgSQLCommand  `json:"pgsql,omitempty"`
	Layers    json.RawMessage `json:"layers"`
	Raw       []byte          `json:"-"`
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

	args := []string{tsharkPath, "-T", "ek", "-l", "-x"}

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
			if isIndexLine(line) {
				continue
			}

			raw := make(json.RawMessage, len(line))
			copy(raw, line)

			pkt := parseEKPacket(raw)
			select {
			case c.packets <- pkt:
			case <-ctx.Done():
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
		delete(obj.Layers, "frame")
	}

	delete(obj.Layers, "eth")
	delete(obj.Layers, "ip")
	delete(obj.Layers, "ipv6")
	delete(obj.Layers, "udp")

	if tcpRaw, ok := obj.Layers["tcp"]; ok {
		var tcp map[string]any
		if err := json.Unmarshal(tcpRaw, &tcp); err == nil {
			if src := ekStringField(tcp, "tcp_tcp_srcport"); src != "" {
				if p, err := strconv.ParseUint(src, 10, 16); err == nil {
					pkt.SrcPort = uint16(p)
				}
			}
			if dst := ekStringField(tcp, "tcp_tcp_dstport"); dst != "" {
				if p, err := strconv.ParseUint(dst, 10, 16); err == nil {
					pkt.DstPort = uint16(p)
				}
			}
			raw, err := hex.DecodeString(ekStringField(tcp, "tcp_tcp_payload_raw"))
			if err != nil {
				fmt.Println("Error decoding hex string:", err)
			} else {
				pkt.Raw = raw
			}
		}
		delete(obj.Layers, "tcp")
	}

	if pgsqlRaw, ok := obj.Layers["pgsql"]; ok {
		pkt.PgSQL = parsePgSQLLayer(pgsqlRaw)
		fmt.Println(pkt.PgSQL)
		delete(obj.Layers, "pgsql")
	}
	pkt.Layers, _ = json.Marshal(obj.Layers)

	return pkt
}

func ekStringField(obj map[string]any, key string) string {
	switch v := obj[key].(type) {
	case string:
		return v
	default:
		return ""
	}
}

type PacketLog struct {
	mu          sync.RWMutex
	packets     []Packet
	limit       int
	subscribers map[uint64]chan Packet
	nextID      uint64
}

func NewPacketLog(limit int) *PacketLog {
	return &PacketLog{
		packets:     make([]Packet, 0, limit),
		limit:       limit,
		subscribers: make(map[uint64]chan Packet),
	}
}

func (l *PacketLog) Record(pkt Packet) {
	l.mu.Lock()
	l.packets = append(l.packets, pkt)
	if len(l.packets) > l.limit {
		l.packets = l.packets[1:]
	}
	subs := make(map[uint64]chan Packet, len(l.subscribers))
	for k, v := range l.subscribers {
		subs[k] = v
	}
	l.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- pkt:
		default:
		}
	}
}

func (l *PacketLog) GetAll() []Packet {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]Packet, len(l.packets))
	copy(result, l.packets)
	return result
}

func (l *PacketLog) Subscribe() (uint64, <-chan Packet) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id := l.nextID
	l.nextID++
	ch := make(chan Packet, 64)
	l.subscribers[id] = ch
	return id, ch
}

func (l *PacketLog) Unsubscribe(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ch, ok := l.subscribers[id]; ok {
		close(ch)
		delete(l.subscribers, id)
	}
}

type CaptureManager struct {
	mu       sync.Mutex
	captures map[int]*managedCapture
	log      *PacketLog
}

type managedCapture struct {
	capture Capture
	cancel  context.CancelFunc
}

func NewCaptureManager(packetLog *PacketLog) *CaptureManager {
	return &CaptureManager{
		captures: make(map[int]*managedCapture),
		log:      packetLog,
	}
}

func (m *CaptureManager) Sync(ports map[int]CaptureConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for port, mc := range m.captures {
		if _, ok := ports[port]; !ok {
			m.stopCapture(mc)
			delete(m.captures, port)
		}
	}

	for port, cfg := range ports {
		if _, ok := m.captures[port]; ok {
			continue
		}
		cap := NewCapture(cfg)
		ctx, cancel := context.WithCancel(context.Background())
		if err := cap.Start(ctx); err != nil {
			cancel()
			continue
		}
		mc := &managedCapture{capture: cap, cancel: cancel}
		m.captures[port] = mc
		go m.drain(ctx, cap)
	}
}

func (m *CaptureManager) drain(ctx context.Context, cap Capture) {
	for {
		select {
		case pkt, ok := <-cap.Packets():
			if !ok {
				return
			}
			m.log.Record(pkt)
		case <-ctx.Done():
			return
		}
	}
}

func (m *CaptureManager) stopCapture(mc *managedCapture) {
	mc.cancel()
	mc.capture.Wait()
}

func (m *CaptureManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, mc := range m.captures {
		m.stopCapture(mc)
		delete(m.captures, port)
	}
}
