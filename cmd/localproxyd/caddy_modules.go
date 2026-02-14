package main

import (
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4proxy"
	"github.com/mholt/caddy-l4/modules/l4tls"
	"github.com/xetera/localproxy/internal/proxy/protocol"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(TapHandler{})
	caddy.RegisterModule(MemoryLogWriter{})
}

type AccessLogEntry struct {
	Timestamp   time.Time           `json:"ts"`
	Level       string              `json:"level"`
	Logger      string              `json:"logger"`
	Message     string              `json:"msg"`
	Request     map[string]any      `json:"request,omitempty"`
	Duration    float64             `json:"duration,omitempty"`
	Size        int                 `json:"size,omitempty"`
	Status      int                 `json:"status,omitempty"`
	RespHeaders map[string][]string `json:"resp_headers,omitempty"`
	Raw         map[string]any      `json:"raw,omitempty"`
}

var (
	accessLogs   []AccessLogEntry
	accessLogsMu sync.RWMutex
)

func GetAccessLogs() []AccessLogEntry {
	accessLogsMu.RLock()
	defer accessLogsMu.RUnlock()
	result := make([]AccessLogEntry, len(accessLogs))
	copy(result, accessLogs)
	return result
}

type MemoryLogWriter struct{}

func (MemoryLogWriter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.writers.memory",
		New: func() caddy.Module { return new(MemoryLogWriter) },
	}
}

func (m *MemoryLogWriter) String() string {
	return "memory"
}

func (m *MemoryLogWriter) WriterKey() string {
	return m.String()
}

func (m *MemoryLogWriter) OpenWriter() (io.WriteCloser, error) {
	return &memoryLogSink{}, nil
}

type memoryLogSink struct{}

func (s *memoryLogSink) Write(p []byte) (n int, err error) {
	os.Stdout.Write(p)

	var entry map[string]any
	if err := json.Unmarshal(p, &entry); err != nil {
		return len(p), nil
	}

	logEntry := AccessLogEntry{
		Timestamp: time.Now(),
		Raw:       entry,
	}

	if ts, ok := entry["ts"].(float64); ok {
		logEntry.Timestamp = time.Unix(int64(ts), int64((ts-float64(int64(ts)))*1e9))
	}
	if level, ok := entry["level"].(string); ok {
		logEntry.Level = level
	}
	if logger, ok := entry["logger"].(string); ok {
		logEntry.Logger = logger
	}
	if msg, ok := entry["msg"].(string); ok {
		logEntry.Message = msg
	}
	if req, ok := entry["request"].(map[string]any); ok {
		logEntry.Request = req
	}
	if dur, ok := entry["duration"].(float64); ok {
		logEntry.Duration = dur
	}
	if size, ok := entry["size"].(float64); ok {
		logEntry.Size = int(size)
	}
	if status, ok := entry["status"].(float64); ok {
		logEntry.Status = int(status)
	}

	accessLogsMu.Lock()
	accessLogs = append(accessLogs, logEntry)
	if len(accessLogs) > 1000 {
		accessLogs = accessLogs[1:]
	}
	accessLogsMu.Unlock()

	return len(p), nil
}

func (s *memoryLogSink) Close() error {
	return nil
}

type ConnectionEvent struct {
	Timestamp  time.Time
	RemoteAddr string
	BytesIn    int64
	BytesOut   int64
	Duration   time.Duration
}

var (
	connectionEvents   []ConnectionEvent
	connectionEventsMu sync.RWMutex
)

type TapHandler struct {
	ParseProtocol bool `json:"parse_protocol,omitempty"`
	logger        *zap.Logger
	pgLog         *protocol.PgMessageLog
}

func (TapHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.tap",
		New: func() caddy.Module { return new(TapHandler) },
	}
}

func (h *TapHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	h.pgLog = protocol.NewPgMessageLog(1000)
	return nil
}

func (h *TapHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	start := time.Now()
	remoteAddr := cx.RemoteAddr().String()

	var remoteAddrPort netip.AddrPort
	var addressParsed bool
	switch addr := cx.RemoteAddr().(type) {
	case *net.TCPAddr:
		ipBytes := addr.IP
		if addr.IP.To4() != nil {
			ipBytes = addr.IP.To4()
		} else if addr.IP.To16() != nil {
			ipBytes = addr.IP.To16()
		}
		netipAddr, parseOk := netip.AddrFromSlice(ipBytes)
		addressParsed = parseOk
		if addressParsed {
			remoteAddrPort = netip.AddrPortFrom(netipAddr, uint16(addr.Port))
		}
	case *net.UDPAddr:
		ipBytes := addr.IP
		if addr.IP.To4() != nil {
			ipBytes = addr.IP.To4()
		} else if addr.IP.To16() != nil {
			ipBytes = addr.IP.To16()
		}
		netipAddr, parseOk := netip.AddrFromSlice(ipBytes)
		addressParsed = parseOk
		if addressParsed {
			remoteAddrPort = netip.AddrPortFrom(netipAddr, uint16(addr.Port))
		}
	}

	wrapped := &tappedConn{
		Conn:       cx.Conn,
		remoteAddr: remoteAddr,
		start:      start,
		logger:     h.logger,
		parseProto: addressParsed && h.ParseProtocol,
		addrPort:   remoteAddrPort,
		pgLog:      h.pgLog,
	}
	cx.Conn = wrapped

	h.logger.Info("connection started", zap.String("remote", remoteAddr))

	err := next.Handle(cx)

	event := ConnectionEvent{
		Timestamp:  start,
		RemoteAddr: remoteAddr,
		BytesIn:    wrapped.bytesIn,
		BytesOut:   wrapped.bytesOut,
		Duration:   time.Since(start),
	}

	connectionEventsMu.Lock()
	connectionEvents = append(connectionEvents, event)
	if len(connectionEvents) > 1000 {
		connectionEvents = connectionEvents[1:]
	}
	connectionEventsMu.Unlock()

	h.logger.Info("connection ended",
		zap.String("remote", remoteAddr),
		zap.Int64("bytes_in", wrapped.bytesIn),
		zap.Int64("bytes_out", wrapped.bytesOut),
		zap.Duration("duration", event.Duration),
	)

	return err
}

type tappedConn struct {
	net.Conn
	remoteAddr string
	start      time.Time
	bytesIn    int64
	bytesOut   int64
	logger     *zap.Logger
	parseProto bool
	addrPort   netip.AddrPort
	pgLog      *protocol.PgMessageLog
}

func (c *tappedConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	c.bytesIn += int64(n)
	if n > 0 && c.parseProto {
		if msg := protocol.ParseFrontendMessage(p[:n]); msg != nil {
			c.pgLog.Record(c.addrPort, *msg)
			c.logger.Info("pg frontend message",
				zap.String("type", msg.Type),
				zap.Any("details", msg.Details),
			)
		}
	}
	return
}

func (c *tappedConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	c.bytesOut += int64(n)
	if n > 0 && c.parseProto {
		if msg := protocol.ParseBackendMessage(p[:n]); msg != nil {
			c.pgLog.Record(c.addrPort, *msg)
			c.logger.Info("pg backend message",
				zap.String("type", msg.Type),
				zap.Any("details", msg.Details),
			)
		}
	}
	return
}

func mustHandler(name string, h any) json.RawMessage {
	b, err := json.Marshal(h)
	if err != nil {
		panic(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	m["handler"] = name
	out, _ := json.Marshal(m)
	return out
}

func BuildL4Config(certPath string) (*layer4.App, error) {
	tlsHandler := &l4tls.Handler{
		ConnectionPolicies: caddytls.ConnectionPolicies{
			&caddytls.ConnectionPolicy{
				ALPN: []string{"postgresql"},
			},
		},
	}

	proxyHandler := &l4proxy.Handler{
		Upstreams: l4proxy.UpstreamPool{
			&l4proxy.Upstream{
				Dial: []string{"localhost:5555"},
			},
		},
	}

	return &layer4.App{
		Servers: map[string]*layer4.Server{
			"postgres_proxy": {
				Listen: []string{"tcp/:5432"},
				Routes: layer4.RouteList{
					&layer4.Route{
						MatcherSetsRaw: []caddy.ModuleMap{
							{"tls": json.RawMessage(`{}`)},
						},
						HandlersRaw: []json.RawMessage{
							mustHandler("tls", tlsHandler),
							mustHandler("tap", &TapHandler{ParseProtocol: true}),
							mustHandler("proxy", proxyHandler),
						},
					},
					&layer4.Route{
						HandlersRaw: []json.RawMessage{
							mustHandler("tap", &TapHandler{ParseProtocol: true}),
							mustHandler("proxy", proxyHandler),
						},
					},
				},
			},
		},
	}, nil
}
