package protocol

import (
	"maps"
	"context"
	"fmt"
	"sync"

	"github.com/xetera/localproxy/pkg/tshark"
)

type PacketLog struct {
	mu          sync.RWMutex
	packets     []*tshark.Packet
	limit       int
	subscribers map[uint64]chan *tshark.Packet
	nextID      uint64
}

func NewPacketLog(limit int) *PacketLog {
	return &PacketLog{
		packets:     make([]*tshark.Packet, 0, limit),
		limit:       limit,
		subscribers: make(map[uint64]chan *tshark.Packet),
	}
}

func (l *PacketLog) Record(pkt *tshark.Packet) {
	l.mu.Lock()
	l.packets = append(l.packets, pkt)
	if len(l.packets) > l.limit {
		l.packets = l.packets[1:]
	}
	subs := make(map[uint64]chan *tshark.Packet, len(l.subscribers))
	maps.Copy(subs, l.subscribers)
	l.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- pkt:
		default:
		}
	}
}

func (l *PacketLog) GetAll() []*tshark.Packet {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]*tshark.Packet, len(l.packets))
	copy(result, l.packets)
	return result
}

func (l *PacketLog) Subscribe() (uint64, <-chan *tshark.Packet) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id := l.nextID
	l.nextID++
	ch := make(chan *tshark.Packet, 64)
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
	capture *tshark.Capture
	cancel  context.CancelFunc
}

func NewCaptureManager(packetLog *PacketLog) *CaptureManager {
	return &CaptureManager{
		captures: make(map[int]*managedCapture),
		log:      packetLog,
	}
}

func (m *CaptureManager) Sync(ports map[int]tshark.CaptureConfig) {
	var toStop []*managedCapture

	m.mu.Lock()
	for port, mc := range m.captures {
		if _, ok := ports[port]; !ok {
			toStop = append(toStop, mc)
			delete(m.captures, port)
		}
	}

	for port, cfg := range ports {
		if _, ok := m.captures[port]; ok {
			continue
		}
		cap := tshark.NewCapture(cfg)
		ctx, cancel := context.WithCancel(context.Background())
		if err := cap.Start(ctx); err != nil {
			cancel()
			fmt.Printf("failed to start capture on port %d: %v\n", port, err)
			continue
		}
		mc := &managedCapture{capture: cap, cancel: cancel}
		m.captures[port] = mc
		go m.drain(ctx, cap)
	}
	m.mu.Unlock()

	for _, mc := range toStop {
		mc.cancel()
		mc.capture.Wait()
	}
}

func (m *CaptureManager) drain(ctx context.Context, cap *tshark.Capture) {
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

func (m *CaptureManager) Stop() {
	m.mu.Lock()
	captures := make([]*managedCapture, 0, len(m.captures))
	for port, mc := range m.captures {
		captures = append(captures, mc)
		delete(m.captures, port)
	}
	m.mu.Unlock()

	for _, mc := range captures {
		mc.cancel()
		mc.capture.Wait()
	}
}
