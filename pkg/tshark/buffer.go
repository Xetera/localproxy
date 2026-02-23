package tshark

import "sync"

const defaultBufferSize = 1000

type PacketBuffer struct {
	mu      sync.Mutex
	packets []*Packet
	head    int
	count   int
	size    int

	subsMu sync.Mutex
	subs   []chan *Packet
}

func NewPacketBuffer() *PacketBuffer {
	return &PacketBuffer{
		packets: make([]*Packet, defaultBufferSize),
		size:    defaultBufferSize,
		subs:    make([]chan *Packet, 0),
	}
}

func (b *PacketBuffer) index(i int) int {
	return (b.head + i) % b.size
}

func (b *PacketBuffer) Add(pkt *Packet) {
	b.mu.Lock()
	idx := b.index(b.count)
	if b.count == b.size {
		b.head = b.index(1)
	} else {
		b.count++
	}
	b.packets[idx] = pkt
	b.mu.Unlock()

	b.subsMu.Lock()
	for _, ch := range b.subs {
		select {
		case ch <- pkt:
		default:
		}
	}
	b.subsMu.Unlock()
}

func (b *PacketBuffer) Snapshot() []*Packet {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]*Packet, b.count)
	for i := 0; i < b.count; i++ {
		result[i] = b.packets[b.index(i)]
	}
	return result
}

func (b *PacketBuffer) Subscribe() chan *Packet {
	ch := make(chan *Packet, 64)
	b.subsMu.Lock()
	b.subs = append(b.subs, ch)
	b.subsMu.Unlock()
	return ch
}

func (b *PacketBuffer) Get(number uint64) *Packet {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := 0; i < b.count; i++ {
		pkt := b.packets[b.index(i)]
		if pkt.Number == number {
			return pkt
		}
	}
	return nil
}

func (b *PacketBuffer) Unsubscribe(ch chan *Packet) {
	b.subsMu.Lock()
	for i, sub := range b.subs {
		if sub == ch {
			b.subs = append(b.subs[:i], b.subs[i+1:]...)
			break
		}
	}
	b.subsMu.Unlock()
}
