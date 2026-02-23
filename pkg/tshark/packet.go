package tshark

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Packet struct {
	Number    uint64
	Timestamp time.Time
	Protocol  string
	Length    int
	Src       netip.AddrPort
	Dst       netip.AddrPort
	layers    map[string]json.RawMessage
	raw       json.RawMessage
}

func (p *Packet) HasLayer(name string) bool {
	_, ok := p.layers[strings.ToLower(name)]
	return ok
}

func (p *Packet) Layer(name string) (json.RawMessage, bool) {
	raw, ok := p.layers[strings.ToLower(name)]
	return raw, ok
}

func (p *Packet) LayerNames() []string {
	names := make([]string, 0, len(p.layers))
	for name := range p.layers {
		names = append(names, name)
	}
	return names
}

func (p *Packet) TCP() (*TCPLayer, error) {
	raw, ok := p.layers["tcp"]
	if !ok {
		return nil, ErrLayerNotFound
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	return parseTCPLayer(fields), nil
}

func (p *Packet) PgSQL() ([]PgSQLMessage, error) {
	raw, ok := p.layers["pgsql"]
	if !ok {
		return nil, ErrLayerNotFound
	}
	return parsePgSQLLayer(raw)
}

func (p *Packet) Raw() json.RawMessage {
	return p.raw
}

func ParseEKPacket(line []byte) (*Packet, error) {
	raw := make(json.RawMessage, len(line))
	copy(raw, line)

	var obj struct {
		Timestamp string                     `json:"timestamp"`
		Layers    map[string]json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}

	pkt := &Packet{
		layers: make(map[string]json.RawMessage),
		raw:    raw,
	}

	if obj.Timestamp != "" {
		if ms, err := strconv.ParseInt(obj.Timestamp, 10, 64); err == nil {
			pkt.Timestamp = time.UnixMilli(ms)
		}
	}

	if frameRaw, ok := obj.Layers["frame"]; ok {
		var frame map[string]any
		if err := json.Unmarshal(frameRaw, &frame); err == nil {
			if num := ekString(frame, "frame_frame_number"); num != "" {
				pkt.Number, _ = strconv.ParseUint(num, 10, 64)
			}
			if length := ekString(frame, "frame_frame_len"); length != "" {
				pkt.Length, _ = strconv.Atoi(length)
			}
			if proto := ekString(frame, "frame_frame_protocols"); proto != "" {
				parts := strings.Split(proto, ":")
				if len(parts) > 0 {
					pkt.Protocol = parts[len(parts)-1]
				}
			}
		}
	}

	var srcIP, dstIP netip.Addr
	var srcPort, dstPort uint16

	if ipRaw, ok := obj.Layers["ip"]; ok {
		var ip map[string]any
		if err := json.Unmarshal(ipRaw, &ip); err == nil {
			if s := ekString(ip, "ip_ip_src"); s != "" {
				srcIP, _ = netip.ParseAddr(s)
			}
			if d := ekString(ip, "ip_ip_dst"); d != "" {
				dstIP, _ = netip.ParseAddr(d)
			}
		}
	}
	if ip6Raw, ok := obj.Layers["ipv6"]; ok {
		var ip6 map[string]any
		if err := json.Unmarshal(ip6Raw, &ip6); err == nil {
			if s := ekString(ip6, "ipv6_ipv6_src"); s != "" {
				srcIP, _ = netip.ParseAddr(s)
			}
			if d := ekString(ip6, "ipv6_ipv6_dst"); d != "" {
				dstIP, _ = netip.ParseAddr(d)
			}
		}
	}

	if tcpRaw, ok := obj.Layers["tcp"]; ok {
		var tcp map[string]any
		if err := json.Unmarshal(tcpRaw, &tcp); err == nil {
			if v := ekString(tcp, "tcp_tcp_srcport"); v != "" {
				if p, err := strconv.ParseUint(v, 10, 16); err == nil {
					srcPort = uint16(p)
				}
			}
			if v := ekString(tcp, "tcp_tcp_dstport"); v != "" {
				if p, err := strconv.ParseUint(v, 10, 16); err == nil {
					dstPort = uint16(p)
				}
			}
		}
	} else if udpRaw, ok := obj.Layers["udp"]; ok {
		var udp map[string]any
		if err := json.Unmarshal(udpRaw, &udp); err == nil {
			if v := ekString(udp, "udp_udp_srcport"); v != "" {
				if p, err := strconv.ParseUint(v, 10, 16); err == nil {
					srcPort = uint16(p)
				}
			}
			if v := ekString(udp, "udp_udp_dstport"); v != "" {
				if p, err := strconv.ParseUint(v, 10, 16); err == nil {
					dstPort = uint16(p)
				}
			}
		}
	}

	if srcIP.IsValid() {
		pkt.Src = netip.AddrPortFrom(srcIP, srcPort)
	}
	if dstIP.IsValid() {
		pkt.Dst = netip.AddrPortFrom(dstIP, dstPort)
	}

	for name, raw := range obj.Layers {
		if name == "frame" {
			continue
		}
		pkt.layers[name] = raw
	}

	return pkt, nil
}

func IsIndexLine(line []byte) bool {
	if len(line) < 10 {
		return true
	}
	return line[1] == '"' && line[2] == 'i' && line[3] == 'n' && line[4] == 'd' && line[5] == 'e' && line[6] == 'x'
}

func ekString(obj map[string]any, key string) string {
	if v, ok := obj[key].(string); ok {
		return v
	}
	return ""
}

func ekBool(obj map[string]any, key string) bool {
	switch v := obj[key].(type) {
	case bool:
		return v
	case string:
		return v == "1" || v == "true"
	default:
		return false
	}
}

func ekPayloadBytes(obj map[string]any, key string) []byte {
	s := ekString(obj, key)
	if s == "" {
		return nil
	}
	b, _ := hex.DecodeString(s)
	return b
}
