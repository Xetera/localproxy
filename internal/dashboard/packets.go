package dashboard

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/xetera/localproxy/pkg/tshark"
)

type packetDetailField struct {
	Label string
	Value string
	Mono  bool
}

type packetDetailMessage struct {
	Type   string
	Fields []packetDetailField
}

func (s *DashboardServer) servePackets(w http.ResponseWriter, r *http.Request) {
	subdomain := r.URL.Query().Get("subdomain")
	if subdomain == "" {
		http.Error(w, "subdomain parameter required", http.StatusBadRequest)
		return
	}

	s.backendsMu.RLock()
	backend, exists := s.backends[subdomain]
	s.backendsMu.RUnlock()

	if !exists {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}

	if s.packetSource == nil {
		http.Error(w, "packet capture not available", http.StatusServiceUnavailable)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	buf := s.packetSource.PacketBuffer(backend.Endpoint)
	if buf == nil {
		<-r.Context().Done()
		return
	}

	ch := buf.Subscribe()
	defer buf.Unsubscribe(ch)

	servicePort := backend.Endpoint.Port()

	snapshot := buf.Snapshot()
	for _, pkt := range snapshot {
		s.writePacketEvent(w, pkt, servicePort, subdomain)
	}
	flusher.Flush()

	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			s.writePacketEvent(w, pkt, servicePort, subdomain)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *DashboardServer) writePacketEvent(w http.ResponseWriter, pkt *tshark.Packet, servicePort uint16, subdomain string) {
	direction := "request"
	if pkt.Src.Port() == servicePort {
		direction = "response"
	}
	var pgPreview []string
	if msgs, err := pkt.PgSQL(); err == nil {
		for _, msg := range msgs {
			pgPreview = append(pgPreview, msg.MessageType())
		}
	}

	var buf bytes.Buffer
	s.packetRowTmpl.Execute(&buf, map[string]any{
		"Timestamp": pkt.Timestamp.Format("15:04:05.000"),
		"Src":       pkt.Src.String(),
		"Dst":       pkt.Dst.String(),
		"Protocol":  pkt.Protocol,
		"Length":    pkt.Length,
		"Direction": direction,
		"Number":    pkt.Number,
		"Subdomain": subdomain,
		"PgPreview": pgPreview,
	})
	fmt.Fprintf(w, "event: packet\n")
	for line := range strings.SplitSeq(buf.String(), "\n") {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprintf(w, "\n")
}

func (s *DashboardServer) servePacketDetail(w http.ResponseWriter, r *http.Request) {
	subdomain := r.URL.Query().Get("subdomain")
	numberStr := r.URL.Query().Get("number")
	if subdomain == "" || numberStr == "" {
		http.Error(w, "subdomain and number required", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseUint(numberStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid packet number", http.StatusBadRequest)
		return
	}

	s.backendsMu.RLock()
	backend, exists := s.backends[subdomain]
	s.backendsMu.RUnlock()

	if !exists {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}

	if s.packetSource == nil {
		http.Error(w, "packet capture not available", http.StatusServiceUnavailable)
		return
	}

	buf := s.packetSource.PacketBuffer(backend.Endpoint)
	if buf == nil {
		http.Error(w, "no packet buffer", http.StatusNotFound)
		return
	}

	pkt := buf.Get(number)
	if pkt == nil {
		http.Error(w, "packet not found", http.StatusNotFound)
		return
	}

	data := map[string]any{
		"Number": pkt.Number,
		"Length": pkt.Length,
		"Layers": pkt.LayerNames(),
	}

	if tcp, err := pkt.TCP(); err == nil {
		var flags []string
		if tcp.Flags.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.Flags.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.Flags.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.Flags.RST {
			flags = append(flags, "RST")
		}
		if tcp.Flags.PSH {
			flags = append(flags, "PSH")
		}
		if tcp.Flags.URG {
			flags = append(flags, "URG")
		}
		flagsStr := strings.Join(flags, " ")
		if flagsStr == "" {
			flagsStr = "(none)"
		}
		data["TCP"] = map[string]any{
			"Seq":        tcp.Seq,
			"Ack":        tcp.Ack,
			"FlagsStr":   flagsStr,
			"Window":     tcp.Window,
			"PayloadLen": len(tcp.Payload),
		}
	}

	if msgs, err := pkt.PgSQL(); err == nil && len(msgs) > 0 {
		var pgMessages []packetDetailMessage
		for _, msg := range msgs {
			dm := packetDetailMessage{Type: msg.MessageType()}
			switch m := msg.(type) {
			case tshark.PgQuery:
				dm.Fields = append(dm.Fields, packetDetailField{"Query", m.Query, true})
			case tshark.PgParse:
				if m.Statement != "" {
					dm.Fields = append(dm.Fields, packetDetailField{"Statement", m.Statement, false})
				}
				dm.Fields = append(dm.Fields, packetDetailField{"Query", m.Query, true})
			case tshark.PgBind:
				if m.Portal != "" {
					dm.Fields = append(dm.Fields, packetDetailField{"Portal", m.Portal, false})
				}
				if m.Statement != "" {
					dm.Fields = append(dm.Fields, packetDetailField{"Statement", m.Statement, false})
				}
			case tshark.PgError:
				dm.Fields = append(dm.Fields, packetDetailField{"Severity", m.Severity, false})
				dm.Fields = append(dm.Fields, packetDetailField{"Code", m.Code, true})
				dm.Fields = append(dm.Fields, packetDetailField{"Message", m.Message, false})
			case tshark.PgStartup:
				for _, p := range m.Parameters {
					dm.Fields = append(dm.Fields, packetDetailField{p.Name, p.Value, false})
				}
			case tshark.PgParameterStatus:
				dm.Fields = append(dm.Fields, packetDetailField{m.Name, m.Value, false})
			case tshark.PgAuthRequest:
				dm.Fields = append(dm.Fields, packetDetailField{"Auth Type", strconv.Itoa(m.AuthType), false})
			case tshark.PgRowDescription:
				dm.Fields = append(dm.Fields, packetDetailField{"Columns", strconv.Itoa(len(m.Columns)), false})
				for _, col := range m.Columns {
					dm.Fields = append(dm.Fields, packetDetailField{col.Name, "type=" + col.TypeOID, true})
				}
			case tshark.PgDataRow:
				for i, v := range m.Values {
					dm.Fields = append(dm.Fields, packetDetailField{"[" + strconv.Itoa(i) + "]", v, true})
				}
			}
			pgMessages = append(pgMessages, dm)
		}
		data["PgMessages"] = pgMessages
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.packetDetailTmpl.Execute(w, data); err != nil {
		log.Printf("packet detail template error: %v", err)
	}
}
