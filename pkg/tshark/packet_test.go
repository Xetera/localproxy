package tshark

import (
	"bufio"
	"os"
	"testing"
)

func loadTestPackets(t *testing.T, path string) []*Packet {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var packets []*Packet
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if IsIndexLine(line) {
			continue
		}
		pkt, err := ParseEKPacket(line)
		if err != nil {
			t.Fatalf("parsing packet: %v", err)
		}
		packets = append(packets, pkt)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return packets
}

func TestParseTestData(t *testing.T) {
	packets := loadTestPackets(t, "testdata/psql.jsonl")
	if len(packets) == 0 {
		t.Fatal("expected at least one packet")
	}
}

func TestPacketFrame(t *testing.T) {
	packets := loadTestPackets(t, "testdata/psql.jsonl")
	pkt := packets[0]

	if pkt.Number != 43 {
		t.Errorf("expected frame number 43, got %d", pkt.Number)
	}
	if pkt.Length != 184 {
		t.Errorf("expected frame length 184, got %d", pkt.Length)
	}
	if pkt.Protocol != "pgsql" {
		t.Errorf("expected protocol pgsql, got %s", pkt.Protocol)
	}
	if pkt.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestPacketTCP(t *testing.T) {
	packets := loadTestPackets(t, "testdata/psql.jsonl")
	pkt := packets[0]

	tcp, err := pkt.TCP()
	if err != nil {
		t.Fatal(err)
	}

	if tcp.SrcPort != 5432 {
		t.Errorf("expected src port 5432, got %d", tcp.SrcPort)
	}
	if tcp.DstPort != 52770 {
		t.Errorf("expected dst port 52770, got %d", tcp.DstPort)
	}
	if tcp.Length != 108 {
		t.Errorf("expected tcp len 108, got %d", tcp.Length)
	}
	if !tcp.Flags.PSH {
		t.Error("expected PSH flag set")
	}
	if !tcp.Flags.ACK {
		t.Error("expected ACK flag set")
	}
	if tcp.Flags.SYN {
		t.Error("expected SYN flag unset")
	}
	if len(tcp.Payload) == 0 {
		t.Error("expected non-empty payload")
	}
}

func TestPacketPgSQL(t *testing.T) {
	packets := loadTestPackets(t, "testdata/psql.jsonl")
	pkt := packets[0]

	msgs, err := pkt.PgSQL()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 pgsql messages, got %d", len(msgs))
	}

	auth, ok := msgs[0].(PgAuthRequest)
	if !ok {
		t.Fatalf("expected PgAuthRequest, got %T", msgs[0])
	}
	if auth.AuthType != 0 {
		t.Errorf("expected auth type 0, got %d", auth.AuthType)
	}

	pgErr, ok := msgs[1].(PgError)
	if !ok {
		t.Fatalf("expected PgError, got %T", msgs[1])
	}
	if pgErr.Severity != "FATAL" {
		t.Errorf("expected severity FATAL, got %q", pgErr.Severity)
	}
	if pgErr.Code != "28000" {
		t.Errorf("expected code 28000, got %q", pgErr.Code)
	}
	if pgErr.Message != `role "xetera" does not exist` {
		t.Errorf("unexpected error message: %q", pgErr.Message)
	}
}

func TestHasLayer(t *testing.T) {
	packets := loadTestPackets(t, "testdata/psql.jsonl")
	pkt := packets[0]

	if !pkt.HasLayer("tcp") {
		t.Error("expected tcp layer")
	}
	if !pkt.HasLayer("pgsql") {
		t.Error("expected pgsql layer")
	}
	if pkt.HasLayer("dns") {
		t.Error("unexpected dns layer")
	}
}

func TestIsIndexLine(t *testing.T) {
	idx := []byte(`{"index":{"_index":"packets-2026-02-22"}}`)
	if !IsIndexLine(idx) {
		t.Error("expected index line to be detected")
	}
	pkt := []byte(`{"timestamp":"123","layers":{}}`)
	if IsIndexLine(pkt) {
		t.Error("expected packet line to not be detected as index")
	}
}
