package tshark

import (
	"strconv"
)

type TCPLayer struct {
	SrcPort  uint16
	DstPort  uint16
	Seq      uint32
	Ack      uint32
	Flags    TCPFlags
	Window   uint16
	Length   int
	Payload  []byte
	fields   map[string]any
}

type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
}

func (t *TCPLayer) Field(name string) (any, bool) {
	v, ok := t.fields["tcp_tcp_"+name]
	return v, ok
}

func parseTCPLayer(fields map[string]any) *TCPLayer {
	t := &TCPLayer{fields: fields}

	if v := ekString(fields, "tcp_tcp_srcport"); v != "" {
		if p, err := strconv.ParseUint(v, 10, 16); err == nil {
			t.SrcPort = uint16(p)
		}
	}
	if v := ekString(fields, "tcp_tcp_dstport"); v != "" {
		if p, err := strconv.ParseUint(v, 10, 16); err == nil {
			t.DstPort = uint16(p)
		}
	}
	if v := ekString(fields, "tcp_tcp_seq"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			t.Seq = uint32(n)
		}
	}
	if v := ekString(fields, "tcp_tcp_ack"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			t.Ack = uint32(n)
		}
	}
	if v := ekString(fields, "tcp_tcp_window_size_value"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err == nil {
			t.Window = uint16(n)
		}
	}
	if v := ekString(fields, "tcp_tcp_len"); v != "" {
		t.Length, _ = strconv.Atoi(v)
	}

	t.Payload = ekPayloadBytes(fields, "tcp_tcp_payload_raw")

	t.Flags.SYN = ekBool(fields, "tcp_tcp_flags_syn")
	t.Flags.ACK = ekBool(fields, "tcp_tcp_flags_ack")
	t.Flags.FIN = ekBool(fields, "tcp_tcp_flags_fin")
	t.Flags.RST = ekBool(fields, "tcp_tcp_flags_reset")
	t.Flags.PSH = ekBool(fields, "tcp_tcp_flags_push")
	t.Flags.URG = ekBool(fields, "tcp_tcp_flags_urg")

	return t
}
