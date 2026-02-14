package protocol

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

type Direction int

const (
	DirectionClientToServer Direction = 0
	DirectionServerToClient Direction = iota
)

type PgMessage struct {
	Timestamp time.Time      `json:"timestamp"`
	Direction Direction       `json:"direction"`
	Type      string          `json:"type"`
	Details   any             `json:"details,omitempty"`
	Endpoint  netip.AddrPort  `json:"endpoint"`
	Raw       []byte          `json:"-"`
}

type PgMessageLog struct {
	mu          sync.RWMutex
	messages    []PgMessage
	limit       int
	subscribers map[uint64]chan PgMessage
	nextID      uint64
}

func NewPgMessageLog(limit int) *PgMessageLog {
	return &PgMessageLog{
		messages:    make([]PgMessage, 0, limit),
		limit:       limit,
		subscribers: make(map[uint64]chan PgMessage),
	}
}

func (l *PgMessageLog) Record(msg PgMessage) {
	l.mu.Lock()
	l.messages = append(l.messages, msg)
	if len(l.messages) > l.limit {
		l.messages = l.messages[1:]
	}
	subs := make(map[uint64]chan PgMessage, len(l.subscribers))
	for id, ch := range l.subscribers {
		subs[id] = ch
	}
	l.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (l *PgMessageLog) GetAll() []PgMessage {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]PgMessage, len(l.messages))
	copy(result, l.messages)
	return result
}

func (l *PgMessageLog) Subscribe() (uint64, <-chan PgMessage) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id := l.nextID
	l.nextID++
	ch := make(chan PgMessage, 64)
	l.subscribers[id] = ch
	return id, ch
}

func (l *PgMessageLog) Unsubscribe(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ch, ok := l.subscribers[id]; ok {
		close(ch)
		delete(l.subscribers, id)
	}
}

func ParseFrontendMessage(data []byte) *PgMessage {
	if len(data) < 4 {
		return nil
	}

	msg := &PgMessage{
		Timestamp: time.Now(),
		Direction: DirectionClientToServer,
		Raw:       data,
	}

	if isStartupMessage(data) {
		r := bytes.NewReader(data)
		backend := pgproto3.NewBackend(r, nil)
		startupMsg, err := backend.ReceiveStartupMessage()
		if err != nil {
			msg.Type = "StartupMessage"
			msg.Details = map[string]any{
				"error":      err.Error(),
				"partial":    true,
				"bytes_recv": len(data),
			}
			return msg
		}

		switch m := startupMsg.(type) {
		case *pgproto3.StartupMessage:
			msg.Type = "StartupMessage"
			msg.Details = map[string]any{
				"protocol_version": m.ProtocolVersion,
				"parameters":       m.Parameters,
			}
		case *pgproto3.SSLRequest:
			msg.Type = "SSLRequest"
		case *pgproto3.CancelRequest:
			msg.Type = "CancelRequest"
			msg.Details = map[string]any{
				"process_id": m.ProcessID,
				"secret_key": m.SecretKey,
			}
		default:
			msg.Type = "UnknownStartup"
		}

		return msg
	}

	if len(data) < 5 {
		return nil
	}

	msgType := data[0]

	switch msgType {
	case 'Q':
		var q pgproto3.Query
		if err := q.Decode(data[5:]); err == nil {
			msg.Type = "Query"
			msg.Details = map[string]any{"query": q.String}
		}
	case 'P':
		var p pgproto3.Parse
		if err := p.Decode(data[5:]); err == nil {
			msg.Type = "Parse"
			msg.Details = map[string]any{
				"name":  p.Name,
				"query": p.Query,
			}
		}
	case 'B':
		var b pgproto3.Bind
		if err := b.Decode(data[5:]); err == nil {
			msg.Type = "Bind"
			msg.Details = map[string]any{
				"portal":             b.DestinationPortal,
				"prepared_statement": b.PreparedStatement,
				"parameter_count":    len(b.Parameters),
			}
		}
	case 'E':
		var e pgproto3.Execute
		if err := e.Decode(data[5:]); err == nil {
			msg.Type = "Execute"
			msg.Details = map[string]any{
				"portal":   e.Portal,
				"max_rows": e.MaxRows,
			}
		}
	case 'D':
		var d pgproto3.Describe
		if err := d.Decode(data[5:]); err == nil {
			msg.Type = "Describe"
			msg.Details = map[string]any{
				"object_type": string(d.ObjectType),
				"name":        d.Name,
			}
		}
	case 'C':
		var c pgproto3.Close
		if err := c.Decode(data[5:]); err == nil {
			msg.Type = "Close"
			msg.Details = map[string]any{
				"object_type": string(c.ObjectType),
				"name":        c.Name,
			}
		}
	case 'S':
		msg.Type = "Sync"
	case 'X':
		msg.Type = "Terminate"
	case 'p':
		msg.Type = "PasswordMessage"
	case 'H':
		msg.Type = "Flush"
	default:
		msg.Type = "Unknown"
		msg.Details = map[string]any{"type_byte": string(msgType)}
	}

	return msg
}

func ParseBackendMessage(data []byte) *PgMessage {
	if len(data) < 5 {
		return nil
	}

	msg := &PgMessage{
		Timestamp: time.Now(),
		Direction: DirectionServerToClient,
		Raw:       data,
	}

	msgType := data[0]

	switch msgType {
	case 'R':
		msg.Type = "Authentication"
		if len(data) >= 9 {
			authType := int32(data[5])<<24 | int32(data[6])<<16 | int32(data[7])<<8 | int32(data[8])
			msg.Details = map[string]any{"auth_type": authType}
		}
	case 'K':
		var k pgproto3.BackendKeyData
		if err := k.Decode(data[5:]); err == nil {
			msg.Type = "BackendKeyData"
			msg.Details = map[string]any{
				"process_id": k.ProcessID,
				"secret_key": k.SecretKey,
			}
		}
	case 'S':
		var s pgproto3.ParameterStatus
		if err := s.Decode(data[5:]); err == nil {
			msg.Type = "ParameterStatus"
			msg.Details = map[string]any{
				"name":  s.Name,
				"value": s.Value,
			}
		}
	case 'Z':
		var z pgproto3.ReadyForQuery
		if err := z.Decode(data[5:]); err == nil {
			msg.Type = "ReadyForQuery"
			msg.Details = map[string]any{
				"transaction_status": string(z.TxStatus),
			}
		}
	case 'T':
		var t pgproto3.RowDescription
		if err := t.Decode(data[5:]); err == nil {
			msg.Type = "RowDescription"
			fields := make([]map[string]any, len(t.Fields))
			for i, f := range t.Fields {
				fields[i] = map[string]any{
					"name":      string(f.Name),
					"table_oid": f.TableOID,
					"data_type": f.DataTypeOID,
				}
			}
			msg.Details = map[string]any{"fields": fields}
		}
	case 'D':
		var d pgproto3.DataRow
		if err := d.Decode(data[5:]); err == nil {
			msg.Type = "DataRow"
			values := make([]string, len(d.Values))
			for i, v := range d.Values {
				if v == nil {
					values[i] = "<null>"
				} else {
					values[i] = string(v)
				}
			}
			msg.Details = map[string]any{"values": values}
		}
	case 'C':
		var c pgproto3.CommandComplete
		if err := c.Decode(data[5:]); err == nil {
			msg.Type = "CommandComplete"
			msg.Details = map[string]any{"command_tag": string(c.CommandTag)}
		}
	case 'E':
		var e pgproto3.ErrorResponse
		if err := e.Decode(data[5:]); err == nil {
			msg.Type = "ErrorResponse"
			msg.Details = map[string]any{
				"severity": e.Severity,
				"code":     e.Code,
				"message":  e.Message,
				"detail":   e.Detail,
			}
		}
	case 'N':
		var n pgproto3.NoticeResponse
		if err := n.Decode(data[5:]); err == nil {
			msg.Type = "NoticeResponse"
			msg.Details = map[string]any{
				"severity": n.Severity,
				"message":  n.Message,
			}
		}
	case '1':
		msg.Type = "ParseComplete"
	case '2':
		msg.Type = "BindComplete"
	case '3':
		msg.Type = "CloseComplete"
	case 'n':
		msg.Type = "NoData"
	case 's':
		msg.Type = "PortalSuspended"
	case 't':
		msg.Type = "ParameterDescription"
	case 'I':
		msg.Type = "EmptyQueryResponse"
	default:
		msg.Type = "Unknown"
		msg.Details = map[string]any{"type_byte": string(msgType)}
	}

	return msg
}

func isStartupMessage(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	version := int(data[4])<<24 | int(data[5])<<16 | int(data[6])<<8 | int(data[7])
	return version == pgproto3.ProtocolVersionNumber ||
		version == 80877103 ||
		version == 80877102
}

func (m PgMessage) MarshalJSON() ([]byte, error) {
	type Alias PgMessage
	return json.Marshal(&struct {
		Alias
		Timestamp string `json:"timestamp"`
	}{
		Alias:     Alias(m),
		Timestamp: m.Timestamp.Format(time.RFC3339Nano),
	})
}
