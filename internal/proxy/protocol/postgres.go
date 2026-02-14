package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
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
	Direction Direction      `json:"direction"`
	Type      string         `json:"type"`
	Details   any            `json:"details,omitempty"`
	Endpoint  netip.AddrPort `json:"endpoint"`
	Raw       []byte         `json:"-"`
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
	maps.Copy(subs, l.subscribers)
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

func frontendMessageToDetails(m pgproto3.FrontendMessage) (string, any) {
	switch msg := m.(type) {
	case *pgproto3.StartupMessage:
		return "StartupMessage", map[string]any{
			"protocol_version": msg.ProtocolVersion,
			"parameters":       msg.Parameters,
		}
	case *pgproto3.SSLRequest:
		return "SSLRequest", nil
	case *pgproto3.CancelRequest:
		return "CancelRequest", map[string]any{
			"process_id": msg.ProcessID,
			"secret_key": msg.SecretKey,
		}
	case *pgproto3.GSSEncRequest:
		return "GSSEncRequest", nil
	case *pgproto3.Query:
		return "Query", map[string]any{"query": msg.String}
	case *pgproto3.Parse:
		return "Parse", map[string]any{"name": msg.Name, "query": msg.Query}
	case *pgproto3.Bind:
		return "Bind", map[string]any{
			"portal":             msg.DestinationPortal,
			"prepared_statement": msg.PreparedStatement,
			"parameter_count":    len(msg.Parameters),
		}
	case *pgproto3.Execute:
		return "Execute", map[string]any{"portal": msg.Portal, "max_rows": msg.MaxRows}
	case *pgproto3.Describe:
		return "Describe", map[string]any{"object_type": string(msg.ObjectType), "name": msg.Name}
	case *pgproto3.Close:
		return "Close", map[string]any{"object_type": string(msg.ObjectType), "name": msg.Name}
	case *pgproto3.Sync:
		return "Sync", nil
	case *pgproto3.Terminate:
		return "Terminate", nil
	case *pgproto3.Flush:
		return "Flush", nil
	case *pgproto3.CopyData:
		return "CopyData", map[string]any{"length": len(msg.Data)}
	case *pgproto3.CopyDone:
		return "CopyDone", nil
	case *pgproto3.CopyFail:
		return "CopyFail", map[string]any{"message": msg.Message}
	case *pgproto3.FunctionCall:
		return "FunctionCall", map[string]any{"function": msg.Function}
	case *pgproto3.PasswordMessage:
		return "PasswordMessage", nil
	case *pgproto3.SASLInitialResponse:
		return "SASLInitialResponse", map[string]any{"mechanism": msg.AuthMechanism}
	case *pgproto3.SASLResponse:
		return "SASLResponse", nil
	default:
		return fmt.Sprintf("Unknown(%T)", m), nil
	}
}

func backendMessageToDetails(m pgproto3.BackendMessage) (string, any) {
	switch msg := m.(type) {
	case *pgproto3.AuthenticationOk:
		return "AuthenticationOk", nil
	case *pgproto3.AuthenticationCleartextPassword:
		return "AuthenticationCleartextPassword", nil
	case *pgproto3.AuthenticationMD5Password:
		return "AuthenticationMD5Password", nil
	case *pgproto3.AuthenticationSASL:
		return "AuthenticationSASL", map[string]any{"mechanisms": msg.AuthMechanisms}
	case *pgproto3.AuthenticationSASLContinue:
		return "AuthenticationSASLContinue", nil
	case *pgproto3.AuthenticationSASLFinal:
		return "AuthenticationSASLFinal", nil
	case *pgproto3.AuthenticationGSS:
		return "AuthenticationGSS", nil
	case *pgproto3.AuthenticationGSSContinue:
		return "AuthenticationGSSContinue", nil
	case *pgproto3.BackendKeyData:
		return "BackendKeyData", map[string]any{
			"process_id": msg.ProcessID,
			"secret_key": msg.SecretKey,
		}
	case *pgproto3.ParameterStatus:
		return "ParameterStatus", map[string]any{"name": msg.Name, "value": msg.Value}
	case *pgproto3.ReadyForQuery:
		return "ReadyForQuery", map[string]any{"transaction_status": string(msg.TxStatus)}
	case *pgproto3.RowDescription:
		fields := make([]map[string]any, len(msg.Fields))
		for i, f := range msg.Fields {
			fields[i] = map[string]any{
				"name":      string(f.Name),
				"table_oid": f.TableOID,
				"data_type": f.DataTypeOID,
			}
		}
		return "RowDescription", map[string]any{"fields": fields}
	case *pgproto3.DataRow:
		values := make([]string, len(msg.Values))
		for i, v := range msg.Values {
			if v == nil {
				values[i] = "<null>"
			} else {
				values[i] = string(v)
			}
		}
		return "DataRow", map[string]any{"values": values}
	case *pgproto3.CommandComplete:
		return "CommandComplete", map[string]any{"command_tag": string(msg.CommandTag)}
	case *pgproto3.ErrorResponse:
		return "ErrorResponse", map[string]any{
			"severity": msg.Severity,
			"code":     msg.Code,
			"message":  msg.Message,
			"detail":   msg.Detail,
		}
	case *pgproto3.NoticeResponse:
		return "NoticeResponse", map[string]any{"severity": msg.Severity, "message": msg.Message}
	case *pgproto3.ParseComplete:
		return "ParseComplete", nil
	case *pgproto3.BindComplete:
		return "BindComplete", nil
	case *pgproto3.CloseComplete:
		return "CloseComplete", nil
	case *pgproto3.NoData:
		return "NoData", nil
	case *pgproto3.PortalSuspended:
		return "PortalSuspended", nil
	case *pgproto3.ParameterDescription:
		return "ParameterDescription", nil
	case *pgproto3.EmptyQueryResponse:
		return "EmptyQueryResponse", nil
	case *pgproto3.CopyInResponse:
		return "CopyInResponse", nil
	case *pgproto3.CopyOutResponse:
		return "CopyOutResponse", nil
	case *pgproto3.CopyBothResponse:
		return "CopyBothResponse", nil
	case *pgproto3.CopyData:
		return "CopyData", map[string]any{"length": len(msg.Data)}
	case *pgproto3.CopyDone:
		return "CopyDone", nil
	case *pgproto3.NotificationResponse:
		return "NotificationResponse", map[string]any{
			"channel": msg.Channel,
			"payload": msg.Payload,
			"pid":     msg.PID,
		}
	case *pgproto3.FunctionCallResponse:
		return "FunctionCallResponse", nil
	default:
		return fmt.Sprintf("Unknown(%T)", m), nil
	}
}

func ParseFrontendMessages(data []byte) []*PgMessage {
	if len(data) < 4 {
		return nil
	}

	now := time.Now()
	r := bytes.NewReader(data)
	backend := pgproto3.NewBackend(r, nil)

	if isStartupMessage(data) {
		startupMsg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return []*PgMessage{{
				Timestamp: now,
				Direction: DirectionClientToServer,
				Type:      "StartupMessage",
				Details: map[string]any{
					"error":      err.Error(),
					"partial":    true,
					"bytes_recv": len(data),
				},
			}}
		}
		typeName, details := frontendMessageToDetails(startupMsg)
		return []*PgMessage{{
			Timestamp: now,
			Direction: DirectionClientToServer,
			Type:      typeName,
			Details:   details,
		}}
	}

	var msgs []*PgMessage
	for {
		m, err := backend.Receive()
		if err != nil {
			break
		}
		typeName, details := frontendMessageToDetails(m)
		msgs = append(msgs, &PgMessage{
			Timestamp: now,
			Direction: DirectionClientToServer,
			Type:      typeName,
			Details:   details,
		})
	}
	return msgs
}

func ParseBackendMessages(data []byte) []*PgMessage {
	if len(data) < 5 {
		return nil
	}

	now := time.Now()
	r := bytes.NewReader(data)
	frontend := pgproto3.NewFrontend(r, nil)

	var msgs []*PgMessage
	for {
		m, err := frontend.Receive()
		if err != nil {
			break
		}
		typeName, details := backendMessageToDetails(m)
		msgs = append(msgs, &PgMessage{
			Timestamp: now,
			Direction: DirectionServerToClient,
			Type:      typeName,
			Details:   details,
		})
	}
	return msgs
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
