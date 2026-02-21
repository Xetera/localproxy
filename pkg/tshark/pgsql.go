package tshark

import (
	"encoding/json"
	"strconv"
	"strings"
)

type PgSQLMessage interface {
	pgMsg()
	MessageType() string
}

type PgStartup struct {
	Parameters []PgParameter
	Length     int
}

type PgParameter struct {
	Name  string
	Value string
}

type PgAuthRequest struct {
	AuthType int
	Length   int
}

type PgQuery struct {
	Query  string
	Length int
}

type PgParse struct {
	Statement string
	Query     string
	Length    int
}

type PgBind struct {
	Portal    string
	Statement string
	Length    int
}

type PgError struct {
	Severity string
	Code     string
	Message  string
	File     string
	Line     string
	Routine  string
	Length   int
}

type PgParameterStatus struct {
	Name   string
	Value  string
	Length int
}

type PgUnknown struct {
	Type   string
	Length int
	Fields map[string]any
}

func (PgStartup) pgMsg()         {}
func (PgAuthRequest) pgMsg()     {}
func (PgQuery) pgMsg()           {}
func (PgParse) pgMsg()           {}
func (PgBind) pgMsg()            {}
func (PgError) pgMsg()           {}
func (PgParameterStatus) pgMsg() {}
func (PgUnknown) pgMsg()         {}

func (PgStartup) MessageType() string         { return "Startup message" }
func (PgAuthRequest) MessageType() string     { return "Authentication request" }
func (PgQuery) MessageType() string           { return "Simple query" }
func (PgParse) MessageType() string           { return "Parse" }
func (PgBind) MessageType() string            { return "Bind" }
func (PgError) MessageType() string           { return "Error" }
func (PgParameterStatus) MessageType() string { return "Parameter status" }
func (m PgUnknown) MessageType() string       { return m.Type }

func parsePgSQLLayer(raw json.RawMessage) ([]PgSQLMessage, error) {
	var pgsql any
	if err := json.Unmarshal(raw, &pgsql); err != nil {
		return nil, err
	}

	var pgsqlMaps []map[string]any
	switch v := pgsql.(type) {
	case map[string]any:
		pgsqlMaps = append(pgsqlMaps, v)
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				pgsqlMaps = append(pgsqlMaps, m)
			}
		}
	default:
		return nil, nil
	}

	if len(pgsqlMaps) == 0 {
		return nil, nil
	}

	var messages []PgSQLMessage
	for _, pgsqlMap := range pgsqlMaps {
		clean := trimPrefixes(pgsqlMap, "pgsql_pgsql_")
		typ := ekString(clean, "type")
		if typ == "" {
			continue
		}
		length, _ := strconv.Atoi(ekString(clean, "length"))

		switch typ {
		case "Startup message":
			msg := PgStartup{Length: length}
			names := ekStringSlice(clean, "parameter_name")
			values := ekStringSlice(clean, "parameter_value")
			for i := range names {
				if i < len(values) {
					msg.Parameters = append(msg.Parameters, PgParameter{Name: names[i], Value: values[i]})
				}
			}
			messages = append(messages, msg)

		case "Authentication request":
			authType, _ := strconv.Atoi(ekString(clean, "authtype"))
			messages = append(messages, PgAuthRequest{AuthType: authType, Length: length})

		case "Simple query":
			messages = append(messages, PgQuery{
				Query:  ekString(clean, "query"),
				Length: length,
			})

		case "Parse":
			messages = append(messages, PgParse{
				Statement: ekString(clean, "statement"),
				Query:     ekString(clean, "query"),
				Length:    length,
			})

		case "Bind":
			messages = append(messages, PgBind{
				Portal:    ekString(clean, "portal"),
				Statement: ekString(clean, "statement"),
				Length:    length,
			})

		case "Error":
			messages = append(messages, PgError{
				Severity: ekString(clean, "severity"),
				Code:     ekString(clean, "code"),
				Message:  ekString(clean, "message"),
				File:     ekString(clean, "file"),
				Line:     ekString(clean, "line"),
				Routine:  ekString(clean, "routine"),
				Length:   length,
			})

		case "Parameter status":
			messages = append(messages, PgParameterStatus{
				Name:   ekString(clean, "parameter_name"),
				Value:  ekString(clean, "parameter_value"),
				Length: length,
			})

		default:
			messages = append(messages, PgUnknown{
				Type:   typ,
				Length: length,
				Fields: clean,
			})
		}
	}

	return messages, nil
}

func ekStringSlice(obj map[string]any, key string) []string {
	switch v := obj[key].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func trimPrefixes(obj map[string]any, prefix string) map[string]any {
	result := make(map[string]any, len(obj))
	for key, value := range obj {
		result[strings.TrimPrefix(key, prefix)] = value
	}
	return result
}
