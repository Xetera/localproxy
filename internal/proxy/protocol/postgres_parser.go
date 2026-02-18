package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PgParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PgSQLCommand struct {
	Type            string      `json:"type"`
	ParameterStatus PgParameter `json:"parameter_status,omitzero"`
	Query           string      `json:"query,omitempty"`
	Statement       string      `json:"statement,omitempty"`
	Portal          string      `json:"portal,omitempty"`
	Prepare         string      `json:"prepare,omitempty"`
}

func trimPrefixes(obj map[string]any, prefix string) map[string]any {
	result := make(map[string]any, len(obj))
	for key, value := range obj {
		newKey := strings.TrimPrefix(key, prefix)
		result[newKey] = value
	}
	return result
}

func parsePgSQLLayer(raw json.RawMessage) []PgSQLCommand {
	var pgsql any
	if err := json.Unmarshal(raw, &pgsql); err != nil {
		return nil
	}
	fmt.Println("123", pgsql)

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
		return nil
	}

	if len(pgsqlMaps) == 0 {
		return nil
	}

	var commands []PgSQLCommand
	for _, pgsqlMap := range pgsqlMaps {
		cleanMap := trimPrefixes(pgsqlMap, "pgsql_pgsql_")
		cmd := PgSQLCommand{}

		if typ := ekStringField(cleanMap, "type"); typ != "" {
			cmd.Type = typ
		}

		if parameter := ekStringField(cleanMap, "parameter_name"); parameter != "" {
			if value := ekStringField(cleanMap, "parameter_value"); value != "" {
				cmd.ParameterStatus = PgParameter{Name: parameter, Value: value}
			}
		}

		if query := ekStringField(cleanMap, "query"); query != "" {
			cmd.Query = query
		}

		if stmt := ekStringField(cleanMap, "statement"); stmt != "" {
			cmd.Statement = stmt
		}

		if portal := ekStringField(cleanMap, "portal"); portal != "" {
			cmd.Portal = portal
		}

		if prep := ekStringField(cleanMap, "prepare"); prep != "" {
			cmd.Prepare = prep
		}

		if cmd.Type != "" {
			commands = append(commands, cmd)
		}
	}

	return commands
}
