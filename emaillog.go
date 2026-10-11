package pocketid

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// emailFailureMessage is what Pocket ID logs when a one-time access email it
// accepted fails to send, with the error and the address as attributes
// (onetimeaccess/service.go:126-129 at v2.14.0). A send that succeeds logs
// nothing.
const emailFailureMessage = "Failed to send one-time access token email"

// LogCommand reads the Pocket ID service's log over the last window, from the
// compose project it runs in. The project is the deployment's
// (deployment.Project), so nothing else in the command varies.
func LogCommand(project string, window time.Duration) string {
	return fmt.Sprintf("docker compose -p '%s' logs --no-color --no-log-prefix --since %ds app 2>&1",
		strings.ReplaceAll(project, "'", `'\''`), int(window.Round(time.Second)/time.Second))
}

// EmailFailure finds the error Pocket ID logged for a failed login link email
// to address, in its log as LogCommand reads it. The log is Pocket ID's text
// format, key=value with a value quoted when it needs to be, unless LOG_JSON
// makes it one JSON object a line (bootstrap/observability_boostrap.go:97-106);
// both are read. The address is matched whole, so one admin's failure is never
// reported as another's.
func EmailFailure(logs, address string) (string, bool) {
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, emailFailureMessage) {
			continue
		}
		attrs := jsonAttrs(line)
		if attrs == nil {
			_, rest, _ := strings.Cut(line, emailFailureMessage)
			attrs = textAttrs(rest)
		}
		if attrs["address"] == address {
			return attrs["error"], true
		}
	}
	return "", false
}

// jsonAttrs is a LOG_JSON line's string attributes, or nil for a line that is
// not one.
func jsonAttrs(line string) map[string]string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") {
		return nil
	}
	var raw map[string]any
	if json.Unmarshal([]byte(line), &raw) != nil || raw["msg"] != emailFailureMessage {
		return nil
	}
	out := map[string]string{}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// textAttrs reads key=value pairs, where a value is either bare up to the
// next space or a Go quoted string, which is how the text format quotes one
// holding a space or a quote.
func textAttrs(s string) map[string]string {
	out := map[string]string{}
	for {
		s = strings.TrimLeft(s, " ")
		key, rest, ok := strings.Cut(s, "=")
		if !ok || key == "" || strings.Contains(key, " ") {
			return out
		}
		var value string
		if strings.HasPrefix(rest, `"`) {
			quoted, err := strconv.QuotedPrefix(rest)
			if err != nil {
				return out
			}
			value, _ = strconv.Unquote(quoted)
			rest = rest[len(quoted):]
		} else {
			value, rest, _ = strings.Cut(rest, " ")
		}
		out[key] = value
		s = rest
	}
}
