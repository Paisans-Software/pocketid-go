package pocketid_test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

// request is one curl config, parsed back the way curl reads it.
type request struct {
	Method  string
	URL     *url.URL
	Headers []string
	Body    string
}

// fakeAPI answers curl configs with a handler and records what was sent.
type fakeAPI struct {
	t        *testing.T
	commands []string
	requests []request
	handle   func(r request) (int, string)
}

func (f *fakeAPI) Describe() string { return "home-a.local" }

func (f *fakeAPI) RunInput(command, stdin string) (string, error) {
	f.commands = append(f.commands, command)
	r := parseConfig(f.t, stdin)
	f.requests = append(f.requests, r)
	status, body := f.handle(r)
	return fmt.Sprintf("%s\npaisans-http-status:%d", body, status), nil
}

func parseConfig(t *testing.T, cfg string) request {
	t.Helper()
	var r request
	for _, line := range strings.Split(strings.TrimSpace(cfg), "\n") {
		option, quoted, ok := strings.Cut(line, " = ")
		if !ok || len(quoted) < 2 || quoted[0] != '"' || quoted[len(quoted)-1] != '"' {
			t.Fatalf("not a quoted curl config line: %q", line)
		}
		value := unquote(quoted[1 : len(quoted)-1])
		switch option {
		case "url":
			u, err := url.Parse(value)
			if err != nil {
				t.Fatal(err)
			}
			r.URL = u
		case "request":
			r.Method = value
		case "header":
			r.Headers = append(r.Headers, value)
		case "data-raw":
			r.Body = value
		case "max-time", "write-out":
		default:
			t.Fatalf("unexpected curl option %q", option)
		}
	}
	return r
}

func unquote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (r request) header(name string) string {
	for _, h := range r.Headers {
		if k, v, ok := strings.Cut(h, ": "); ok && strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

const apiKey = "not-a-real-api-key-0001"

func newClient(f *fakeAPI) *pocketid.Client {
	return &pocketid.Client{Transport: f, BaseURL: "http://10.44.0.1:1411", APIKey: apiKey}
}
