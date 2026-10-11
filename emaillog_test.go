package pocketid_test

import (
	"testing"
	"time"

	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

const textFailure = `Oct 11 18:53:41 INF HTTP request completed method=POST path=/api/users/u-1/one-time-access-email status=204
Oct 11 18:53:41 ERR Failed to send one-time access token email error="failed to send email: dial tcp 10.0.0.9:587: i/o timeout" address=fern@example.org
`

const jsonFailure = `{"time":"2026-10-11T18:53:41Z","level":"ERROR","msg":"Failed to send one-time access token email","error":"failed to send email: 535 auth failed","address":"fern@example.org"}
`

// A failure logged for the admin's address is found, with Pocket ID's own
// error, in the default text format and in LOG_JSON's.
func TestEmailFailureFindsTheAddress(t *testing.T) {
	for name, tc := range map[string]struct{ logs, want string }{
		"text": {textFailure, "failed to send email: dial tcp 10.0.0.9:587: i/o timeout"},
		"json": {jsonFailure, "failed to send email: 535 auth failed"},
	} {
		got, ok := pocketid.EmailFailure(tc.logs, "fern@example.org")
		if !ok || got != tc.want {
			t.Errorf("%s: EmailFailure = %q, %v; want %q", name, got, ok, tc.want)
		}
	}
}

// Another admin's failure, or no failure, is not this admin's.
func TestEmailFailureIgnoresOtherAddresses(t *testing.T) {
	for _, logs := range []string{textFailure, jsonFailure, "", "Oct 11 18:53:41 INF started\n"} {
		if got, ok := pocketid.EmailFailure(logs, "sam@example.org"); ok {
			t.Errorf("EmailFailure(%q) = %q, want none", logs, got)
		}
	}
}

// An address is matched whole: one that only ends with it is someone else.
func TestEmailFailureMatchesTheWholeAddress(t *testing.T) {
	if _, ok := pocketid.EmailFailure(textFailure, "ern@example.org"); ok {
		t.Error("matched a suffix of the address")
	}
}

// The log command reads one compose service's log for a window, and nothing
// in it varies but the project and the window.
func TestLogCommand(t *testing.T) {
	got := pocketid.LogCommand("paisans-f2a9-auth", 45*time.Second)
	want := "docker compose -p 'paisans-f2a9-auth' logs --no-color --no-log-prefix --since 45s app 2>&1"
	if got != want {
		t.Errorf("LogCommand = %q\nwant %q", got, want)
	}
}
