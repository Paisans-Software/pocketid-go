package pocketid_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/paisans-software/pocketid-go"
)

func TestPrivate(t *testing.T) {
	mesh := netip.MustParsePrefix("203.0.113.0/24")
	for _, c := range []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"[::1]", true},
		{"10.44.0.1", true},
		{"172.16.5.4", true},
		{"192.168.1.10", true},
		{"100.64.0.1", true},
		{"100.127.255.254", true},
		{"fd00::1", true},
		{"::ffff:10.0.0.1", true},
		{"app", true},
		{"localhost", true},
		{"203.0.113.7", true}, // in the caller's network
		{"8.8.8.8", false},
		{"100.128.0.1", false},
		{"2001:db8::1", false},
		{"fe80::1", false},
		{"id.example.org", false},
		{"10.0.0.1.nip.io", false},
		{"", false},
	} {
		if got := pocketid.Private(c.host, mesh); got != c.want {
			t.Errorf("Private(%q) = %v, want %v", c.host, got, c.want)
		}
	}
	if pocketid.Private("203.0.113.7") {
		t.Error("an address outside the private ranges passed without the caller naming its network")
	}
}

// A public BaseURL is refused before anything is sent, on either path, and
// the error names the host and not the key.
func TestThePublicInternetGetsNoKey(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 200, `{}` }}
	c := newClient(f)
	c.BaseURL = "https://id.example.org"
	_, err := c.Users(context.Background())
	if err == nil || !strings.Contains(err.Error(), "id.example.org") || strings.Contains(err.Error(), apiKey) {
		t.Fatalf("got %v", err)
	}
	if len(f.requests) != 0 {
		t.Error("a request was sent to a public address")
	}

	sent := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sent = true }))
	defer srv.Close()
	h := &pocketid.Client{HTTP: srv.Client(), BaseURL: "http://8.8.8.8:1411", APIKey: apiKey}
	if _, err := h.Users(context.Background()); err == nil {
		t.Fatal("a public address was accepted on the HTTP path")
	}
	if sent {
		t.Error("a request was sent")
	}
}

func TestTheCallersNetworkIsPrivate(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 200, `{"data":[],"pagination":{"totalPages":1}}` }}
	c := newClient(f)
	c.BaseURL = "http://203.0.113.7:1411"
	if _, err := c.Users(context.Background()); err == nil {
		t.Fatal("an address outside the private ranges was accepted")
	}
	c.Networks = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if _, err := c.Users(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A context that is already done sends nothing on the Transport path, and
// cancels the request on the HTTP path.
func TestContextCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 200, `{}` }}
	if _, err := newClient(f).Users(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if len(f.requests) != 0 {
		t.Error("a request was sent with a cancelled context")
	}

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel = context.WithCancel(context.Background())
	h := &pocketid.Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: apiKey}
	done := make(chan error, 1)
	go func() { _, err := h.Users(ctx); done <- err }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
