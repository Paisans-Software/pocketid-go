package pocketid_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

// Every request is the same command line, and the key, the URL and the body
// travel on stdin. The command line is what `ps` shows.
func TestEveryRequestIsTheSameCommandLine(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		return 201, `{"token":"tok-not-real-0001"}`
	}}
	if _, err := newClient(f).LoginToken("u-1", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.commands {
		if c != pocketid.CurlCommand {
			t.Errorf("ran %q, not the constant curl command", c)
		}
		if strings.Contains(c, apiKey) {
			t.Error("the command line carries the API key")
		}
	}
	r := f.requests[0]
	if r.header("X-API-Key") != apiKey {
		t.Errorf("the key was not sent as X-API-Key: %v", r.Headers)
	}
	if r.Method != "POST" || r.URL.String() != "http://10.44.0.1:1411/api/users/u-1/one-time-access-token" {
		t.Errorf("sent %s %s", r.Method, r.URL)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil || body["ttl"] != "15m0s" {
		t.Errorf("body %q, want a 15m ttl", r.Body)
	}
}

// A value that contains a quote, a backslash or a newline cannot escape its
// line in the config and become an option of its own.
func TestConfigQuotingSurvivesHostileValues(t *testing.T) {
	hostile := "x\"\nurl = \"http://elsewhere\\"
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 201, `{}` }}
	if _, err := newClient(f).CreateGroup(hostile); err != nil {
		t.Fatal(err)
	}
	r := f.requests[0]
	if r.URL.Host != "10.44.0.1:1411" {
		t.Fatalf("the request went to %s", r.URL.Host)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	if body["name"] != hostile {
		t.Errorf("name arrived as %q", body["name"])
	}
}

// Search is a substring match, so only an exact username is a match, and a
// second page is read when the first does not hold it.
func TestFindUserMatchesExactlyAcrossPages(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.URL.Query().Get("search") != "founder" {
			t.Errorf("searched for %q", r.URL.Query().Get("search"))
		}
		if r.URL.Query().Get("pagination[page]") == "1" {
			return 200, `{"data":[{"id":"u-0","username":"founders"}],"pagination":{"totalPages":2}}`
		}
		return 200, `{"data":[{"id":"u-1","username":"founder","isAdmin":true}],"pagination":{"totalPages":2}}`
	}}
	u, err := newClient(f).FindUser("founder")
	if err != nil {
		t.Fatal(err)
	}
	if u == nil || u.ID != "u-1" || !u.IsAdmin {
		t.Fatalf("found %+v", u)
	}
	if len(f.requests) != 2 {
		t.Errorf("made %d requests, want 2", len(f.requests))
	}
}

// An error carries Pocket ID's message and never the key or a secret that was
// in the body, even when the far end echoes them.
func TestErrorsNeverCarryTheKeyOrASecret(t *testing.T) {
	secret := "not-a-real-client-secret-0001"
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		return 400, `{"error":"bad secret ` + secret + ` for key ` + apiKey + `"}`
	}}
	err := newClient(f).AddClientSecret("c-1", secret)
	var apiErr *pocketid.APIError
	if err == nil {
		t.Fatal("a 400 was not an error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), apiKey) {
		t.Fatalf("the error carries a credential: %v", err)
	}
	if errors.As(err, &apiErr) {
		t.Fatal("the redacted error should be a plain error, so the raw APIError cannot be unwrapped")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("the error lacks the status: %v", err)
	}
}

// A transport error that echoes its input cannot carry the key out either.
func TestTransportErrorsAreRedacted(t *testing.T) {
	c := &pocketid.Client{Transport: echoFailure{}, BaseURL: "http://10.44.0.1:1411", APIKey: apiKey}
	_, err := c.FindUser("founder")
	if err == nil || strings.Contains(err.Error(), apiKey) {
		t.Fatalf("got %v", err)
	}
}

type echoFailure struct{}

func (echoFailure) Describe() string { return "home-a.local" }
func (echoFailure) RunInput(_, stdin string) (string, error) {
	return "", errors.New("ssh failed: " + stdin)
}

// No status line means curl never got an answer, which is not a 200.
func TestNoStatusIsAnError(t *testing.T) {
	c := &pocketid.Client{Transport: silent{}, BaseURL: "http://10.44.0.1:1411", APIKey: apiKey}
	if _, err := c.FindGroup("admins"); err == nil {
		t.Fatal("no answer was read as success")
	}
}

type silent struct{}

func (silent) Describe() string                     { return "home-a.local" }
func (silent) RunInput(_, _ string) (string, error) { return "", nil }

func TestHasActiveSecretComparesPrefixesOfActiveSecretsOnly(t *testing.T) {
	secrets := []pocketid.ClientSecret{{Prefix: "abcd", IsActive: false}, {Prefix: "wxyz", IsActive: true}, {Prefix: "", IsActive: true}}
	if pocketid.HasActiveSecret(secrets, "abcd-rest-of-it") {
		t.Error("an inactive secret matched")
	}
	if !pocketid.HasActiveSecret(secrets, "wxyz-rest-of-it") {
		t.Error("an active secret did not match")
	}
	if pocketid.HasActiveSecret(secrets, "") {
		t.Error("an empty value matched the prefixless secret")
	}
}

func TestLoginLink(t *testing.T) {
	if got := pocketid.LoginLink("https://id.example.org/", "abc"); got != "https://id.example.org/lc/abc" {
		t.Errorf("got %s", got)
	}
}

func TestNoKeyIsRefusedBeforeAnyRequest(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 200, `{}` }}
	c := newClient(f)
	c.APIKey = ""
	if _, err := c.FindUser("founder"); err == nil || !strings.Contains(err.Error(), "static_api_key") {
		t.Fatalf("got %v", err)
	}
	if len(f.requests) != 0 {
		t.Error("a request was made without a key")
	}
}

// SetLaunchURL reads the client and sends every field the update writes back
// as read, with only launchURL changed: federated credentials kept, secrets
// and logo URLs not sent, and the group restriction unchanged.
func TestSetLaunchURLSendsTheClientBackUnchanged(t *testing.T) {
	current := `{"id":"c-1","name":"talk","description":"","hasLogo":true,"hasDarkLogo":false,"launchURL":null,
		"requiresReauthentication":false,"clientType":"","callbackURLs":["https://talk.example.org/oauth/oidc/verify"],
		"logoutCallbackURLs":[],"isPublic":false,"pkceEnabled":true,"requiresPushedAuthorizationRequests":false,
		"skipConsent":true,"credentials":{"federatedIdentities":[{"issuer":"https://ci.example.org","replayProtection":false}],
		"secrets":[{"id":"s-1","prefix":"abcd","isActive":true}]},"isGroupRestricted":true,
		"accessTokenDurationMinutes":60,"refreshTokenDurationMinutes":43200,"allowedUserGroups":[{"id":"g-1","name":"members"}]}`
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.Method == "GET" {
			return 200, current
		}
		return 200, `{}`
	}}
	if err := newClient(f).SetLaunchURL("c-1", "https://talk.example.org"); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 2 || f.requests[1].Method != "PUT" || f.requests[1].URL.Path != "/api/oidc/clients/c-1" {
		t.Fatalf("requests %+v", f.requests)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(f.requests[1].Body), &sent); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"name": "talk", "description": "", "callbackURLs": []any{"https://talk.example.org/oauth/oidc/verify"},
		"logoutCallbackURLs": []any{}, "isPublic": false, "pkceEnabled": true, "requiresReauthentication": false,
		"requiresPushedAuthorizationRequests": false, "skipConsent": true, "isGroupRestricted": true,
		"accessTokenDurationMinutes": float64(60), "refreshTokenDurationMinutes": float64(43200),
		"credentials": map[string]any{"federatedIdentities": []any{map[string]any{"issuer": "https://ci.example.org", "replayProtection": false}}},
		"launchURL":   "https://talk.example.org",
	}
	got, _ := json.Marshal(sent)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Errorf("sent %s\nwant %s", got, exp)
	}
	for _, c := range f.commands {
		if c != pocketid.CurlCommand || strings.Contains(c, apiKey) {
			t.Errorf("ran %q", c)
		}
	}
}
