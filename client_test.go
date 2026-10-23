package pocketid_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paisans-software/pocketid-go"
)

// Every request is the same command line, and the key, the URL and the body
// travel on stdin. The command line is what `ps` shows.
func TestEveryRequestIsTheSameCommandLine(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		return 201, `{"token":"tok-not-real-0001"}`
	}}
	if _, err := newClient(f).LoginToken(context.Background(), "u-1", 15*time.Minute); err != nil {
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
	if _, err := newClient(f).CreateGroup(context.Background(), hostile); err != nil {
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
	u, err := newClient(f).FindUser(context.Background(), "founder")
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
	err := newClient(f).AddClientSecret(context.Background(), "c-1", secret)
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
	_, err := c.FindUser(context.Background(), "founder")
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
	if _, err := c.FindGroup(context.Background(), "admins"); err == nil {
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
	if _, err := c.FindUser(context.Background(), "founder"); !errors.Is(err, pocketid.ErrNoAPIKey) {
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
	if err := newClient(f).SetLaunchURL(context.Background(), "c-1", "https://talk.example.org"); err != nil {
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

// A client is read and deleted by ID, and an ID Pocket ID does not hold is
// nil on a read and success on a delete, so a repeated removal ends the same.
func TestClientByIDAndDelete(t *testing.T) {
	held := true
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.URL.Path != "/api/oidc/clients/c-1" {
			t.Errorf("sent %s %s", r.Method, r.URL)
		}
		switch {
		case !held:
			return 404, `{"error":"OIDC client not found"}`
		case r.Method == "DELETE":
			held = false
			return 204, ""
		default:
			return 200, `{"id":"c-1","name":"docs"}`
		}
	}}
	c := newClient(f)
	got, err := c.OIDCClientByID(context.Background(), "c-1")
	if err != nil || got == nil || got.Name != "docs" {
		t.Fatalf("OIDCClientByID = %+v, %v", got, err)
	}
	if err := c.DeleteOIDCClient(context.Background(), "c-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteOIDCClient(context.Background(), "c-1"); err != nil {
		t.Errorf("a second delete: %v", err)
	}
	if got, err := c.OIDCClientByID(context.Background(), "c-1"); err != nil || got != nil {
		t.Errorf("after the delete: %+v, %v", got, err)
	}
}

// HasAdmin reads users page by page, unfiltered, and stops at the first that
// is an admin.
func TestHasAdminStopsAtTheFirstAdmin(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.Method != "GET" || r.URL.Path != "/api/users" || r.URL.Query().Get("search") != "" {
			t.Errorf("sent %s %s", r.Method, r.URL)
		}
		switch r.URL.Query().Get("pagination[page]") {
		case "1":
			return 200, `{"data":[{"id":"u-0","username":"member"}],"pagination":{"totalPages":3}}`
		case "2":
			return 200, `{"data":[{"id":"u-1","username":"founder","isAdmin":true}],"pagination":{"totalPages":3}}`
		}
		return 200, `{"data":[{"id":"u-2","username":"later"}],"pagination":{"totalPages":3}}`
	}}
	has, err := newClient(f).HasAdmin(context.Background())
	if err != nil || !has {
		t.Fatalf("has %t, err %v", has, err)
	}
	if len(f.requests) != 2 {
		t.Errorf("read %d pages, want 2", len(f.requests))
	}
}

// With no admin on any page, every page is read and the answer is no.
func TestHasAdminReadsEveryPageWhenThereIsNone(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.URL.Query().Get("pagination[page]") == "1" {
			return 200, `{"data":[{"id":"u-0","username":"member"}],"pagination":{"totalPages":2}}`
		}
		return 200, `{"data":[{"id":"u-1","username":"other"}],"pagination":{"totalPages":2}}`
	}}
	has, err := newClient(f).HasAdmin(context.Background())
	if err != nil || has {
		t.Fatalf("has %t, err %v", has, err)
	}
	if len(f.requests) != 2 {
		t.Errorf("read %d pages, want 2", len(f.requests))
	}
}

// An error is returned as an error, never as no admin, and never carries the
// key.
func TestHasAdminFailsWithoutTheKey(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(request) (int, string) {
		return 401, `{"error":"bad key ` + apiKey + `"}`
	}}
	has, err := newClient(f).HasAdmin(context.Background())
	if err == nil || has || strings.Contains(err.Error(), apiKey) {
		t.Fatalf("has %t, err %v", has, err)
	}
}

// HasPasskey asks the audit log for the user's PASSKEY_ADDED events, filtered
// by Pocket ID, and still checks the user on each row it returns.
func TestHasPasskeyReadsTheUsersPasskeyEvents(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		return 200, `{"data":[{"event":"PASSKEY_ADDED","userID":"u-1"}],"pagination":{"totalPages":1}}`
	}}
	has, err := newClient(f).HasPasskey(context.Background(), "u-1")
	if err != nil || !has {
		t.Fatalf("HasPasskey = %v, %v", has, err)
	}
	r := f.requests[0]
	q := r.URL.Query()
	if r.Method != "GET" || r.URL.Path != "/api/audit-logs/all" ||
		q.Get("filters[userID]") != "u-1" || q.Get("filters[event]") != "PASSKEY_ADDED" {
		t.Errorf("sent %s %s", r.Method, r.URL)
	}
}

// A row for another user, as an unapplied filter would return, is not this
// user's passkey.
func TestHasPasskeyIgnoresAnotherUsersEvent(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		return 200, `{"data":[{"event":"PASSKEY_ADDED","userID":"u-2"},{"event":"SIGN_IN","userID":"u-1"}],"pagination":{"totalPages":1}}`
	}}
	has, err := newClient(f).HasPasskey(context.Background(), "u-1")
	if err != nil || has {
		t.Fatalf("HasPasskey = %v, %v", has, err)
	}
}

// EmailLoginLink asks Pocket ID to email the user a link of its own, with
// the ttl, and expects 204.
func TestEmailLoginLinkSendsTheTTL(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 204, `` }}
	if err := newClient(f).EmailLoginLink(context.Background(), "u-1", 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	r := f.requests[0]
	if r.Method != "POST" || r.URL.Path != "/api/users/u-1/one-time-access-email" {
		t.Errorf("sent %s %s", r.Method, r.URL)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil || body["ttl"] != "24h0m0s" {
		t.Errorf("body %q, want a 24h ttl", r.Body)
	}
}

// Pocket ID refuses the email when its admin email setting is off; the
// refusal comes back as Pocket ID's own message.
func TestEmailLoginLinkRefused(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		return 403, `{"error":"Email one-time access is disabled"}`
	}}
	err := newClient(f).EmailLoginLink(context.Background(), "u-1", 24*time.Hour)
	var apiErr *pocketid.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("err = %v", err)
	}
}

// A client secret is deleted by its ID under its client, and an ID Pocket ID
// no longer holds is success, so a retirement interrupted after the delete
// ends the same on the next run.
func TestDeleteClientSecret(t *testing.T) {
	held := true
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.Method != "DELETE" || r.URL.Path != "/api/oidc/clients/c-1/secrets/s-1" {
			t.Errorf("sent %s %s", r.Method, r.URL)
		}
		if !held {
			return 404, `{"error":"Client secret not found"}`
		}
		held = false
		return 204, ""
	}}
	c := newClient(f)
	if err := c.DeleteClientSecret(context.Background(), "c-1", "s-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteClientSecret(context.Background(), "c-1", "s-1"); err != nil {
		t.Errorf("a second delete: %v", err)
	}
	if len(f.requests) != 2 {
		t.Errorf("made %d requests", len(f.requests))
	}
}

// Any other failure is one.
func TestDeleteClientSecretFails(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 500, `{"error":"boom"}` }}
	if err := newClient(f).DeleteClientSecret(context.Background(), "c-1", "s-1"); err == nil {
		t.Fatal("a 500 was not an error")
	}
}

// SetClientName sends the client back as read with only the name changed,
// the launch URL included, since the update would otherwise clear it.
func TestSetClientNameKeepsTheLaunchURL(t *testing.T) {
	current := `{"id":"c-1","name":"gate","callbackURLs":["https://gate.example.org/oauth2/callback"],
		"launchURL":"https://gate.example.org","isPublic":false,"pkceEnabled":true,"isGroupRestricted":true,
		"credentials":{"secrets":[{"id":"s-1","prefix":"abcd","isActive":true}]}}`
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.Method == "GET" {
			return 200, current
		}
		return 200, `{}`
	}}
	if err := newClient(f).SetClientName(context.Background(), "c-1", "Example Community"); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 2 || f.requests[1].Method != "PUT" || f.requests[1].URL.Path != "/api/oidc/clients/c-1" {
		t.Fatalf("requests %+v", f.requests)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(f.requests[1].Body), &sent); err != nil {
		t.Fatal(err)
	}
	if sent["name"] != "Example Community" || sent["launchURL"] != "https://gate.example.org" || sent["isGroupRestricted"] != true || sent["pkceEnabled"] != true {
		t.Errorf("sent %v", sent)
	}
	if strings.Contains(f.requests[1].Body, "abcd") {
		t.Errorf("the update carries secrets: %s", f.requests[1].Body)
	}
}

// Every client is read, across pages, with whether it has a logo and where it
// launches. Nothing but GET is sent.
func TestOIDCClientsReadsEveryPage(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.Method != "GET" {
			t.Errorf("method %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/oidc/clients" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.URL.Query().Get("pagination[page]") == "1" {
			return 200, `{"data":[{"id":"c-0","name":"Forum","hasLogo":true,"launchURL":"https://forum.example.org"}],"pagination":{"totalPages":2}}`
		}
		return 200, `{"data":[{"id":"c-1","name":"Wiki","hasLogo":false,"launchURL":null,"isGroupRestricted":true}],"pagination":{"totalPages":2}}`
	}}
	got, err := newClient(f).OIDCClients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "c-0" || got[1].ID != "c-1" {
		t.Fatalf("read %+v", got)
	}
	if !got[0].HasLogo || got[0].LaunchURL == nil || *got[0].LaunchURL != "https://forum.example.org" {
		t.Errorf("first client %+v", got[0])
	}
	if got[1].HasLogo || got[1].LaunchURL != nil || !got[1].IsGroupRestricted {
		t.Errorf("second client %+v", got[1])
	}
	if len(f.requests) != 2 {
		t.Errorf("read %d pages, want 2", len(f.requests))
	}
}
