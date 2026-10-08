package pocketid_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

// With HTTP set, a request goes straight to BaseURL with the same method,
// path, query, headers and body it would have had through curl, and no
// Transport is needed.
func TestHTTPModeSendsTheRequestDirectly(t *testing.T) {
	var got struct {
		method, path, query, key, accept, contentType, body string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method, got.path, got.query = r.Method, r.URL.Path, r.URL.RawQuery
		got.key, got.accept, got.contentType = r.Header.Get("X-API-Key"), r.Header.Get("Accept"), r.Header.Get("Content-Type")
		got.body = string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := &pocketid.Client{HTTP: srv.Client(), BaseURL: srv.URL + "/", APIKey: "key-0123456789abcdef"}
	if err := c.SetUserGroups("u 1", []string{"g1", "g2"}); err != nil {
		t.Fatal(err)
	}
	if got.method != "PUT" || got.path != "/api/users/u 1/user-groups" {
		t.Errorf("sent %s %s", got.method, got.path)
	}
	if got.key != "key-0123456789abcdef" || got.accept != "application/json" || got.contentType != "application/json" {
		t.Errorf("headers: key %q accept %q content-type %q", got.key, got.accept, got.contentType)
	}
	if got.body != `{"userGroupIds":["g1","g2"]}` {
		t.Errorf("body %q", got.body)
	}
}

// Users walks every page, and User reads one user with its groups and LDAP ID.
func TestHTTPModeListsUsersAndReadsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users" && r.URL.Query().Get("pagination[page]") == "1":
			io.WriteString(w, `{"data":[{"id":"a","username":"alice","isAdmin":true}],"pagination":{"totalPages":2}}`)
		case r.URL.Path == "/api/users" && r.URL.Query().Get("pagination[page]") == "2":
			io.WriteString(w, `{"data":[{"id":"b","username":"bob"}],"pagination":{"totalPages":2}}`)
		case r.URL.Path == "/api/users/a":
			io.WriteString(w, `{"id":"a","username":"alice","isAdmin":true,"ldapId":"cn=alice","userGroups":[{"id":"g1","name":"members"}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := &pocketid.Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "key-0123456789abcdef"}
	users, err := c.Users()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].Username != "alice" || users[1].Username != "bob" {
		t.Fatalf("users %+v", users)
	}
	u, err := c.User("a")
	if err != nil {
		t.Fatal(err)
	}
	if u.LdapID == nil || *u.LdapID != "cn=alice" || !u.InGroup("g1") {
		t.Errorf("user %+v", u)
	}
}

// An error in HTTP mode carries Pocket ID's message and never the key.
func TestHTTPModeErrorsAreRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":"bad key key-0123456789abcdef"}`)
	}))
	defer srv.Close()
	c := &pocketid.Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "key-0123456789abcdef"}
	_, err := c.Users()
	if err == nil || strings.Contains(err.Error(), "key-0123456789abcdef") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want a redacted 403, got %v", err)
	}
}

// A Pocket ID that does not answer is an error naming the request, not a
// status of zero.
func TestHTTPModeNoAnswerIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	c := &pocketid.Client{HTTP: &http.Client{}, BaseURL: url, APIKey: "key-0123456789abcdef"}
	if _, err := c.Users(); err == nil || !strings.Contains(err.Error(), "GET /api/users") {
		t.Fatalf("want an error naming the request, got %v", err)
	}
}
