package pocketid_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/paisans-software/pocketid-go"
)

const fernAsRead = `{"id":"u-1","username":"fern","email":"fern@example.org","emailVerified":true,
	"firstName":"Fern","lastName":"Gully","displayName":"Fern Gully","isAdmin":true,"locale":"de",
	"disabled":false,"userGroups":[{"id":"g-1","name":"members"}],"ldapId":null}`

func ptr[T any](v T) *T { return &v }

// UpdateUser sends back every field it was not asked to change exactly as it
// read it, the username, the admin flag and the locale above all, which no
// UserChange can name.
func TestUpdateUserChangesOnlyWhatItIsAsked(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.Method == "GET" {
			return 200, fernAsRead
		}
		return 200, fernAsRead
	}}
	_, err := newClient(f).UpdateUser(context.Background(), "u-1", pocketid.UserChange{
		Email: ptr("fern@new.example.org"), EmailVerified: ptr(true),
		DisplayName: ptr("Fern G."), Disabled: ptr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 2 || f.requests[0].Method != "GET" || f.requests[1].Method != "PUT" || f.requests[1].URL.Path != "/api/users/u-1" {
		t.Fatalf("requests %+v", f.requests)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(f.requests[1].Body), &sent); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"username": "fern", "email": "fern@new.example.org", "emailVerified": true,
		"firstName": "Fern", "lastName": "Gully", "displayName": "Fern G.",
		"isAdmin": true, "locale": "de", "disabled": true,
	}
	if !reflect.DeepEqual(sent, want) {
		t.Errorf("sent %v\nwant %v", sent, want)
	}
}

func TestUpdateUserWithNothingToChangeSendsNothing(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 200, fernAsRead }}
	u, err := newClient(f).UpdateUser(context.Background(), "u-1", pocketid.UserChange{})
	if err != nil || u.Username != "fern" {
		t.Fatalf("got %+v, %v", u, err)
	}
	for _, r := range f.requests {
		if r.Method != "GET" {
			t.Errorf("sent %s %s", r.Method, r.URL.Path)
		}
	}
}

// Pocket ID takes only a locale for a user an LDAP sync manages, so the
// change would be reported and not made.
func TestUpdateUserRefusesAnLDAPUser(t *testing.T) {
	ldap := strings.Replace(fernAsRead, `"ldapId":null`, `"ldapId":"cn=fern"`, 1)
	f := &fakeAPI{t: t, handle: func(r request) (int, string) { return 200, ldap }}
	if _, err := newClient(f).UpdateUser(context.Background(), "u-1", pocketid.UserChange{Disabled: ptr(true)}); err == nil {
		t.Fatal("an LDAP user was updated")
	}
	if len(f.requests) != 1 {
		t.Errorf("requests %+v", f.requests)
	}
}

func TestGroupsReadsEveryPage(t *testing.T) {
	f := &fakeAPI{t: t, handle: func(r request) (int, string) {
		if r.URL.Query().Get("pagination[page]") == "1" {
			return 200, `{"data":[{"id":"g-1","name":"members"}],"pagination":{"totalPages":2}}`
		}
		return 200, `{"data":[{"id":"g-2","name":"empty"}],"pagination":{"totalPages":2}}`
	}}
	groups, err := newClient(f).Groups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[1].Name != "empty" {
		t.Fatalf("got %+v", groups)
	}
	for _, r := range f.requests {
		if r.URL.Path != "/api/user-groups" || r.URL.Query().Get("search") != "" {
			t.Errorf("requested %s", r.URL)
		}
	}
}

// A redirect is answered, not followed: net/http would carry X-API-Key to
// wherever it points, past the private address check.
func TestARedirectIsNotFollowed(t *testing.T) {
	followed := false
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := &pocketid.Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: apiKey}
	if _, err := c.Users(context.Background()); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("got %v", err)
	}
	if followed {
		t.Error("the redirect was followed")
	}
}
