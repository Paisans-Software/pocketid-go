//go:build pocketid_integration

// This file runs the client against a real ghcr.io/pocket-id/pocket-id
// container, so what it assumes about Pocket ID's routes, payloads and status
// codes is checked against Pocket ID rather than against the fake. Every
// call is made on both paths: HTTP, and curl through a Transport that runs it
// on this machine.
//
//	go test -tags pocketid_integration ./...
//
// POCKETID_IMAGE names the image; it defaults to the release this module was
// last checked against.
package pocketid_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/paisans-software/pocketid-go"
)

const defaultImage = "ghcr.io/pocket-id/pocket-id:v2.18.0"

const realKey = "integration-static-api-key-0123456789"

// staticUserID is the user Pocket ID makes for its static API key, an
// administrator with a fixed ID (apikey/service.go at v2.18.0).
const staticUserID = "00000000-0000-0000-0000-000000000000"

func startPocketID(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH; skipping the Pocket ID integration test")
	}
	image := os.Getenv("POCKETID_IMAGE")
	if image == "" {
		image = defaultImage
	}
	name := fmt.Sprintf("pocketid-go-it-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", "127.0.0.1::1411",
		"-e", "APP_URL=http://localhost:1411",
		"-e", "ENCRYPTION_KEY=0123456789abcdef0123456789abcdef",
		"-e", "STATIC_API_KEY="+realKey,
		"-e", "ANALYTICS_DISABLED=true",
		image).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	out, err = exec.Command("docker", "port", name, "1411").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v\n%s", err, out)
	}
	base := "http://" + strings.TrimSpace(strings.Split(string(out), "\n")[0])
	for deadline := time.Now().Add(90 * time.Second); ; {
		if resp, err := http.Get(base + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				return base
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Fatalf("Pocket ID did not become healthy:\n%s", logs)
		}
		time.Sleep(time.Second)
	}
}

// localCurl is a Transport that runs the command on this machine, as an ssh
// connection would on a host.
type localCurl struct{}

func (localCurl) Describe() string { return "this machine" }

func (localCurl) RunInput(command, stdin string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	return string(out), err
}

func TestRealPocketID(t *testing.T) {
	base := startPocketID(t)
	for _, path := range []struct {
		name   string
		client *pocketid.Client
	}{
		{"http", &pocketid.Client{HTTP: &http.Client{}, BaseURL: base, APIKey: realKey}},
		{"transport", &pocketid.Client{Transport: localCurl{}, BaseURL: base, APIKey: realKey}},
	} {
		t.Run(path.name, func(t *testing.T) { exercise(t, path.client, path.name) })
	}
}

func exercise(t *testing.T, c *pocketid.Client, suffix string) {
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	users, err := c.Users(ctx)
	must(err)
	static := false
	for _, u := range users {
		if u.ID == staticUserID && u.IsAdmin {
			static = true
		}
	}
	if !static {
		t.Errorf("the static API key's user is not listed as an administrator: %+v", users)
	}
	admin, err := c.HasAdmin(ctx)
	must(err)
	if !admin {
		t.Error("HasAdmin is false with the static key's user present")
	}

	group, err := c.CreateGroup(ctx, "members-"+suffix)
	must(err)
	found, err := c.FindGroup(ctx, "members-"+suffix)
	must(err)
	if found == nil || found.ID != group.ID {
		t.Fatalf("FindGroup: %+v", found)
	}

	email := "fern-" + suffix + "@example.org"
	fern, err := c.CreateUser(ctx, pocketid.NewUser{Username: "fern-" + suffix, Email: &email, FirstName: "Fern", LastName: "Gully", DisplayName: "Fern Gully"})
	must(err)
	if fern.EmailVerified {
		t.Error("a user created without emailVerified is verified")
	}
	byName, err := c.FindUser(ctx, "fern-"+suffix)
	must(err)
	if byName == nil || byName.ID != fern.ID {
		t.Fatalf("FindUser: %+v", byName)
	}
	must(c.SetUserGroups(ctx, fern.ID, []string{group.ID}))
	must(c.VerifyEmail(ctx, fern))
	read, err := c.User(ctx, fern.ID)
	must(err)
	if !read.InGroup(group.ID) || !read.EmailVerified || read.LastName == nil || *read.LastName != "Gully" {
		t.Fatalf("after groups and verification: %+v", read)
	}
	must(c.SetAdmin(ctx, read))
	read, err = c.User(ctx, fern.ID)
	must(err)
	if !read.IsAdmin || !read.InGroup(group.ID) {
		t.Fatalf("SetAdmin: %+v", read)
	}
	must(c.Demote(ctx, read))
	read, err = c.User(ctx, fern.ID)
	must(err)
	if read.IsAdmin || !read.EmailVerified {
		t.Fatalf("Demote: %+v", read)
	}

	token, err := c.LoginToken(ctx, fern.ID, time.Hour)
	must(err)
	if token == "" {
		t.Error("LoginToken returned no token")
	}
	passkey, err := c.HasPasskey(ctx, fern.ID)
	must(err)
	if passkey {
		t.Error("a new user has a passkey")
	}

	created, err := c.CreateOIDCClient(ctx, pocketid.NewOIDCClient{
		Name: "wiki-" + suffix, CallbackURLs: []string{"https://wiki.example.org/callback"},
		IsGroupRestricted: true, LaunchURL: "https://wiki.example.org",
	})
	must(err)
	must(c.SetAllowedGroups(ctx, created.ID, []string{group.ID}))
	must(c.SetSkipConsent(ctx, created.ID, true))
	must(c.SetLaunchURL(ctx, created.ID, "https://wiki.example.org/home"))
	must(c.SetClientName(ctx, created.ID, "Wiki "+suffix))
	client, err := c.FindOIDCClient(ctx, "Wiki "+suffix)
	must(err)
	if client == nil || !client.SkipConsent || !client.IsGroupRestricted || client.LaunchURL == nil ||
		*client.LaunchURL != "https://wiki.example.org/home" || len(client.AllowedUserGroups) != 1 ||
		len(client.CallbackURLs) != 1 {
		t.Fatalf("after the updates: %+v", client)
	}

	secret := "integration-secret-0123456789-" + suffix
	must(c.AddClientSecret(ctx, created.ID, secret))
	secrets, err := c.ClientSecrets(ctx, created.ID)
	must(err)
	if !pocketid.HasActiveSecret(secrets, secret) {
		t.Fatalf("the added secret is not active: %+v", secrets)
	}
	must(c.DeleteClientSecret(ctx, created.ID, secrets[0].ID))
	must(c.DeleteClientSecret(ctx, created.ID, secrets[0].ID))

	must(c.DeleteOIDCClient(ctx, created.ID))
	must(c.DeleteOIDCClient(ctx, created.ID))

	empty, err := c.CreateGroup(ctx, "empty-"+suffix)
	must(err)
	all, err := c.Groups(ctx)
	must(err)
	seen := map[string]bool{}
	for _, g := range all {
		seen[g.ID] = true
	}
	if !seen[group.ID] || !seen[empty.ID] {
		t.Errorf("Groups missed one: %+v", all)
	}

	// UpdateUser on an administrator: the fields asked for change, and the
	// username, the admin flag and the groups stay as they were.
	must(c.SetAdmin(ctx, read))
	newEmail := "fern.g-" + suffix + "@example.org"
	verified, disabled := true, true
	display := "Fern G."
	updated, err := c.UpdateUser(ctx, fern.ID, pocketid.UserChange{
		Email: &newEmail, EmailVerified: &verified, DisplayName: &display, Disabled: &disabled,
	})
	must(err)
	again, err := c.User(ctx, fern.ID)
	must(err)
	for _, u := range []pocketid.User{updated, again} {
		if u.Email == nil || *u.Email != newEmail || !u.EmailVerified || u.DisplayName != display || !u.Disabled ||
			u.Username != "fern-"+suffix || !u.IsAdmin || u.FirstName != "Fern" || !u.InGroup(group.ID) {
			t.Errorf("after UpdateUser: %+v", u)
		}
	}
	gone, err := c.OIDCClientByID(ctx, created.ID)
	must(err)
	if gone != nil {
		t.Errorf("a deleted client is still read: %+v", gone)
	}
}
