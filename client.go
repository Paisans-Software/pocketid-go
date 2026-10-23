// Package pocketid calls a running Pocket ID's REST API with its static API
// key.
//
// The client supports Pocket ID v2.18.0 and newer. Every route, payload and
// status code here was read from Pocket ID's source at tag v2.18.0
// (github.com/pocket-id/pocket-id); each method's comment cites where. The
// integration test runs against v2.18.0 by default. A Pocket ID major release
// is a major release here.
//
// A Client reaches Pocket ID one of two ways. With HTTP set, it sends each
// request straight to BaseURL, for code running beside Pocket ID. Otherwise
// it runs curl on a host through a Transport, such as an ssh connection, and
// curl calls BaseURL from there. Everything that varies, the URL, the API key
// and the body, travels to curl in a config on stdin (`curl --config -`), so
// the command line is the same constant for every request and carries
// nothing: a command line is in the process table, readable by every user on
// the host, for as long as it runs.
//
// The key goes only to a private address (see Private): it is an
// administrator's credential, and Pocket ID's API answers wherever its port
// is reachable.
//
// Every method takes a context. The HTTP path cancels the request with it;
// the Transport path checks it before each request, since a Transport cannot
// stop a curl that has started.
package pocketid

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Transport runs a command on a host with stdin, the way an ssh connection
// does. It is declared here so this package depends on the shape and not on
// whatever provides it.
type Transport interface {
	RunInput(command, stdin string) (string, error)
	Describe() string
}

// CurlCommand is the only command line this package ever runs. It is exported
// so a test can assert that nothing else reaches a host.
//
// --globoff because query keys such as pagination[limit] are brackets, which
// curl would otherwise read as a URL glob. They are percent encoded as well;
// this is the second lock.
const CurlCommand = "curl --silent --show-error --globoff --config -"

// statusMarker precedes the HTTP status curl writes after the body, so a body
// that happens to end in three digits cannot be mistaken for it.
const statusMarker = "\npocketid-http-status:"

// Client is one Pocket ID, reached at BaseURL from the host the Transport
// reaches, as in http://10.44.0.1:1411.
//
// HTTP, when set, sends each request straight to BaseURL instead, and
// Transport is not used. That is for code running beside Pocket ID, which has
// no host to go through.
type Client struct {
	Transport Transport
	HTTP      *http.Client
	BaseURL   string
	APIKey    string
	// Networks are private networks besides the ones Private always accepts,
	// such as a mesh whose addresses are not in a private range.
	Networks []netip.Prefix
}

// ErrNoAPIKey is returned, before any request, by a client without a key.
var ErrNoAPIKey = errors.New("no API key for Pocket ID")

// APIError is a response outside the status a call expected. Message is
// Pocket ID's own `error` field (dto/error_dto.go:6-10) when it sent one.
type APIError struct {
	Method  string
	Path    string
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("Pocket ID answered %s %s with %d: %s", e.Method, e.Path, e.Status, e.Message)
	}
	return fmt.Sprintf("Pocket ID answered %s %s with %d", e.Method, e.Path, e.Status)
}

// do sends one request and decodes a response with the wanted status into
// out. secrets are any values in the body besides the API key; every one is
// scrubbed from an error before it is returned.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any, want int, secrets ...string) error {
	secrets = append(secrets, c.APIKey)
	if c.APIKey == "" {
		return ErrNoAPIKey
	}
	if err := c.private(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	var status int
	var payload string
	var err error
	if c.HTTP != nil {
		status, payload, err = c.send(ctx, method, path, query, body)
	} else {
		status, payload, err = c.curl(method, path, query, body)
	}
	if err != nil {
		return Redact(err, secrets...)
	}
	if status != want {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal([]byte(payload), &e)
		return Redact(&APIError{Method: method, Path: path, Status: status, Message: e.Error}, secrets...)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal([]byte(payload), out); err != nil {
		// The payload is not quoted into the error: a response this call
		// expected may carry a secret, and one it cannot parse is still that
		// response.
		return fmt.Errorf("%s %s: the %d response is not the JSON expected: %v", method, path, status, err)
	}
	return nil
}

// curl sends one request through curl on the Transport's host.
func (c *Client) curl(method, path string, query url.Values, body any) (int, string, error) {
	cfg, err := c.config(method, path, query, body)
	if err != nil {
		return 0, "", err
	}
	raw, err := c.Transport.RunInput(CurlCommand, cfg)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s through %s: %w", method, path, c.Transport.Describe(), err)
	}
	status, payload, err := splitStatus(raw)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s: %w", method, path, err)
	}
	return status, payload, nil
}

// send sends one request with HTTP, carrying what config gives curl: the key,
// JSON both ways, and a 30 second limit when the client sets none.
func (c *Client) send(ctx context.Context, method, path string, query url.Values, body any) (int, string, error) {
	target := strings.TrimRight(c.BaseURL, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s: %w", method, path, err)
	}
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := *c.HTTP
	if client.Timeout == 0 {
		client.Timeout = 30 * time.Second
	}
	// A redirect is answered, never followed. net/http would follow it with
	// X-API-Key still set, which would take the key to an address the private
	// check never saw; curl, on the Transport path, follows none either.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s: Pocket ID did not answer: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s: reading the response: %w", method, path, err)
	}
	return resp.StatusCode, string(raw), nil
}

// config is curl's configuration for one request. Every value is a quoted
// string, in which curl reads \\ and \" as escapes, so nothing a value holds
// can end its line and start another option.
func (c *Client) config(method, path string, query url.Values, body any) (string, error) {
	target := strings.TrimRight(c.BaseURL, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var b strings.Builder
	line := func(option, value string) {
		fmt.Fprintf(&b, "%s = \"%s\"\n", option, curlQuote(value))
	}
	line("url", target)
	line("request", method)
	line("header", "X-API-Key: "+c.APIKey)
	line("header", "Accept: application/json")
	line("max-time", "30")
	line("write-out", statusMarker+"%{http_code}")
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		line("header", "Content-Type: application/json")
		// data-raw, not data-binary: a body beginning with @ would be read
		// as a file name by the other two.
		line("data-raw", string(raw))
	}
	return b.String(), nil
}

func curlQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s)
}

// splitStatus separates the body from the status curl wrote after it.
func splitStatus(raw string) (int, string, error) {
	i := strings.LastIndex(raw, statusMarker)
	if i < 0 {
		return 0, "", errors.New("curl printed no status, so the request may not have been made")
	}
	status, err := strconv.Atoi(strings.TrimSpace(raw[i+len(statusMarker):]))
	if err != nil || status == 0 {
		return 0, "", errors.New("curl printed no HTTP status: Pocket ID did not answer")
	}
	return status, raw[:i], nil
}

// Redact removes every given secret, and its base64 form, from an error.
func Redact(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	changed := false
	for _, s := range secrets {
		if s == "" {
			continue
		}
		for _, form := range []string{s, base64.StdEncoding.EncodeToString([]byte(s))} {
			if strings.Contains(msg, form) {
				msg = strings.ReplaceAll(msg, form, "[redacted]")
				changed = true
			}
		}
	}
	if !changed {
		return err
	}
	return errors.New(msg)
}

// pageSize is Pocket ID's own ceiling: a larger limit is cut to 100
// (utils/list_request_util.go:61-65).
const pageSize = 100

// paginated is dto.Paginated (dto/pagination_dto.go:7-10).
type paginated[T any] struct {
	Data       []T `json:"data"`
	Pagination struct {
		TotalPages int `json:"totalPages"`
	} `json:"pagination"`
}

// list walks every page of a list route filtered by search. Pocket ID's search
// is a substring match (LIKE '%term%'), so callers compare exactly afterwards.
func list[T any](ctx context.Context, c *Client, path, search string) ([]T, error) {
	var out []T
	err := pages(ctx, c, path, search, func(data []T) bool {
		out = append(out, data...)
		return false
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// pages hands each page of a list route filtered by search to visit, in
// order, until visit returns true or the last page has been read.
func pages[T any](ctx context.Context, c *Client, path, search string, visit func([]T) bool) error {
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("search", search)
		q.Set("pagination[page]", strconv.Itoa(page))
		q.Set("pagination[limit]", strconv.Itoa(pageSize))
		var got paginated[T]
		if err := c.do(ctx, "GET", path, q, nil, &got, 200); err != nil {
			return err
		}
		if visit(got.Data) || page >= got.Pagination.TotalPages || len(got.Data) == 0 {
			return nil
		}
	}
}

// Group is dto.UserGroupMinimalDto (dto/user_group_dto.go:21-29), the parts
// read here. Name is what the `groups` claim carries
// (oidc/claims_service.go:157-162); FriendlyName is only shown in the UI.
type Group struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	FriendlyName string `json:"friendlyName"`
}

// User is dto.UserDto (dto/user_dto.go:9-23).
type User struct {
	ID            string  `json:"id"`
	Username      string  `json:"username"`
	Email         *string `json:"email"`
	EmailVerified bool    `json:"emailVerified"`
	FirstName     string  `json:"firstName"`
	LastName      *string `json:"lastName"`
	DisplayName   string  `json:"displayName"`
	IsAdmin       bool    `json:"isAdmin"`
	Locale        *string `json:"locale"`
	Disabled      bool    `json:"disabled"`
	UserGroups    []Group `json:"userGroups"`
	// LdapID is set on a user an LDAP sync manages, whose groups that sync
	// owns (dto/user_dto.go:21).
	LdapID *string `json:"ldapId"`
}

// InGroup reports whether the user belongs to a group, by ID.
func (u User) InGroup(id string) bool {
	for _, g := range u.UserGroups {
		if g.ID == id {
			return true
		}
	}
	return false
}

// NewUser is dto.UserCreateDto (dto/user_dto.go:25-38), the fields set here.
// EmailVerified is stored as sent (service/user_service.go:316); left out, it
// is false, and Pocket ID then sends email_verified false in every ID token.
type NewUser struct {
	Username      string  `json:"username"`
	Email         *string `json:"email,omitempty"`
	EmailVerified bool    `json:"emailVerified,omitempty"`
	FirstName     string  `json:"firstName"`
	LastName      string  `json:"lastName"`
	DisplayName   string  `json:"displayName"`
	IsAdmin       bool    `json:"isAdmin"`
}

// FindUser returns the user with exactly this username, or nil.
// GET /api/users (controller/user_controller.go:30, :123-142).
func (c *Client) FindUser(ctx context.Context, username string) (*User, error) {
	users, err := list[User](ctx, c, "/api/users", username)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Username == username {
			return &u, nil
		}
	}
	return nil, nil
}

// SearchUsers returns every user Pocket ID's search matches, a substring of
// the username, the email or the names (service/user_service.go:64-65), so
// callers compare exactly afterwards.
func (c *Client) SearchUsers(ctx context.Context, search string) ([]User, error) {
	return list[User](ctx, c, "/api/users", search)
}

// Users returns every user, each with its groups: ListUsers preloads them
// (service/user_service.go:55-60).
func (c *Client) Users(ctx context.Context) ([]User, error) {
	return list[User](ctx, c, "/api/users", "")
}

// HasAdmin reports whether any user is an admin, reading GET /api/users page
// by page and stopping at the first that is. Read only.
func (c *Client) HasAdmin(ctx context.Context) (bool, error) {
	found := false
	err := pages(ctx, c, "/api/users", "", func(users []User) bool {
		found = slices.ContainsFunc(users, func(u User) bool { return u.IsAdmin })
		return found
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

// User reads one user with its groups. GET /api/users/:id
// (controller/user_controller.go:32; service/user_service.go:74-84 preloads
// UserGroups).
func (c *Client) User(ctx context.Context, id string) (User, error) {
	var out User
	err := c.do(ctx, "GET", "/api/users/"+url.PathEscape(id), nil, nil, &out, 200)
	return out, err
}

// CreateUser creates a user. POST /api/users answers 201 with the user
// (controller/user_controller.go:33, :266).
func (c *Client) CreateUser(ctx context.Context, u NewUser) (User, error) {
	var out User
	err := c.do(ctx, "POST", "/api/users", nil, u, &out, 201)
	return out, err
}

// SetAdmin makes an existing user an administrator. See updateUser.
func (c *Client) SetAdmin(ctx context.Context, u User) error {
	u.IsAdmin = true
	return c.updateUser(ctx, u)
}

// Demote makes an existing administrator an ordinary user. See updateUser.
func (c *Client) Demote(ctx context.Context, u User) error {
	u.IsAdmin = false
	return c.updateUser(ctx, u)
}

// VerifyEmail marks an existing user's email address verified, so the ID
// tokens Pocket ID issues for them carry email_verified true. See updateUser.
//
// An administrator's update stores emailVerified as sent
// (service/user_service.go:552-554). The one rule that would override it,
// resetting verification to the EMAILS_VERIFIED setting, applies only when the
// email changes (service/user_service.go:544-547), and the email is sent back
// unchanged.
func (c *Client) VerifyEmail(ctx context.Context, u User) error {
	u.EmailVerified = true
	return c.updateUser(ctx, u)
}

// UserChange is what UpdateUser may change about a user. A nil field is left
// as Pocket ID holds it. The username, the admin flag and the locale are not
// here, so no caller of UpdateUser can change them.
type UserChange struct {
	Email         *string
	EmailVerified *bool
	FirstName     *string
	LastName      *string
	DisplayName   *string
	Disabled      *bool
}

func (ch UserChange) empty() bool {
	return ch == UserChange{}
}

// UpdateUser reads the user, changes only the fields change sets, and sends
// every other field back as it was read (see updateUser), so the read and
// the write are one call and no field can be sent from anywhere but Pocket
// ID's own answer. It returns the user Pocket ID holds afterwards, with the
// groups it read, since this route does not return them. A change
// that sets nothing sends nothing and returns the user as read.
//
// An administrator's update stores emailVerified as sent, after Pocket ID has
// reset it for a changed email (service/user_service.go:544-555 at v2.18.0),
// so Email and EmailVerified set together keep the address verified. A user
// an LDAP sync manages takes only a locale from this route (:530-536), so
// UpdateUser refuses one rather than report a change Pocket ID did not make.
func (c *Client) UpdateUser(ctx context.Context, id string, change UserChange) (User, error) {
	u, err := c.User(ctx, id)
	if err != nil {
		return User{}, err
	}
	if change.empty() {
		return u, nil
	}
	if u.LdapID != nil {
		return User{}, fmt.Errorf("user %s is managed by LDAP, and Pocket ID takes only a locale for one", u.Username)
	}
	if change.Email != nil {
		u.Email = change.Email
	}
	if change.EmailVerified != nil {
		u.EmailVerified = *change.EmailVerified
	}
	if change.FirstName != nil {
		u.FirstName = *change.FirstName
	}
	if change.LastName != nil {
		u.LastName = change.LastName
	}
	if change.DisplayName != nil {
		u.DisplayName = *change.DisplayName
	}
	if change.Disabled != nil {
		u.Disabled = *change.Disabled
	}
	var out User
	if err := c.put(ctx, u, &out); err != nil {
		return User{}, err
	}
	// The update's answer leaves out the user's groups, which the update
	// neither reads nor writes, so they are the ones read before it.
	out.UserGroups = u.UserGroups
	return out, nil
}

// updateUser sends a user back as given.
//
// PUT /api/users/:id (controller/user_controller.go:34, :279-281, :430-440)
// takes the whole create DTO and overwrites every personal field, admin flag,
// verification and disabled state with what it is sent
// (service/user_service.go:532-556), so a caller changes one field of the user
// exactly as read and sends the rest unchanged. Sending only the one field
// would blank the name.
func (c *Client) updateUser(ctx context.Context, u User) error {
	return c.put(ctx, u, nil)
}

// put is updateUser's request, decoding Pocket ID's answer into out when it
// is not nil.
func (c *Client) put(ctx context.Context, u User, out *User) error {
	lastName := ""
	if u.LastName != nil {
		lastName = *u.LastName
	}
	body := map[string]any{
		"username":      u.Username,
		"email":         u.Email,
		"emailVerified": u.EmailVerified,
		"firstName":     u.FirstName,
		"lastName":      lastName,
		"displayName":   u.DisplayName,
		"isAdmin":       u.IsAdmin,
		"locale":        u.Locale,
		"disabled":      u.Disabled,
	}
	var into any
	if out != nil {
		into = out
	}
	return c.do(ctx, "PUT", "/api/users/"+url.PathEscape(u.ID), nil, body, into, 200)
}

// LoginToken issues a one-time access token for a user, valid for ttl and for
// one sign in. POST /api/users/:id/one-time-access-token answers 201 with
// {"token": ...} (onetimeaccess/module.go:68, handler.go:36-60). The ttl is a
// Go duration string (utils/json_util.go:19-35) and must be over a second and
// at most 31 days (dto/validations.go:42, :51-58).
//
// The token is a credential. It is returned to the caller and never put into
// an error.
func (c *Client) LoginToken(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	err := c.do(ctx, "POST", "/api/users/"+url.PathEscape(userID)+"/one-time-access-token", nil,
		map[string]string{"ttl": ttl.String()}, &out, 201)
	if err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("Pocket ID answered 201 without a token")
	}
	return out.Token, nil
}

// EmailLoginLink has Pocket ID email a user a one-time login link, valid for
// ttl and for one sign in. POST /api/users/:id/one-time-access-email answers
// 204 (onetimeaccess/module.go:69, handler.go:103-128) once the token is
// stored, and sends the email afterwards, in the background
// (onetimeaccess/service.go:105-133), so a 204 says nothing about the send. A
// failed send is logged by Pocket ID as `Failed to send one-time access token
// email` with the address; see EmailFailure. The token is Pocket ID's own and
// is never returned, so the emailed link is not the one LoginToken returns.
//
// Pocket ID refuses it unless EMAIL_ONE_TIME_ACCESS_AS_ADMIN_ENABLED is true
// (onetimeaccess/service.go:56-61), and for a user without an email
// (:95-97).
func (c *Client) EmailLoginLink(ctx context.Context, userID string, ttl time.Duration) error {
	return c.do(ctx, "POST", "/api/users/"+url.PathEscape(userID)+"/one-time-access-email", nil,
		map[string]string{"ttl": ttl.String()}, nil, 204)
}

// AuditEvent is the part of dto.AuditLogDto (dto/audit_log_dto.go:7-20) read
// here.
type AuditEvent struct {
	Event  string `json:"event"`
	UserID string `json:"userID"`
}

// HasPasskey reports whether a user has ever registered a passkey: whether
// the audit log holds a PASSKEY_ADDED event for them
// (model/audit_log.go:38, written at webauthn/service.go:208). No admin route
// lists another user's passkeys, so this is the one read that answers it.
//
// GET /api/audit-logs/all (controller/audit_log_controller.go:24) filters on
// the model's filterable fields, Event and UserID (model/audit_log.go:10-22),
// by the key the frontend sends, userID (audit-log-list.svelte:71); a key it
// does not know is ignored rather than refused
// (utils/list_request_util.go:133-147). So each row's user is checked as
// well, and a filter that did not apply cannot answer for someone else.
// Read only.
func (c *Client) HasPasskey(ctx context.Context, userID string) (bool, error) {
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("filters[userID]", userID)
		q.Set("filters[event]", "PASSKEY_ADDED")
		q.Set("pagination[page]", strconv.Itoa(page))
		q.Set("pagination[limit]", strconv.Itoa(pageSize))
		var got paginated[AuditEvent]
		if err := c.do(ctx, "GET", "/api/audit-logs/all", q, nil, &got, 200); err != nil {
			return false, err
		}
		if slices.ContainsFunc(got.Data, func(e AuditEvent) bool {
			return e.UserID == userID && e.Event == "PASSKEY_ADDED"
		}) {
			return true, nil
		}
		if page >= got.Pagination.TotalPages || len(got.Data) == 0 {
			return false, nil
		}
	}
}

// LoginLink is where a one-time token is exchanged in a browser: the app's
// public URL, /lc/, and the token, the same link Pocket ID's own CLI prints
// (cmds/one_time_access_token.go:67; frontend/src/routes/lc/[code]).
func LoginLink(publicURL, token string) string {
	return strings.TrimRight(publicURL, "/") + "/lc/" + token
}

// FindGroup returns the group with exactly this name, or nil.
// GET /api/user-groups (controller/user_group_controller.go:29).
func (c *Client) FindGroup(ctx context.Context, name string) (*Group, error) {
	groups, err := list[Group](ctx, c, "/api/user-groups", name)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.Name == name {
			return &g, nil
		}
	}
	return nil, nil
}

// Groups returns every group, empty ones included, reading GET
// /api/user-groups (controller/user_group_controller.go:29) page by page to
// the last.
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	return list[Group](ctx, c, "/api/user-groups", "")
}

// ValidGroupName is whether CreateGroup's request would pass Pocket ID
// v2.18.0 for name. The group DTO binds the name to `required,min=2,max=255`
// and the friendly name to `required,min=2,max=50`
// (dto/user_group_dto.go:36-37), with no character pattern on either, and
// CreateGroup sends name as both, so the tighter bound governs. The validator
// counts characters, not bytes. Pocket ID normalises to NFC before it checks
// (`unorm:"nfc"`); a name that is not in NFC is judged here as written, which
// differs only for a name whose composed form is shorter by a character.
func ValidGroupName(name string) bool {
	n := utf8.RuneCountInString(name)
	return n >= 2 && n <= 50
}

// CreateGroup creates a group whose name and friendly name are both name.
// POST /api/user-groups answers 201 (controller/user_group_controller.go:31,
// :137); both fields are required, 2 to 50 characters for the friendly name
// (dto/user_group_dto.go:35-39).
func (c *Client) CreateGroup(ctx context.Context, name string) (Group, error) {
	var out Group
	err := c.do(ctx, "POST", "/api/user-groups", nil, map[string]string{"name": name, "friendlyName": name}, &out, 201)
	return out, err
}

// SetUserGroups replaces a user's groups. PUT /api/users/:id/user-groups
// (controller/user_controller.go:41, :391-410) replaces the whole set, so a
// caller adding one group sends the user's current groups as well.
func (c *Client) SetUserGroups(ctx context.Context, userID string, groupIDs []string) error {
	return c.do(ctx, "PUT", "/api/users/"+url.PathEscape(userID)+"/user-groups", nil,
		map[string][]string{"userGroupIds": groupIDs}, nil, 200)
}

// OIDCClient is dto.OidcClientWithAllowedUserGroupsDto
// (dto/oidc_dto.go:20-39), the parts read here.
type OIDCClient struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	CallbackURLs      []string `json:"callbackURLs"`
	IsPublic          bool     `json:"isPublic"`
	PkceEnabled       bool     `json:"pkceEnabled"`
	IsGroupRestricted bool     `json:"isGroupRestricted"`
	AllowedUserGroups []Group  `json:"allowedUserGroups"`
	LaunchURL         *string  `json:"launchURL"`
	// HasLogo is dto.OidcClientMetaDataDto.HasLogo (dto/oidc_dto.go:13 at
	// v2.18.0); the logo itself is public at GET /api/oidc/clients/:id/logo
	// (controller/oidc_controller.go:43).
	HasLogo bool `json:"hasLogo"`
	// HasDarkLogo is dto.OidcClientMetaDataDto.HasDarkLogo (dto/oidc_dto.go:14
	// at v2.18.0), set by the list (controller/oidc_controller.go:143).
	// GET /api/oidc/clients/:id/logo?light=false serves it, falling back to
	// the other variant when there is none (service/oidc_service.go:526-537).
	HasDarkLogo bool `json:"hasDarkLogo"`
	// SkipConsent is dto.OidcClientDto.SkipConsent (dto/oidc_dto.go:28 at
	// v2.18.0).
	SkipConsent bool `json:"skipConsent"`
}

// NewOIDCClient is dto.OidcClientCreateDto (dto/oidc_dto.go:52-77), the fields
// set here. The ID is left to Pocket ID. LaunchURL is what puts the client
// on a member's dashboard: the list the dashboard reads shows only clients
// that have one, as a single query at v2.18.0 (service/oidc_service.go:839-846).
type NewOIDCClient struct {
	Name              string   `json:"name"`
	CallbackURLs      []string `json:"callbackURLs"`
	IsPublic          bool     `json:"isPublic"`
	PkceEnabled       bool     `json:"pkceEnabled"`
	IsGroupRestricted bool     `json:"isGroupRestricted"`
	LaunchURL         string   `json:"launchURL,omitempty"`
	// SkipConsent is dto.OidcClientCreateDto.SkipConsent (dto/oidc_dto.go:62),
	// accepted on create as on update. It has no omitempty: false is a
	// choice the plan shows, not an absence.
	SkipConsent bool `json:"skipConsent"`
}

// OIDCClients returns every client, all pages
// (controller/oidc_controller.go:30 at v2.18.0), each with its allowed
// groups.
func (c *Client) OIDCClients(ctx context.Context) ([]OIDCClient, error) {
	return list[OIDCClient](ctx, c, "/api/oidc/clients", "")
}

// FindOIDCClient returns the client with exactly this name, with its allowed
// groups, or nil. The list (controller/oidc_controller.go:30, :127-157)
// searches by name and gives each client's allowed groups.
func (c *Client) FindOIDCClient(ctx context.Context, name string) (*OIDCClient, error) {
	clients, err := list[OIDCClient](ctx, c, "/api/oidc/clients", name)
	if err != nil {
		return nil, err
	}
	for _, found := range clients {
		if found.Name == name {
			return &found, nil
		}
	}
	return nil, nil
}

// OIDCClientByID returns the client with this ID, or nil when Pocket ID holds
// none. GET /api/oidc/clients/:id (controller/oidc_controller.go:32) answers
// 404 for an ID it does not hold: the service maps gorm's record not found to
// apperror.NotFound (service/oidc_service.go, getClientInternal), which is
// http.StatusNotFound (apperror/constructors.go:14-16), at tag v2.18.0.
func (c *Client) OIDCClientByID(ctx context.Context, id string) (*OIDCClient, error) {
	var out OIDCClient
	err := c.do(ctx, "GET", "/api/oidc/clients/"+url.PathEscape(id), nil, nil, &out, 200)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == 404 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteOIDCClient deletes a client by ID. DELETE /api/oidc/clients/:id
// answers 204 (controller/oidc_controller.go:36, deleteClientHandler) and 404
// for an ID it does not hold (service/oidc_service.go, DeleteClient), at tag
// v2.18.0. A 404 is success here, so a run interrupted after the delete
// reaches the same end on the next one.
func (c *Client) DeleteOIDCClient(ctx context.Context, id string) error {
	err := c.do(ctx, "DELETE", "/api/oidc/clients/"+url.PathEscape(id), nil, nil, nil, 204)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == 404 {
		return nil
	}
	return err
}

// CreateOIDCClient creates a client. POST /api/oidc/clients answers 201
// (controller/oidc_controller.go:29, :166-186). It creates no secret.
func (c *Client) CreateOIDCClient(ctx context.Context, n NewOIDCClient) (OIDCClient, error) {
	var out OIDCClient
	err := c.do(ctx, "POST", "/api/oidc/clients", nil, n, &out, 201)
	return out, err
}

// clientUpdateFields are the fields of dto.OidcClientUpdateDto
// (dto/oidc_dto.go:41-60) that the update writes to the client
// (service/oidc_service.go:252-294) and that a read of the client returns
// (dto/oidc_dto.go:5-29), apart from credentials, which is handled on its own.
var clientUpdateFields = []string{
	"name", "description", "callbackURLs", "logoutCallbackURLs", "isPublic",
	"pkceEnabled", "requiresReauthentication", "requiresPushedAuthorizationRequests",
	"skipConsent", "isGroupRestricted", "accessTokenDurationMinutes",
	"refreshTokenDurationMinutes", "launchURL",
}

// SetSkipConsent sets whether the client skips Pocket ID's consent screen and
// leaves the rest of it as it is (see updateClient). The update DTO takes
// skipConsent (dto/oidc_dto.go:62 at v2.18.0) and writes it with the other
// fields, so it travels in the same whole-client PUT.
func (c *Client) SetSkipConsent(ctx context.Context, clientID string, skip bool) error {
	return c.updateClient(ctx, clientID, "skipConsent", skip)
}

// SetLaunchURL sets a client's launch URL and leaves the rest of it as it is
// (see updateClient).
func (c *Client) SetLaunchURL(ctx context.Context, clientID, launchURL string) error {
	return c.updateClient(ctx, clientID, "launchURL", launchURL)
}

// SetClientName renames a client and leaves the rest of it as it is (see
// updateClient). The name is what Pocket ID shows a person signing in with
// the client, and is how a caller can find the client again.
func (c *Client) SetClientName(ctx context.Context, clientID, name string) error {
	return c.updateClient(ctx, clientID, "name", name)
}

// updateClient sets one field of a client and leaves the rest of it as it is.
//
// PUT /api/oidc/clients/:id (controller/oidc_controller.go:32, :217-237)
// overwrites every field it takes with what it is sent
// (service/oidc_service.go:186-250, :252-294), so the client is read again
// and every field sent back as read, with only the one field changed. In
// particular: callback URLs, PKCE and the public flag are sent unchanged;
// isGroupRestricted is sent unchanged, which matters because sending false
// clears the allowed groups (:199-205); the launch URL is sent back, since
// the update writes it too; the federated credentials are sent back, since
// the update replaces them (:282-292). Secrets are not sent and would be
// ignored (dto/oidc_dto.go:93-94), and neither is a logo URL, which is
// fetched only when one is sent (:235-247).
//
// One side effect is Pocket ID's own: a client with PKCE off has its "PKCE
// supported" hint cleared (:277-280), as saving it in the admin UI does.
func (c *Client) updateClient(ctx context.Context, clientID, field string, value any) error {
	path := "/api/oidc/clients/" + url.PathEscape(clientID)
	var current map[string]json.RawMessage
	if err := c.do(ctx, "GET", path, nil, nil, &current, 200); err != nil {
		return err
	}
	body := map[string]any{}
	for _, k := range clientUpdateFields {
		if v, ok := current[k]; ok {
			body[k] = v
		}
	}
	var creds struct {
		FederatedIdentities json.RawMessage `json:"federatedIdentities,omitempty"`
	}
	if raw, ok := current["credentials"]; ok {
		if err := json.Unmarshal(raw, &creds); err != nil {
			return fmt.Errorf("GET %s: its credentials are not the JSON expected: %v", path, err)
		}
	}
	body["credentials"] = creds
	body[field] = value
	return c.do(ctx, "PUT", path, nil, body, nil, 200)
}

// SetAllowedGroups replaces the groups a restricted client admits.
// PUT /api/oidc/clients/:id/allowed-user-groups (controller/oidc_controller.go:38)
// replaces the association and leaves isGroupRestricted as it was
// (service/oidc_service.go:656-702).
func (c *Client) SetAllowedGroups(ctx context.Context, clientID string, groupIDs []string) error {
	return c.do(ctx, "PUT", "/api/oidc/clients/"+url.PathEscape(clientID)+"/allowed-user-groups", nil,
		map[string][]string{"userGroupIds": groupIDs}, nil, 200)
}

// ClientSecret is dto.OidcClientSecretDto (dto/oidc_dto.go:79-87): never the
// value, only its first four characters (model/oidc.go:43,
// service/oidc_service.go:511-518).
type ClientSecret struct {
	ID       string `json:"id"`
	Prefix   string `json:"prefix"`
	IsActive bool   `json:"isActive"`
}

// MaxClientSecrets is how many secrets one client may hold (model/oidc.go:41).
const MaxClientSecrets = 20

// ClientSecrets lists a client's secrets, without their values.
// GET /api/oidc/clients/:id/secrets (controller/oidc_controller.go:39, :285-299).
func (c *Client) ClientSecrets(ctx context.Context, clientID string) ([]ClientSecret, error) {
	var out []ClientSecret
	err := c.do(ctx, "GET", "/api/oidc/clients/"+url.PathEscape(clientID)+"/secrets", nil, nil, &out, 200)
	return out, err
}

// AddClientSecret gives a client a secret whose value the caller chose.
//
// POST /api/oidc/clients/:id/secrets accepts a caller supplied value of at
// least 16 printable ASCII characters (dto/oidc_dto.go:89-95,
// service/oidc_service.go:452-460) and leaves the client's other secrets
// usable (controller/oidc_controller.go:303). Supplying the value is what lets
// the caller record it before Pocket ID ever holds it. The response echoes
// it (dto/oidc_dto.go:97-101), so the response is read for nothing and the
// value is scrubbed from any error.
func (c *Client) AddClientSecret(ctx context.Context, clientID, secret string) error {
	return c.do(ctx, "POST", "/api/oidc/clients/"+url.PathEscape(clientID)+"/secrets", nil,
		map[string]string{"secret": secret}, nil, 201, secret)
}

// DeleteClientSecret deletes one of a client's secrets by its ID, so that a
// value an app no longer presents stops being valid.
// DELETE /api/oidc/clients/:id/secrets/:secretId answers 204
// (controller/oidc_controller.go, deleteClientSecretHandler), and the service
// answers apperror.NotFound, a 404, for a client or a secret it does not hold
// (service/oidc_service.go, DeleteClientSecret), at tag v2.18.0. A 404 is
// success here, so a run interrupted after the delete reaches the same end on
// the next one. Nothing in the request or the answer carries a secret's value.
func (c *Client) DeleteClientSecret(ctx context.Context, clientID, secretID string) error {
	err := c.do(ctx, "DELETE", "/api/oidc/clients/"+url.PathEscape(clientID)+"/secrets/"+url.PathEscape(secretID), nil, nil, nil, 204)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == 404 {
		return nil
	}
	return err
}

// SecretPrefixLength is how much of a secret Pocket ID keeps in clear text
// (model/oidc.go:43).
const SecretPrefixLength = 4

// HasActiveSecret reports whether any active secret's stored prefix is the
// start of value. Four characters is a check against an obvious mismatch, not
// a proof: it is all Pocket ID keeps that can be compared without the value.
// A secret shorter than five characters keeps no prefix at all
// (service/oidc_service.go:513-515).
func HasActiveSecret(secrets []ClientSecret, value string) bool {
	if len(value) <= SecretPrefixLength {
		return false
	}
	for _, s := range secrets {
		if s.IsActive && s.Prefix != "" && strings.HasPrefix(value, s.Prefix) {
			return true
		}
	}
	return false
}
