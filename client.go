// Package pocketid calls a running Pocket ID's REST API from the workstation,
// through curl on the host it runs on.
//
// Every route, payload and status code here was read from Pocket ID's source
// at tag v2.14.0 (github.com/pocket-id/pocket-id); each method cites where.
//
// The request goes over the operator's own ssh to the site, where curl calls
// the port Pocket ID publishes on that site's mesh address. Everything that
// varies, the URL, the API key and the body, travels in a curl config on
// stdin (`curl --config -`), so the command line is the same constant for
// every request and carries nothing: a command line is in the process table,
// readable by every user on the host, for as long as it runs.
//
// Rejected: an API key file on the host for an operator's curl. It would be a
// second long lived copy of an admin credential, outside the rendered set that
// apply owns and audits, and readable by whoever can read that file rather
// than only by whoever holds the age key to the secrets file.
package pocketid

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Transport is the part of an ssh transport this package uses. It is declared
// here so the package depends on the shape and not on apply;
// apply.SSHTransport satisfies it.
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
const statusMarker = "\npaisans-http-status:"

// Client is one Pocket ID, reached at BaseURL from the host the Transport
// reaches. BaseURL is the published mesh port, as in http://10.44.0.1:1411.
//
// HTTP, when set, sends each request straight to BaseURL instead, and
// Transport is not used. That is for code running beside Pocket ID on the
// mesh, such as the admin reconciler, which has no ssh to go through.
type Client struct {
	Transport Transport
	HTTP      *http.Client
	BaseURL   string
	APIKey    string
}

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
func (c *Client) do(method, path string, query url.Values, body, out any, want int, secrets ...string) error {
	secrets = append(secrets, c.APIKey)
	var status int
	var payload string
	var err error
	if c.HTTP != nil {
		status, payload, err = c.send(method, path, query, body)
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
func (c *Client) send(method, path string, query url.Values, body any) (int, string, error) {
	if c.APIKey == "" {
		return 0, "", errors.New("no API key: set apps.<pocket-id app>.static_api_key with `paisans init` and apply it")
	}
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
	req, err := http.NewRequest(method, target, reader)
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
	if c.APIKey == "" {
		return "", errors.New("no API key: set apps.<pocket-id app>.static_api_key with `paisans init` and apply it")
	}
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
// (utils/list_request_util.go:60-64).
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
func list[T any](c *Client, path, search string) ([]T, error) {
	var out []T
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("search", search)
		q.Set("pagination[page]", strconv.Itoa(page))
		q.Set("pagination[limit]", strconv.Itoa(pageSize))
		var got paginated[T]
		if err := c.do("GET", path, q, nil, &got, 200); err != nil {
			return nil, err
		}
		out = append(out, got.Data...)
		if page >= got.Pagination.TotalPages || len(got.Data) == 0 {
			return out, nil
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
// EmailVerified is stored as sent (service/user_service.go:299); left out, it
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
func (c *Client) FindUser(username string) (*User, error) {
	users, err := list[User](c, "/api/users", username)
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

// Users returns every user, each with its groups: ListUsers preloads them
// (service/user_service.go:51-56).
func (c *Client) Users() ([]User, error) {
	return list[User](c, "/api/users", "")
}

// User reads one user with its groups. GET /api/users/:id
// (controller/user_controller.go:32; service/user_service.go:70-80 preloads
// UserGroups).
func (c *Client) User(id string) (User, error) {
	var out User
	err := c.do("GET", "/api/users/"+url.PathEscape(id), nil, nil, &out, 200)
	return out, err
}

// CreateUser creates a user. POST /api/users answers 201 with the user
// (controller/user_controller.go:33, :266).
func (c *Client) CreateUser(u NewUser) (User, error) {
	var out User
	err := c.do("POST", "/api/users", nil, u, &out, 201)
	return out, err
}

// SetAdmin makes an existing user an administrator. See updateUser.
func (c *Client) SetAdmin(u User) error {
	u.IsAdmin = true
	return c.updateUser(u)
}

// VerifyEmail marks an existing user's email address verified, so the ID
// tokens Pocket ID issues for them carry email_verified true. See updateUser.
//
// An administrator's update stores emailVerified as sent
// (service/user_service.go:515-517). The one rule that would override it,
// resetting verification to the EMAILS_VERIFIED setting, applies only when the
// email changes (service/user_service.go:507-510), and the email is sent back
// unchanged.
func (c *Client) VerifyEmail(u User) error {
	u.EmailVerified = true
	return c.updateUser(u)
}

// updateUser sends a user back as given.
//
// PUT /api/users/:id (controller/user_controller.go:34, :279-281, :430-440)
// takes the whole create DTO and overwrites every personal field, admin flag,
// verification and disabled state with what it is sent
// (service/user_service.go:495-519), so a caller changes one field of the user
// exactly as read and sends the rest unchanged. Sending only the one field
// would blank the name.
func (c *Client) updateUser(u User) error {
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
	return c.do("PUT", "/api/users/"+url.PathEscape(u.ID), nil, body, nil, 200)
}

// LoginToken issues a one-time access token for a user, valid for ttl and for
// one sign in. POST /api/users/:id/one-time-access-token answers 201 with
// {"token": ...} (onetimeaccess/module.go:68, handler.go:36-60). The ttl is a
// Go duration string (utils/json_util.go:19-35) and must be over a second and
// at most 31 days (dto/validations.go:42, :51-58).
//
// The token is a credential. It is returned to the caller and never put into
// an error.
func (c *Client) LoginToken(userID string, ttl time.Duration) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	err := c.do("POST", "/api/users/"+url.PathEscape(userID)+"/one-time-access-token", nil,
		map[string]string{"ttl": ttl.String()}, &out, 201)
	if err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("Pocket ID answered 201 without a token")
	}
	return out.Token, nil
}

// LoginLink is where a one-time token is exchanged in a browser: the app's
// public URL, /lc/, and the token, the same link Pocket ID's own CLI prints
// (cmds/one_time_access_token.go:78; frontend/src/routes/lc/[code]).
func LoginLink(publicURL, token string) string {
	return strings.TrimRight(publicURL, "/") + "/lc/" + token
}

// FindGroup returns the group with exactly this name, or nil.
// GET /api/user-groups (controller/user_group_controller.go:29).
func (c *Client) FindGroup(name string) (*Group, error) {
	groups, err := list[Group](c, "/api/user-groups", name)
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

// CreateGroup creates a group whose name and friendly name are both name.
// POST /api/user-groups answers 201 (controller/user_group_controller.go:31,
// :137); both fields are required, 2 to 50 characters for the friendly name
// (dto/user_group_dto.go:35-39).
func (c *Client) CreateGroup(name string) (Group, error) {
	var out Group
	err := c.do("POST", "/api/user-groups", nil, map[string]string{"name": name, "friendlyName": name}, &out, 201)
	return out, err
}

// SetUserGroups replaces a user's groups. PUT /api/users/:id/user-groups
// (controller/user_controller.go:41, :391-410) replaces the whole set, so a
// caller adding one group sends the user's current groups as well.
func (c *Client) SetUserGroups(userID string, groupIDs []string) error {
	return c.do("PUT", "/api/users/"+url.PathEscape(userID)+"/user-groups", nil,
		map[string][]string{"userGroupIds": groupIDs}, nil, 200)
}

// OIDCClient is dto.OidcClientWithAllowedUserGroupsDto
// (dto/oidc_dto.go:16-34), the parts read here.
type OIDCClient struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	CallbackURLs      []string `json:"callbackURLs"`
	IsPublic          bool     `json:"isPublic"`
	PkceEnabled       bool     `json:"pkceEnabled"`
	IsGroupRestricted bool     `json:"isGroupRestricted"`
	AllowedUserGroups []Group  `json:"allowedUserGroups"`
	LaunchURL         *string  `json:"launchURL"`
}

// NewOIDCClient is dto.OidcClientCreateDto (dto/oidc_dto.go:41-65), the fields
// set here. The ID is left to Pocket ID. LaunchURL is what puts the client
// on a member's dashboard: both lists the dashboard reads show only clients
// that have one (service/oidc_service.go:673-680, :758-765).
type NewOIDCClient struct {
	Name              string   `json:"name"`
	CallbackURLs      []string `json:"callbackURLs"`
	IsPublic          bool     `json:"isPublic"`
	PkceEnabled       bool     `json:"pkceEnabled"`
	IsGroupRestricted bool     `json:"isGroupRestricted"`
	LaunchURL         string   `json:"launchURL,omitempty"`
}

// FindOIDCClient returns the client with exactly this name, with its allowed
// groups, or nil. The list (controller/oidc_controller.go:28, :124-154) gives
// only a count of allowed groups, so the match is read again by ID
// (controller/oidc_controller.go:30).
func (c *Client) FindOIDCClient(name string) (*OIDCClient, error) {
	clients, err := list[OIDCClient](c, "/api/oidc/clients", name)
	if err != nil {
		return nil, err
	}
	for _, found := range clients {
		if found.Name != name {
			continue
		}
		var full OIDCClient
		if err := c.do("GET", "/api/oidc/clients/"+url.PathEscape(found.ID), nil, nil, &full, 200); err != nil {
			return nil, err
		}
		return &full, nil
	}
	return nil, nil
}

// CreateOIDCClient creates a client. POST /api/oidc/clients answers 201
// (controller/oidc_controller.go:29, :166-186). It creates no secret.
func (c *Client) CreateOIDCClient(n NewOIDCClient) (OIDCClient, error) {
	var out OIDCClient
	err := c.do("POST", "/api/oidc/clients", nil, n, &out, 201)
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
	"refreshTokenDurationMinutes",
}

// SetLaunchURL sets a client's launch URL and leaves the rest of it as it is.
//
// PUT /api/oidc/clients/:id (controller/oidc_controller.go:32, :217-237)
// overwrites every field it takes with what it is sent
// (service/oidc_service.go:186-250, :252-294), so the client is read again
// and every field sent back as read, with only launchURL changed. In
// particular: callback URLs, PKCE and the public flag are sent unchanged;
// isGroupRestricted is sent unchanged, which matters because sending false
// clears the allowed groups (:199-205); the federated credentials are sent
// back, since the update replaces them (:282-292). Secrets are not sent and
// would be ignored (dto/oidc_dto.go:93-94), and neither is a logo URL, which
// is fetched only when one is sent (:235-247).
//
// One side effect is Pocket ID's own: a client with PKCE off has its "PKCE
// supported" hint cleared (:277-280), as saving it in the admin UI does.
func (c *Client) SetLaunchURL(clientID, launchURL string) error {
	path := "/api/oidc/clients/" + url.PathEscape(clientID)
	var current map[string]json.RawMessage
	if err := c.do("GET", path, nil, nil, &current, 200); err != nil {
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
	body["launchURL"] = launchURL
	return c.do("PUT", path, nil, body, nil, 200)
}

// SetAllowedGroups replaces the groups a restricted client admits.
// PUT /api/oidc/clients/:id/allowed-user-groups (controller/oidc_controller.go:36)
// replaces the association and leaves isGroupRestricted as it was
// (service/oidc_service.go:578-623).
func (c *Client) SetAllowedGroups(clientID string, groupIDs []string) error {
	return c.do("PUT", "/api/oidc/clients/"+url.PathEscape(clientID)+"/allowed-user-groups", nil,
		map[string][]string{"userGroupIds": groupIDs}, nil, 200)
}

// ClientSecret is dto.OidcClientSecretDto (dto/oidc_dto.go:67-75): never the
// value, only its first four characters (model/oidc.go:43,
// service/oidc_service.go:436-442).
type ClientSecret struct {
	ID       string `json:"id"`
	Prefix   string `json:"prefix"`
	IsActive bool   `json:"isActive"`
}

// MaxClientSecrets is how many secrets one client may hold (model/oidc.go:41).
const MaxClientSecrets = 20

// ClientSecrets lists a client's secrets, without their values.
// GET /api/oidc/clients/:id/secrets (controller/oidc_controller.go:37, :274-288).
func (c *Client) ClientSecrets(clientID string) ([]ClientSecret, error) {
	var out []ClientSecret
	err := c.do("GET", "/api/oidc/clients/"+url.PathEscape(clientID)+"/secrets", nil, nil, &out, 200)
	return out, err
}

// AddClientSecret gives a client a secret whose value the caller chose.
//
// POST /api/oidc/clients/:id/secrets accepts a caller supplied value of at
// least 16 printable ASCII characters (dto/oidc_dto.go:77-83,
// service/oidc_service.go:357-364) and leaves the client's other secrets
// usable (controller/oidc_controller.go:292). Supplying the value is what lets
// the toolkit record it before Pocket ID ever holds it. The response echoes
// it (dto/oidc_dto.go:85-89), so the response is read for nothing and the
// value is scrubbed from any error.
func (c *Client) AddClientSecret(clientID, secret string) error {
	return c.do("POST", "/api/oidc/clients/"+url.PathEscape(clientID)+"/secrets", nil,
		map[string]string{"secret": secret}, nil, 201, secret)
}

// SecretPrefixLength is how much of a secret Pocket ID keeps in clear text
// (model/oidc.go:43).
const SecretPrefixLength = 4

// HasActiveSecret reports whether any active secret's stored prefix is the
// start of value. Four characters is a check against an obvious mismatch, not
// a proof: it is all Pocket ID keeps that can be compared without the value.
// A secret shorter than five characters keeps no prefix at all
// (service/oidc_service.go:437-439).
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
