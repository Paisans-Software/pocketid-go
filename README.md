# pocketid-go

A Go client for [Pocket ID](https://github.com/pocket-id/pocket-id)'s REST
API, called with Pocket ID's static API key. The paisans CLI and the services
a paisans deployment runs beside Pocket ID use it, so they speak to Pocket ID
through one client and one test against a real Pocket ID.

```sh
go get github.com/paisans-software/pocketid-go
```

## Pocket ID versions

The client is written against Pocket ID v2. Every route, payload and status
code was read from Pocket ID's source at v2.14.0, and each method's comment
cites where. The integration test runs against v2.18.0 by default. A Pocket
ID major release is a major release here.

## Two ways to reach Pocket ID

```go
// Beside Pocket ID, on its network: requests go straight to BaseURL.
c := &pocketid.Client{HTTP: &http.Client{}, BaseURL: "http://app:1411", APIKey: key}

// From elsewhere, through a host that can reach it: curl runs there.
c := &pocketid.Client{Transport: sshToSite, BaseURL: "http://10.44.0.1:1411", APIKey: key}

users, err := c.Users(ctx)
```

With `Transport`, the command line is always the same constant,
`CurlCommand`. The URL, the key and the body reach curl as a config on stdin,
because a command line is in the host's process table, readable by every user
there, for as long as it runs, and stdin is not. A `Transport` is anything with
`RunInput(command, stdin string)` and `Describe()`, which an ssh connection
satisfies.

## The key goes only to a private address

The static API key is an administrator's credential, and Pocket ID's API
answers wherever its port is reachable, so the client refuses a `BaseURL`
whose host is not private before it sends anything. Private is:

* a loopback, RFC 1918, RFC 6598 or IPv6 unique local address,
* an address in one of the client's `Networks`, for a network whose addresses
  are not in those ranges,
* a hostname with no dot, such as a service's name on a compose network.

A hostname with a dot is refused even when it resolves to a private address,
since what it resolves to can change between the check and the request. The
error names the host and never the key. `Private` is exported, so a caller can
check an address before it builds a client.

A redirect is answered rather than followed, on either path, so the key never
travels to an address the check did not see.

## Changing a user

`UpdateUser` reads the user and sends every field back as read, except those
its `UserChange` sets: the email and its verification, the names, and
whether the user is disabled. The username, the admin flag and the locale are
not in `UserChange`, so this call cannot change them. A user an LDAP sync
manages is refused, since Pocket ID takes only a locale for one.

## Contexts

Every method takes a `context.Context` first. On the `HTTP` path a cancelled
context cancels the request. On the `Transport` path it is checked before each
request; a curl that has already started on a host runs to its end.

## Errors

Errors never carry the key, or a secret the call sent, in plain or base64
form. A response outside the status a call expects is an `*APIError` with
Pocket ID's own message. A client with no key returns `ErrNoAPIKey` before
any request.

## Tests

```sh
go test ./...
go test -tags pocketid_integration ./...    # needs docker
```

The integration test starts a Pocket ID container and makes every call over
both paths. `POCKETID_IMAGE` names another image to run it against.

## Releases

Tags `vX.Y.Z` on `main`, `0.x` while the API settles. `CHANGELOG.md` records
each release.

## Licence

AGPL-3.0-or-later. The full text is in `LICENSE`.
