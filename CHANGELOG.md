# Changelog

All notable changes to this project are documented here, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## [Unreleased]

## [0.2.0] - 2026-10-14

### Added

- Groups lists every group, empty ones included.
- UpdateUser changes a user's email and its verification, names or disabled state, sending every other field back as read; the username, admin flag and locale cannot change through it.

### Security

- A redirect is answered rather than followed on the HTTP path, so the API key never reaches an address the private check did not see.

## [0.1.0] - 2026-10-14

### Added

- A Go client for Pocket ID v2's REST API with its static API key, over HTTP or through curl on a host.
- Every method takes a context.Context first; the HTTP path cancels with it.
- The API key is sent only to a private address or a network the caller names; anything else is refused before a request.
- ErrNoAPIKey is returned before any request by a client without a key.
