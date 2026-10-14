# Changelog

All notable changes to this project are documented here, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## [Unreleased]

## [0.1.0] - 2026-10-14

### Added

- A Go client for Pocket ID v2's REST API with its static API key, over HTTP or through curl on a host.
- Every method takes a context.Context first; the HTTP path cancels with it.
- The API key is sent only to a private address or a network the caller names; anything else is refused before a request.
- ErrNoAPIKey is returned before any request by a client without a key.
