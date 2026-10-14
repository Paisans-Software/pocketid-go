package pocketid

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// cgnat is RFC 6598's shared address space, which netip does not count as
// private and which overlay networks such as Tailscale use.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Private reports whether host is an address the API key may be sent to: a
// loopback, RFC 1918, RFC 6598 or IPv6 unique local address, an address in
// one of networks, or a hostname with no dot, such as a service's name on a
// compose network. A hostname with a dot is refused even when it resolves to
// a private address, since what it resolves to can change between the check
// and the request.
func Private(host string, networks ...netip.Prefix) bool {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host != "" && !strings.Contains(host, ".") && !strings.Contains(host, ":")
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || cgnat.Contains(addr) {
		return true
	}
	for _, n := range networks {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// private refuses a BaseURL whose host is not Private. The error names the
// host and never the key.
func (c *Client) private() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("Pocket ID's address %q is not a URL", c.BaseURL)
	}
	if !Private(u.Hostname(), c.Networks...) {
		return fmt.Errorf("Pocket ID at %s is not on a private network, and the API key is sent only to one", u.Hostname())
	}
	return nil
}
