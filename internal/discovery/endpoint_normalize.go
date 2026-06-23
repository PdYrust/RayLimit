package discovery

import "strings"

// normalizeWildcardListenHost maps wildcard or unspecified listen hosts to a
// concrete loopback address suitable for dialing the local Xray API. The empty
// host, the IPv4 unspecified address, and the IPv6 unspecified address (both
// the bare "::" and the bracketed "[::]" forms) collapse to 127.0.0.1. Every
// other host is returned unchanged apart from surrounding whitespace trimming.
//
// It is the single source of truth shared by the API server-address builder,
// the endpoint reachability probe, and the published-port mapper so the three
// sites cannot drift in how they treat wildcard binds.
func normalizeWildcardListenHost(host string) string {
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return "127.0.0.1"
	default:
		return host
	}
}
