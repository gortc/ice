package ice

import (
	"net"

	"github.com/gortc/ice/internal"
)

// See Deprecating Site Local Addresses [RFC3879]
var siteLocalIPv6 = internal.MustParseNet("FEC0::/10")

// IsHostIPValid reports whether ip is valid as host address ip.
func IsHostIPValid(ip net.IP, ipv6Only bool) bool {
	var (
		v4 = ip.To4() != nil
		v6 = !v4
	)
	if v6 && ip.To16() == nil {
		return false
	}
	if v4 && ipv6Only {
		// IPv4-mapped IPv6 addresses SHOULD NOT be included in the address
		// candidates unless the application using ICE does not support IPv4
		// (i.e., it is an IPv6-only application [RFC4038]).
		return false
	}
	if ip.IsLoopback() {
		// Addresses from a loopback interface MUST NOT be included in the
		// candidate addresses.
		return false
	}
	if siteLocalIPv6.Contains(ip) {
		// Deprecated IPv4-compatible IPv6 addresses [RFC4291] and IPv6 site-
		// local unicast addresses [RFC3879] MUST NOT be included in the
		// address candidates.
		return false
	}
	if ip.IsLinkLocalUnicast() && v6 {
		// When host candidates corresponding to an IPv6 address generated
		// using a mechanism that prevents location tracking are gathered, then
		// host candidates corresponding to IPv6 link-local addresses [RFC4291]
		// MUST NOT be gathered.
		return false
	}
	return true
}
