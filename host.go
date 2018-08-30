package ice

import (
	"net"

	"github.com/gortc/ice/candidate"
	"github.com/gortc/ice/gather"
)

// NewHostCandidateGatherer initializes new host candidate gatherer
// that uses host interfaces to gather candidates. Port open procedure
// should be done by user.
func NewHostCandidateGatherer(onlyIPv6 bool) *HostCandidateGatherer {
	return &HostCandidateGatherer{
		host:     gather.DefaultGatherer,
		ipv6Only: onlyIPv6,
	}
}

// HostCandidateGatherer uses host interfaces to gather candidates.
// Performs only address recognition, socket opening must be done by
// user.
type HostCandidateGatherer struct {
	host     gather.Gatherer
	ipv6Only bool
}

func mustParseNet(n string) *net.IPNet {
	_, parsedNet, err := net.ParseCIDR(n)
	if err != nil {
		panic(err)
	}
	return parsedNet
}

// RFC 3879, Deprecating Site Local Addresses
var siteLocalIPv6 = mustParseNet("FEC0::/10")

func isIPv4MappedIPv6(ip net.IP) bool {
	// TODO: detect IPv4-mapped IPv6 addresses
	return false
}

func validGatherAddr(a gather.Addr, ipv6Only bool) bool {
	ip := a.IP
	v6 := ip.To4() == nil
	if !v6 && ipv6Only {
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
	if isIPv4MappedIPv6(ip) && !ipv6Only {
		// IPv4-mapped IPv6 addresses SHOULD NOT be included in the address
		// candidates unless the application using ICE does not support IPv4
		// (i.e., it is an IPv6-only application [RFC4038]).
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

// Candidates returns all host candidates. All returned candidates represents
// each available transport IP, so Port is zero and Transport defaults to UDP.
func (g HostCandidateGatherer) Candidates() ([]Candidate, error) {
	ifaces, err := g.host.Gather()
	if err != nil {
		return nil, err
	}
	var candidates []Candidate
	for _, iface := range ifaces {
		if !validGatherAddr(iface, g.ipv6Only) {
			continue
		}
		addr := Addr{
			IP: iface.IP,
		}
		c := Candidate{
			Addr: addr,
			Base: addr,
			Type: candidate.Host,
		}
		candidates = append(candidates, c)
	}
	return candidates, nil
}
