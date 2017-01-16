// Package ice implements RFC 5245
// Interactive Connectivity Establishment (ICE):
// A Protocol for Network Address Translator (NAT)
// Traversal for Offer/Answer Protocols.
package ice

import "net"

// AddressType is type for ConnectionAddress.
type AddressType byte

// Possible address types.
const (
	AddressIPv4 AddressType = iota
	AddressIPv6
	AddressFQDN
)

// ConnectionAddress represents address that can be ipv4/6 or FQDN.
type ConnectionAddress struct {
	Host string
	IP   net.IP
	Type AddressType
}

func (a ConnectionAddress) String() string {
	switch a.Type {
	case AddressFQDN:
		return a.Host
	default:
		return a.IP.String()
	}
}

// CandidateType encodes the type of candidate. This specification
// defines the values "host", "srflx", "prflx", and "relay" for host,
// server reflexive, peer reflexive, and relayed candidates,
// respectively. The set of candidate types is extensible for the
// future.
type CandidateType byte

// Set of candidate types.
const (
	CandidateHost CandidateType = iota
	CandidateServerReflexive
	CandidatePeerReflexive
	CandidateRelay
)

// Candidate is ICE candidate defined in RFC 5245 Section 21.1.1.
//
// This attribute is used with Interactive Connectivity
// Establishment (ICE), and provides one of many possible candidate
// addresses for communication. These addresses are validated with
// an end-to-end connectivity check using Session Traversal Utilities
// for NAT (STUN)).
//
// The candidate attribute can itself be extended. The grammar allows
// for new name/value pairs to be added at the end of the attribute. An
// implementation MUST ignore any name/value pairs it doesn't
// understand.
type Candidate struct {
	ConnectionAddress ConnectionAddress
	Port              int
	Transport         string
	Foundation        string
	ComponentID       int
	Priority          int
	Type              CandidateType
	RelatedAddress    ConnectionAddress
	RelatedPort       int
}

func (c *Candidate) Scan(b []byte) error {
	return nil
}
