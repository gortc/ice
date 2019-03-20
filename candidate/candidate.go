// Package candidate contains common types for ice candidate.
package candidate

import "fmt"

// Type encodes the type of candidate. This specification
// defines the values "host", "srflx", "prflx", and "relay" for host,
// server reflexive, peer reflexive, and relayed candidates,
// respectively. The set of candidate types is extensible for the
// future.
type Type byte

// UnmarshalText implements TextUnmarshaler.
func (t *Type) UnmarshalText(text []byte) error {
	for k, v := range candidateTypeToStr {
		if string(text) == v {
			*t = k
			return nil
		}
	}
	return fmt.Errorf("unknown candidate type value: %q", text)
}

// MarshalText implements TextMarshaler.
func (t Type) MarshalText() (text []byte, err error) {
	return []byte(candidateTypeToStr[t]), nil
}

// Set of possible candidate types.
const (
	// Host is a candidate obtained by binding to a specific port
	// from an IP address on the host.  This includes IP addresses on
	// physical interfaces and logical ones, such as ones obtained
	// through VPNs.
	Host Type = iota
	// ServerReflexive is a candidate whose IP address and port
	// are a binding allocated by a NAT for an ICE agent after it sends a
	// packet through the NAT to a server, such as a STUN server.
	ServerReflexive
	// PeerReflexive is a candidate whose IP address and port are
	// a binding allocated by a NAT for an ICE agent after it sends a
	// packet through the NAT to its peer.
	PeerReflexive
	// Relayed is a candidate obtained from a relay server, such as
	// a TURN server.
	Relayed
)

var candidateTypeToStr = map[Type]string{
	Host:            "Host",
	ServerReflexive: "Server-reflexive",
	PeerReflexive:   "Peer-reflexive",
	Relayed:         "Relayed",
}

func strOrUnknown(str string) string {
	if str == "" {
		return "Unknown"
	}
	return str
}

func (t Type) String() string {
	return strOrUnknown(candidateTypeToStr[t])
}

// Protocol is protocol for address.
type Protocol byte

// UnmarshalText implements TextUnmarshaler.
func (t *Protocol) UnmarshalText(s []byte) error {
	switch string(s) {
	case "udp", "UDP":
		*t = UDP
	default:
		*t = ProtocolUnknown
	}
	return nil
}

// MarshalText implements TextMarshaler.
func (t Protocol) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// Supported protocols.
const (
	UDP Protocol = iota
	ProtocolUnknown
)

func (t Protocol) String() string {
	switch t {
	case UDP:
		return "UDP"
	default:
		return "Unknown"
	}
}
