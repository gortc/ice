// Package ice implements RFC 5245
// Interactive Connectivity Establishment (ICE):
// A Protocol for Network Address Translator (NAT)
// Traversal for Offer/Answer Protocols.
package ice

import (
	"bytes"
	"fmt"
	"net"
	"strconv"

	"github.com/pkg/errors"
)

// AddressType is type for ConnectionAddress.
type AddressType byte

// Possible address types.
const (
	AddressIPv4 AddressType = iota
	AddressIPv6
	AddressFQDN
)

func (a AddressType) String() string {
	switch a {
	case AddressIPv4:
		return "IPv4"
	case AddressIPv6:
		return "IPv6"
	case AddressFQDN:
		return "FQDN"
	default:
		panic("unexpected address type")
	}
}

// ConnectionAddress represents address that can be ipv4/6 or FQDN.
type ConnectionAddress struct {
	Host []byte
	IP   net.IP
	Type AddressType
}

func (a ConnectionAddress) Equal(b ConnectionAddress) bool {
	if a.Type != b.Type {
		return false
	}
	switch a.Type {
	case AddressFQDN:
		return bytes.Equal(a.Host, b.Host)
	default:
		return a.IP.Equal(b.IP)
	}
}

func (a ConnectionAddress) str() string {
	switch a.Type {
	case AddressFQDN:
		return string(a.Host)
	default:
		return a.IP.String()
	}
}

func (a ConnectionAddress) String() string {
	return fmt.Sprintf("%s(%s)", a.str(), a.Type)
}

// CandidateType encodes the type of candidate. This specification
// defines the values "host", "srflx", "prflx", and "relay" for host,
// server reflexive, peer reflexive, and relayed candidates,
// respectively. The set of candidate types is extensible for the
// future.
type CandidateType byte

// Set of candidate types.
const (
	CandidateUnknown         CandidateType = iota
	CandidateHost                          // "host"
	CandidateServerReflexive               // "srflx"
	CandidatePeerReflexive                 // "prflx"
	CandidateRelay                         // "relay"
)

func (c CandidateType) String() string {
	switch c {
	case CandidateHost:
		return "host"
	case CandidateServerReflexive:
		return "server-reflexive"
	case CandidatePeerReflexive:
		return "peer-reflexive"
	case CandidateRelay:
		return "relay"
	default:
		return "unknown"
	}
}

const (
	candidateHost            = "host"
	candidateServerReflexive = "srflx"
	candidatePeerReflexive   = "prflx"
	candidateRelay           = "relay"
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
	Transport         TransportType
	TransportValue    []byte
	Foundation        int
	ComponentID       int
	Priority          int
	Type              CandidateType
	RelatedAddress    ConnectionAddress
	RelatedPort       int

	// Extended attributes
	NetworkCost int
	Generation  int

	// Other attributes
	Attributes Attributes
}

func (c Candidate) Equal(b *Candidate) bool {
	if !c.ConnectionAddress.Equal(b.ConnectionAddress) {
		return false
	}
	if c.Port != b.Port {
		return false
	}
	if c.Transport != b.Transport {
		return false
	}
	if !bytes.Equal(c.TransportValue, b.TransportValue) {
		return false
	}
	if c.Foundation != b.Foundation {
		return false
	}
	if c.ComponentID != b.ComponentID {
		return false
	}
	if c.Priority != b.Priority {
		return false
	}
	if c.Type != b.Type {
		return false
	}
	if c.NetworkCost != b.NetworkCost {
		return false
	}
	if c.Generation != b.Generation {
		return false
	}

	return true
}

type Attribute struct {
	Key   []byte
	Value []byte
}

type Attributes []Attribute

func (a Attributes) Value(k []byte) []byte {
	for _, attribute := range a {
		if bytes.Equal(attribute.Key, k) {
			return attribute.Value
		}
	}
	return nil
}

func (a Attribute) String() string {
	return fmt.Sprintf("%s:%s", a.Key, a.Value)
}

type TransportType byte

const (
	TransportUDP TransportType = iota
	TransportUnknown
)

func (t TransportType) String() string {
	switch t {
	case TransportUDP:
		return "UDP"
	default:
		return "Unknown"
	}
}

func (c *Candidate) Scan(b []byte) error {
	return nil
}

// candidateParser should parse []byte into Candidate.
//
// a=candidate:3862931549 1 udp 2113937151 192.168.220.128 56032 typ host generation 0 network-cost 50
//     foundation ---┘    |  |      |            |          |
//   component id --------┘  |      |            |          |
//      transport -----------┘      |            |          |
//       priority ------------------┘            |          |
//  conn. address -------------------------------┘          |
//           port ------------------------------------------┘
type candidateParser struct {
	buf []byte
	c   Candidate
}

const sp = ' '

var (
	spSlice = []byte{sp}
)

const (
	mandatoryElems = 6
)

func parseInt(v []byte) (int, error) {
	i, err := strconv.ParseInt(string(v), 10, 0)
	return int(i), err
}

func (p *candidateParser) parseFoundation(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return errors.Wrap(err, "failed to parse foundation")
	}
	p.c.Foundation = i
	return nil
}

func (p *candidateParser) parseComponentID(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return errors.Wrap(err, "failed to parse component ID")
	}
	p.c.ComponentID = i
	return nil
}

func (p *candidateParser) parsePriority(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return errors.Wrap(err, "failed to parse priority")
	}
	p.c.Priority = i
	return nil
}

func (p *candidateParser) parsePort(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return errors.Wrap(err, "failed to parse port")
	}
	p.c.Port = i
	return nil
}

func (p *candidateParser) parseRelatedPort(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return errors.Wrap(err, "failed to parse port")
	}
	p.c.RelatedPort = i
	return nil
}

func (candidateParser) parseAddress(v []byte, target *ConnectionAddress) error {
	ip := net.ParseIP(string(v))
	if ip == nil {
		target.Host = v
		target.IP = nil
		target.Type = AddressFQDN
		return nil
	}
	target.IP = ip
	target.Type = AddressIPv6
	if target.IP.To4() != nil {
		target.Type = AddressIPv4
	}
	return nil
}

func (p *candidateParser) parseConnectionAddress(v []byte) error {
	return p.parseAddress(v, &p.c.ConnectionAddress)
}

func (p *candidateParser) parseRelatedAddress(v []byte) error {
	return p.parseAddress(v, &p.c.RelatedAddress)
}

func (p *candidateParser) parseTransport(v []byte) error {
	if bytes.Equal(bytes.ToLower(v), []byte("udp")) {
		p.c.Transport = TransportUDP
	} else {
		p.c.Transport = TransportUnknown
		p.c.TransportValue = v
	}
	return nil
}

func (p *candidateParser) parse() error {
	// TODO: refactor and optimize
	if len(p.buf) < 10 {
		return errors.New("buffer too small")
	}
	// special cases for raw value support:
	if p.buf[0] == 'a' {
		p.buf = bytes.TrimPrefix(p.buf, []byte("a="))
	}
	if p.buf[0] == 'c' {
		p.buf = bytes.TrimPrefix(p.buf, []byte("candidate:"))
	}
	elems := bytes.Split(p.buf, spSlice)
	if len(elems) < mandatoryElems {
		return errors.Errorf("too few (%d<%d) elements in candidate",
			len(elems), mandatoryElems,
		)
	}
	if err := p.parseFoundation(elems[0]); err != nil {
		return err
	}
	if err := p.parseComponentID(elems[1]); err != nil {
		return err
	}
	if err := p.parseTransport(elems[2]); err != nil {
		return err
	}
	if err := p.parsePriority(elems[3]); err != nil {
		return err
	}
	if err := p.parseConnectionAddress(elems[4]); err != nil {
		return err
	}
	if err := p.parsePort(elems[5]); err != nil {
		return err
	}
	if len(elems) == mandatoryElems {
		return nil
	}
	var name []byte = nil
	for _, v := range elems[mandatoryElems:] {
		if name == nil {
			name = v
			continue
		}
		attribute := Attribute{
			Key:   name,
			Value: v,
		}
		// add attributes processing here:
		switch string(attribute.Key) {
		case "generation":
			if err := p.parseGeneration(v); err != nil {
				return err
			}
		case "network-cost":
			if err := p.parseNetworkCost(v); err != nil {
				return err
			}
		case "typ":
			if err := p.parseType(v); err != nil {
				return err
			}
		case "raddr":
			if err := p.parseRelatedAddress(v); err != nil {
				return err
			}
		case "rport":
			if err := p.parseRelatedPort(v); err != nil {
				return err
			}
		default:
			// append unknown attribute
			p.c.Attributes = append(p.c.Attributes, attribute)
		}
		name = nil
	}
	return nil
}

func (p *candidateParser) parseNetworkCost(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return errors.Wrap(err, "failed to parse network cost")
	}
	p.c.NetworkCost = i
	return nil
}

func (p *candidateParser) parseGeneration(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return errors.Wrap(err, "failed to parse generation")
	}
	p.c.Generation = i
	return nil
}

func (p *candidateParser) parseType(v []byte) error {
	switch string(v) {
	case candidateHost:
		p.c.Type = CandidateHost
	case candidatePeerReflexive:
		p.c.Type = CandidatePeerReflexive
	case candidateRelay:
		p.c.Type = CandidateRelay
	case candidateServerReflexive:
		p.c.Type = CandidateServerReflexive
	default:
		return errors.Errorf("unknown candidate %q", v)
	}
	return nil
}
