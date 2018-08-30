package ice

import (
	"bytes"
	"crypto/sha256"
	"net"

	ct "github.com/gortc/ice/candidate"
)

// Addr represents transport address, the combination of an IP address
// and the transport protocol (such as UDP or TCP) port.
type Addr struct {
	IP    net.IP
	Port  int
	Proto ct.Protocol
}

// The Candidate is a transport address that is a potential point of contact
// for receipt of data. Candidates also have properties — their type
// (server reflexive, relayed, or host), priority, foundation, and base.
type Candidate struct {
	Addr       Addr
	Type       ct.Type
	Priority   int
	Foundation []byte
	Base       Addr
	Related    Addr
}

const foundationLength = 8

// Foundation computes foundation value for candidate. The serverAddr parameter
// is for STUN or TURN server address, zero value is valid. Will return nil if
// candidate is nil.
//
// Value is an arbitrary string used in the freezing algorithm to
// group similar candidates. It is the same for two candidates that
// have the same type, base IP address, protocol (UDP, TCP, etc.),
// and STUN or TURN server. If any of these are different, then the
// foundation will be different.
func Foundation(c *Candidate, serverAddr Addr) []byte {
	if c == nil {
		return nil
	}
	h := sha256.New()
	values := [][]byte{
		{byte(c.Type)},
		c.Base.IP,
		{byte(c.Addr.Proto)},
	}
	if len(serverAddr.IP) > 0 {
		values = append(values,
			serverAddr.IP,
			[]byte{byte(serverAddr.Proto)},
		)
	}
	h.Write(bytes.Join(values, []byte{':'})) // #nosec
	return h.Sum(nil)[:foundationLength]
}
