package ice

import (
	"bytes"
	"fmt"
	"net"
)

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// PairPriority computes Pair Priority as in RFC 8445 Section 6.1.2.3.
func PairPriority(controlling, controlled int) int64 {
	var (
		g = int64(controlling)
		d = int64(controlled)
	)
	// pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
	v := (1<<32)*min(g, d) + 2*max(g, d)
	if g > d {
		v++
	}
	return v
}

// Pair wraps two candidates, one is local, other is remote.
type Pair struct {
	Local      Candidate `json:"local"`
	Remote     Candidate `json:"remote"`
	Priority   int64     `json:"priority"`
	Foundation []byte    `json:"foundation"`
	State      PairState `json:"state"`
	Nominated  bool      `json:"nominated"`
}

// Equal returns true if pair p equals to pair b.
func (p *Pair) Equal(b *Pair) bool {
	if p.State != b.State {
		return false
	}
	if p.Priority != b.Priority {
		return false
	}
	if !p.Local.Equal(&b.Local) {
		return false
	}
	if !p.Remote.Equal(&b.Remote) {
		return false
	}
	if !bytes.Equal(p.Foundation, b.Foundation) {
		return false
	}
	return true
}

// PairState as defined in RFC 8445 Section 6.1.2.6.
type PairState byte

// In returns true if s in states list.
func (s PairState) In(states ...PairState) bool {
	for _, st := range states {
		if st == s {
			return true
		}
	}
	return false
}

// UnmarshalText implements TextUnmarshaler.
func (s *PairState) UnmarshalText(text []byte) error {
	for k, v := range pairStateToStr {
		if string(text) == v {
			*s = k
			return nil
		}
	}
	return fmt.Errorf("unknown pair state value %q", text)
}

// MarshalText implements TextMarshaler.
func (s PairState) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

var pairStateToStr = map[PairState]string{
	PairWaiting:    "Waiting",
	PairInProgress: "In-Progress",
	PairSucceeded:  "Succeeded",
	PairFailed:     "Failed",
	PairFrozen:     "Frozen",
}

func (s PairState) String() string { return pairStateToStr[s] }

const (
	// PairFrozen state: A check for this pair has not been sent, and it cannot
	// be sent until the pair is unfrozen and moved into the Waiting state.
	PairFrozen PairState = iota
	// PairInProgress state: A check has been sent for this pair, but the
	// transaction is in progress.
	PairInProgress
	// PairSucceeded state: A check has been sent for this pair, and it produced
	// a successful result.
	PairSucceeded
	// PairFailed state: A check has been sent for this pair, and it failed (a
	// response to the check was never received, or a failure response was
	// received).
	PairFailed
	// PairWaiting state: A check has not been sent for this pair, but the pair
	// is not Frozen.
	PairWaiting
)

// SetFoundation sets foundation, the combination of candidates foundations.
func (p *Pair) SetFoundation() {
	f := make([]byte, foundationLength*2)
	copy(f[:foundationLength], p.Local.Foundation)
	copy(f[foundationLength:], p.Remote.Foundation)
	p.Foundation = f
}

// Pairs is ordered slice of Pair elements.
type Pairs []Pair

func (p Pairs) Len() int           { return len(p) }
func (p Pairs) Less(i, j int) bool { return p[i].Priority > p[j].Priority }
func (p Pairs) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func sameFamily(a, b net.IP) bool {
	return len(a.To4()) == len(b.To4())
}

// NewPairs pairs each local candidate with each remote candidate for the same
// component of the same data stream with the same IP address family. Candidates
// should be sorted by priority in descending order, which is default order for
// the Candidates type. Populates only Local and Remote fields of Pair.
//
// See RFC 8445 Section 6.1.2.2.
func NewPairs(local, remote Candidates) Pairs {
	p := make(Pairs, 0, 100)
	for l := range local {
		for r := range remote {
			// Same data stream.
			if local[l].ComponentID != remote[r].ComponentID {
				continue
			}
			ipL, ipR := local[l].Addr.IP, remote[r].Addr.IP
			// Same IP address family.
			if !sameFamily(ipL, ipR) {
				continue
			}
			if ipL.To4() == nil && ipL.IsLinkLocalUnicast() {
				// IPv6 link-local addresses MUST NOT be paired with other
				// than link-local addresses.
				if !ipR.IsLinkLocalUnicast() {
					continue
				}
			}
			pair := Pair{
				Local:  local[l],
				Remote: local[r],
			}
			pair.SetFoundation()
			p = append(p, pair)
		}
	}
	return p
}
