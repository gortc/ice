package ice

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
	Local    Candidate
	Remote   Candidate
	Priority int64
	State    PairState
}

// PairState as defined in RFC 8445 Section 6.1.2.6.
type PairState byte

var pairStateToStr = map[PairState]string{
	PairWaiting:    "Waiting",
	PairInProgress: "In-Progress",
	PairSucceeded:  "Succeeded",
	PairFailed:     "Failed",
	PairFrozen:     "Frozen",
}

func (s PairState) String() string { return pairStateToStr[s] }

const (
	// PairFrozen: A check for this pair has not been sent, and it cannot be
	// sent until the pair is unfrozen and moved into the Waiting state.
	PairFrozen PairState = iota
	// PairInProgress: A check has been sent for this pair, but the
	// transaction is in progress.
	PairInProgress
	// PairSucceeded: A check has been sent for this pair, and it produced a
	// successful result.
	PairSucceeded
	// PairFailed: A check has been sent for this pair, and it failed (a
	// response to the check was never received, or a failure response was
	// received).
	PairFailed
	// PairWaiting: A check has not been sent for this pair, but the pair is
	// not Frozen.
	PairWaiting
)

// Foundation is combination of candidates foundations.
func (p Pair) Foundation() []byte {
	f := make([]byte, foundationLength*2)
	copy(f[:foundationLength], p.Local.Foundation)
	copy(f[foundationLength:], p.Remote.Foundation)
	return f
}

// Pairs is ordered slice of Pair elements.
type Pairs []Pair

func (p Pairs) Len() int           { return len(p) }
func (p Pairs) Less(i, j int) bool { return p[i].Priority > p[j].Priority }
func (p Pairs) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
