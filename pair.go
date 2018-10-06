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
}

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
func (p Pairs) Less(i, j int) bool { return p[i].Priority < p[j].Priority }
func (p Pairs) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
