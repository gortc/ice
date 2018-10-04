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
