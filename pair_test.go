package ice

import (
	"fmt"
	"testing"
)

func TestPairPriority(t *testing.T) {
	for _, tc := range []struct {
		G, D  int
		Value int64
	}{
		{0, 0, 0},
		{1, 1, 4294967298},
		{1, 2, 4294967300},
		{2, 1, 4294967301},
	} {
		t.Run(fmt.Sprintf("%d_%d", tc.G, tc.D), func(t *testing.T) {
			if v := PairPriority(tc.G, tc.D); v != tc.Value {
				t.Errorf("%d (got) != %d (expected)", v, tc.Value)
			}
		})
	}
}

func TestPair_Foundation(t *testing.T) {
	p := Pair{
		Local: Candidate{
			Foundation: make([]byte, foundationLength),
		},
		Remote: Candidate{
			Foundation: make([]byte, foundationLength),
		},
	}
	f := p.Foundation()
	if len(f) != foundationLength*2 {
		t.Error("bad length")
	}
}
