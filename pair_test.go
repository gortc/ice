package ice

import (
	"fmt"
	"sort"
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

func TestPairs(t *testing.T) {
	pairs := Pairs{
		{Priority: 4},
		{Priority: 3},
		{Priority: 100},
		{Priority: 0},
		{Priority: 4},
		{Priority: 5},
		{Priority: 9},
		{Priority: 8},
	}
	sort.Sort(pairs)
	expectedOrder := []int64{
		100, 9, 8, 5, 4, 4, 3, 0,
	}
	for i, p := range pairs {
		if p.Priority != expectedOrder[i] {
			t.Errorf("p[%d]: %d (got) != %d (expected)", i, p.Priority, expectedOrder[i])
		}
	}
}
