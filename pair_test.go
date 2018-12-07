package ice

import (
	"fmt"
	"net"
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
	p.SetFoundation()
	f := p.Foundation
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

func TestNewPairs(t *testing.T) {
	for _, tc := range []struct {
		Name   string
		Local  Candidates
		Remote Candidates
		Result Pairs
	}{
		{
			Name: "Blank",
		},
		{
			Name: "No pairs",
			Local: Candidates{
				{
					Addr: Addr{
						IP: net.ParseIP("1.1.1.1"),
					},
				},
			},
			Remote: Candidates{
				{
					Addr: Addr{
						IP: net.ParseIP("2001:11:12:13:14:15:16:17"),
					},
				},
			},
		},
		{
			Name: "Simple",
			Local: Candidates{
				{
					Addr: Addr{
						IP: net.ParseIP("1.1.1.1"),
					},
				},
			},
			Remote: Candidates{
				{
					Addr: Addr{
						IP: net.ParseIP("1.1.1.1"),
					},
				},
			},
			Result: Pairs{
				{
					Local: Candidate{
						Addr: Addr{
							IP: net.ParseIP("1.1.1.1"),
						},
					},
					Remote: Candidate{
						Addr: Addr{
							IP: net.ParseIP("1.1.1.1"),
						},
					},
				},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			got := NewPairs(tc.Local, tc.Remote)
			if len(got) != len(tc.Result) {
				t.Errorf("bad length: %d (got) != %d (expected)",
					len(got), len(tc.Result),
				)
			}
		})
	}
}
