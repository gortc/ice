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
		{Priority: 0, ComponentID: 2},
		{Priority: 0, ComponentID: 1},
		{Priority: 4},
		{Priority: 5},
		{Priority: 9},
		{Priority: 8},
	}
	sort.Sort(pairs)
	expectedOrder := []struct {
		priority  int64
		component int
	}{
		{100, 0},
		{9, 0},
		{8, 0},
		{5, 0},
		{4, 0},
		{4, 0},
		{3, 0},
		{0, 1},
		{0, 2},
	}
	for i, p := range pairs {
		if p.Priority != expectedOrder[i].priority {
			t.Errorf("p[%d]: %d (got) != %d (expected)", i, p.Priority, expectedOrder[i])
		}
		if p.ComponentID != expectedOrder[i].component {
			t.Errorf("p[%d] component: %d (got) != %d (expected)", i, p.Priority, expectedOrder[i])
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
						IP: net.ParseIP("1.1.1.2"),
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
							IP: net.ParseIP("1.1.1.2"),
						},
					},
				},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			got := NewPairs(tc.Local, tc.Remote)
			if len(got) != len(tc.Result) {
				t.Fatalf("bad length: %d (got) != %d (expected)", len(got), len(tc.Result))
			}
			for i := range tc.Result {
				expectedAddr := tc.Result[i].Remote.Addr
				gotAddr := got[i].Remote.Addr
				if !gotAddr.Equal(expectedAddr) {
					t.Errorf("[%d]: remote addr mismatch: %s (got) != %s (expected)", i, gotAddr, expectedAddr)
				}
				expectedAddr = tc.Result[i].Local.Addr
				gotAddr = got[i].Local.Addr
				if !gotAddr.Equal(expectedAddr) {
					t.Errorf("[%d]: local addr mismatch: %s (got) != %s (expected)", i, gotAddr, expectedAddr)
				}
			}
		})
	}
}
