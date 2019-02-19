package ice

import (
	"bytes"
	"net"
	"sort"
	"testing"

	"github.com/gortc/ice/candidate"
)

var localIP = net.IPv4(127, 0, 0, 1)

func TestFoundation(t *testing.T) {
	for _, tc := range []struct {
		Name         string
		A, B         *Candidate
		AddrA, AddrB Addr
		Equal        bool
	}{
		{
			Name:  "nil",
			Equal: true,
		},
		{
			Name: "simple",
			A: &Candidate{
				Addr: Addr{
					IP:    localIP,
					Port:  1,
					Proto: candidate.UDP,
				},
				Base: Addr{
					IP:    localIP,
					Port:  10,
					Proto: candidate.UDP,
				},
			},
			B: &Candidate{
				Addr: Addr{
					IP:    localIP,
					Port:  1,
					Proto: candidate.UDP,
				},
				Base: Addr{
					IP:    localIP,
					Port:  10,
					Proto: candidate.UDP,
				},
			},
			Equal: true,
		},
		{
			Name: "different turn",
			A: &Candidate{
				Addr: Addr{
					IP:    localIP,
					Port:  1,
					Proto: candidate.UDP,
				},
				Base: Addr{
					IP:    localIP,
					Port:  10,
					Proto: candidate.UDP,
				},
			},
			AddrA: Addr{
				IP: localIP,
			},
			B: &Candidate{
				Addr: Addr{
					IP:    localIP,
					Port:  1,
					Proto: candidate.UDP,
				},
				Base: Addr{
					IP:    localIP,
					Port:  10,
					Proto: candidate.UDP,
				},
			},
			Equal: false,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			a := Foundation(tc.A, tc.AddrA)
			b := Foundation(tc.B, tc.AddrB)
			t.Logf("a: 0x%x", a)
			t.Logf("b: 0x%x", b)
			if bytes.Equal(a, b) != tc.Equal {
				t.Error("mismatch")
			}
		})
	}
}

func TestPriority(t *testing.T) {
	for _, tc := range []struct {
		Name  string
		Type  int
		Local int
		ID    int
		Value int
	}{
		{
			Name:  "host",
			Type:  126,
			Value: 2113929472,
		},
		{
			Name:  "full",
			Type:  TypePreference(candidate.PeerReflexive),
			Local: 50,
			ID:    2,
			Value: 1845506814,
		},
		{
			Name:  "relayed",
			Type:  TypePreference(candidate.Relayed),
			Local: 10,
			ID:    5,
			Value: 2811,
		},
		{
			Name:  "server reflexive",
			Type:  TypePreference(candidate.ServerReflexive),
			Local: 3,
			ID:    1,
			Value: 1677722623,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			if v := Priority(tc.Type, tc.Local, tc.ID); v != tc.Value {
				t.Errorf("p(%d, %d, %d) %d (got) != %d (expected)",
					tc.Type, tc.Local, tc.ID, v, tc.Value,
				)
			}
		})
	}
}

func TestAddr_String(t *testing.T) {
	for _, tc := range []struct {
		Addr   Addr
		String string
	}{
		{
			String: "<nil>:0/UDP",
		},
		{
			String: "1.1.1.1:10/UDP",
			Addr: Addr{
				IP:   net.IPv4(1, 1, 1, 1),
				Port: 10,
			},
		},
	} {
		if v := tc.Addr.String(); v != tc.String {
			t.Errorf("string(%+v): %s (got) != %s (expected)",
				tc.Addr, v, tc.String,
			)
		}
	}
}

func TestAddr_Equal(t *testing.T) {
	for _, tc := range []struct {
		Name  string
		A, B  Addr
		Equal bool
	}{
		{
			Name:  "zero",
			Equal: true,
		},
		{
			Name: "proto",
			A: Addr{
				Proto: 200,
			},
		},
		{
			Name: "port",
			A: Addr{
				Port: 1,
			},
		},
		{
			Name: "ip",
			A: Addr{
				IP: net.IPv4(1, 1, 1, 1),
			},
		},
	} {
		if v := tc.A.Equal(tc.B); v != tc.Equal {
			t.Errorf("equal(%s, %s): %v (got) != %v (expected)",
				tc.A, tc.B, v, tc.Equal,
			)
		}
	}
}

func TestCandidate_Equal(t *testing.T) {
	for _, tc := range []struct {
		Name  string
		A, B  Candidate
		Equal bool
	}{
		{
			Name:  "blank",
			Equal: true,
		},
		{
			Name: "type",
			B: Candidate{
				Type: candidate.PeerReflexive,
			},
			Equal: false,
		},
		{
			Name: "priority",
			B: Candidate{
				Priority: 1000,
			},
			Equal: false,
		},
		{
			Name: "addr",
			B: Candidate{
				Addr: Addr{
					IP: net.IPv4(127, 0, 0, 1),
				},
			},
			Equal: false,
		},
		{
			Name: "foundation",
			A: Candidate{
				Foundation: []byte{2},
			},
			B: Candidate{
				Foundation: []byte{1},
			},
			Equal: false,
		},
		{
			Name: "base",
			B: Candidate{
				Base: Addr{
					IP: net.IPv4(127, 0, 0, 1),
				},
			},
			Equal: false,
		},
		{
			Name: "related",
			B: Candidate{
				Related: Addr{
					IP: net.IPv4(127, 0, 0, 1),
				},
			},
			Equal: false,
		},
		{
			Name: "componentID",
			B: Candidate{
				ComponentID: 10,
			},
			Equal: false,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			if v := tc.A.Equal(&tc.B); v != tc.Equal {
				t.Error("not equal")
			}
		})
	}
}

func TestCandidatesSort(t *testing.T) {
	candidates := Candidates{
		{Priority: 1}, {Priority: 3}, {Priority: 2},
	}
	sort.Sort(candidates)
	for i, p := range []int{3, 2, 1} {
		if candidates[i].Priority != p {
			t.Errorf("p[%d] %d (got) != %d (expected)", i,
				candidates[i].Priority, p,
			)
		}
	}
}
