package ice

import (
	"bytes"
	"net"
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
