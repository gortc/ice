package gather

import (
	"net"
	"testing"
)

func TestAddr_String(t *testing.T) {
	for _, tt := range []struct {
		in  Addr
		out string
	}{
		{in: Addr{}, out: "<nil> [0]"},
		{in: Addr{Zone: "z"}, out: "<nil> (zone z) [0]"},
	} {
		t.Run(tt.out, func(t *testing.T) {
			if tt.in.String() != tt.out {
				t.Errorf("%q", tt.in)
			}
		})
	}
}

func TestAddr_ZeroPortAddr(t *testing.T) {
	for _, tt := range []struct {
		in  Addr
		out string
	}{
		{in: Addr{}, out: "<nil>:0"},
		{in: Addr{Zone: "z"}, out: "<nil>%z:0"},
		{in: Addr{Zone: "z", IP: net.IPv4(127, 0, 0, 1)}, out: "127.0.0.1%z:0"},
	} {
		t.Run(tt.out, func(t *testing.T) {
			if tt.in.ZeroPortAddr() != tt.out {
				t.Errorf("%q", tt.in.ZeroPortAddr())
			}
		})
	}
}
