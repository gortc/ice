package ice

import (
	"testing"
)

func TestGather(t *testing.T) {
	_, err := Gather()
	if err != nil {
		t.Fatal(err)
	}
}

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
