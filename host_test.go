package ice

import (
	"net"
	"testing"

	"github.com/gortc/ice/gather"
)

func TestGatherHostAddresses(t *testing.T) {
	type outputRow struct {
		IP         string
		Preference int
	}
	for _, tc := range []struct {
		Name   string
		Input  []string
		Output []outputRow
	}{
		{
			Name: "blank",
		},
		{
			Name: "loopback",
			Input: []string{
				"127.0.0.1",
			},
		},
		{
			Name: "IPv4",
			Input: []string{
				"1.1.1.1",
				"1.1.1.2",
			},
			Output: []outputRow{
				{"1.1.1.1", 2},
				{"1.1.1.2", 1},
			},
		},
		{
			Name: "IPv6",
			Input: []string{
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa1",
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa2",
			},
			Output: []outputRow{
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa1", 2},
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa2", 1},
			},
		},
		{
			// If a host has two IPv4 addresses and six IPv6 addresses, it will
			// insert an IPv4 address after four IPv6 addresses by choosing the
			// appropriate local preference values when calculating the pair
			// priorities.
			Name: "2xIPv4 and 6xIPv6",
			Input: []string{
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa1",
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa2",
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa3",
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa4",
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa5",
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa6",
				"1.1.1.1",
				"1.1.1.2",
			},
			Output: []outputRow{
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa1", 8},
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa2", 7},
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa3", 6},
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa4", 5},
				{"1.1.1.1", 4},
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa5", 3},
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa6", 2},
				{"1.1.1.2", 1},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			gatherAddrs := make([]gather.Addr, len(tc.Input))
			for i, ip := range tc.Input {
				gatherAddrs[i] = gather.Addr{
					IP: net.ParseIP(ip),
				}
			}
			expecteds := make([]HostAddr, len(tc.Output))
			for i, row := range tc.Output {
				expecteds[i] = HostAddr{
					IP:              net.ParseIP(row.IP),
					LocalPreference: row.Preference,
				}
			}
			gotAddr, err := HostAddresses(gatherAddrs)
			if err != nil {
				t.Fatal(err)
			}
			if len(gotAddr) != len(expecteds) {
				t.Fatalf("bad length: %d (got) != %d (expected)",
					len(gotAddr), len(expecteds),
				)
			}
			for i := range gotAddr {
				got := gotAddr[i]
				exp := expecteds[i]
				if got.LocalPreference != exp.LocalPreference || !got.IP.Equal(exp.IP) {
					t.Errorf("[%d]: %s, %d (got) != %s, %d (expected)",
						i, got.IP, got.LocalPreference, exp.IP, exp.LocalPreference,
					)
				}
			}
		})
	}
}

func TestIsValidHostIP(t *testing.T) {
	for _, tc := range []struct {
		Name  string
		IP    net.IP
		V6    bool
		Valid bool
	}{
		{
			Name: "blank",
		},
		{
			Name: "127.0.0.1",
			IP:   localIP,
		},
		{
			Name:  "v4",
			IP:    net.IPv4(10, 0, 0, 1),
			Valid: true,
		},
		{
			Name: "v4 for v6 only",
			IP:   net.IPv4(10, 0, 0, 1),
			V6:   true,
		},
		{
			Name: "Site-local ipv6",
			IP:   net.ParseIP("FEC0::ff:aa"),
			V6:   true,
		},
		{
			Name: "link-local ipv6",
			IP:   net.ParseIP("fe80::50da:9baa:ef96:15c8"),
		},
		{
			Name:  "ipv4-mapped",
			IP:    net.IPv4(10, 0, 0, 1).To16(),
			Valid: true,
		},
		{
			Name: "ipv4-mapped for v6 only",
			IP:   net.IPv4(10, 0, 0, 1).To16(),
			V6:   true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			if v := IsHostIPValid(tc.IP, tc.V6); v != tc.Valid {
				t.Errorf("valid(%s, v6=%v) %v (got) != %v (expected)",
					tc.IP, tc.V6, v, tc.Valid,
				)
			}
		})
	}
}
