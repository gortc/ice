package ice

import (
	"net"
	"testing"

	"gortc.io/ice/gather"
)

func TestProcessDualStack(t *testing.T) {
	const maxCount = 100
	tt := make([]struct {
		V4, V6 int
	}, 0, maxCount*maxCount)
	// Not checking v4=0 and v6=0 because that case is invalid for
	// the processDualStack function.
	for v4 := 1; v4 <= maxCount; v4++ {
		for v6 := 1; v6 <= maxCount; v6++ {
			tt = append(tt, struct{ V4, V6 int }{V4: v4, V6: v6})
		}
	}
	for _, tc := range tt {
		var v4, v6, all []gather.Addr
		for i := 0; i < tc.V4; i++ {
			a := gather.Addr{
				IP: make(net.IP, net.IPv4len),
			}
			// "marking" IP so we can count unique ip's.
			bin.PutUint32(a.IP, uint32(i))
			v4 = append(v4, a)
			all = append(all, a)
		}
		for i := 0; i < tc.V6; i++ {
			a := gather.Addr{
				IP: make(net.IP, net.IPv6len),
			}
			bin.PutUint32(a.IP, uint32(i))
			v6 = append(v6, a)
			all = append(all, a)
		}
		// Checking that output length is equal to total length.
		result := processDualStack(all, v4, v6)
		if len(result) != len(all) {
			t.Errorf("v4: %d, v6: %d: expected %d, got %d", tc.V4, tc.V6, len(all), len(result))
		}
		// Checking unique IP count.
		gotV4 := make(map[uint32]bool)
		gotV6 := make(map[uint32]bool)
		for _, r := range result {
			if r.IP.To4() == nil {
				gotV6[bin.Uint32(r.IP)] = true
			} else {
				gotV4[bin.Uint32(r.IP)] = true
			}
		}
		if len(gotV4) != len(v4) {
			t.Errorf("v4: %d, v6: %d: v4 expected %d, got %d", tc.V4, tc.V6, len(v4), len(gotV4))
		}
		if len(gotV6) != len(v6) {
			t.Errorf("v4: %d, v6: %d: v6 expected %d, got %d", tc.V4, tc.V6, len(v6), len(gotV6))
		}
	}
}

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
			Name: "Single IPv4",
			Input: []string{
				"1.1.1.1",
			},
			Output: []outputRow{
				{"1.1.1.1", 65535},
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
			Name: "Single IPv6",
			Input: []string{
				"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa1",
			},
			Output: []outputRow{
				{"2a03:e2c0:60f:52:cfe1:fdd:daf7:7fa1", 65535},
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
			expected := make([]HostAddr, len(tc.Output))
			for i, row := range tc.Output {
				expected[i] = HostAddr{
					IP:              net.ParseIP(row.IP),
					LocalPreference: row.Preference,
				}
			}
			gotAddr, err := HostAddresses(gatherAddrs)
			if err != nil {
				t.Fatal(err)
			}
			if len(gotAddr) != len(expected) {
				t.Fatalf("bad length: %d (got) != %d (expected)",
					len(gotAddr), len(expected),
				)
			}
			for i := range gotAddr {
				got := gotAddr[i]
				exp := expected[i]
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
