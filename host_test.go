package ice

import (
	"net"
	"testing"
)

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
