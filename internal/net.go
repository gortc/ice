package internal

import "net"

// MustParseNet ensures that n is correctly parsed *net.IPNet.
func MustParseNet(n string) *net.IPNet {
	_, parsedNet, err := net.ParseCIDR(n)
	if err != nil {
		panic(err)
	}
	return parsedNet
}
