package ice

import (
	"net"

	ct "gortc.io/ice/candidate"
	"gortc.io/ice/gather"
)

// Gather via DefaultGatherer.
func Gather() ([]gather.Addr, error) {
	return gather.DefaultGatherer.Gather()
}

type systemCandidateGatherer struct {
	addr gather.Gatherer
}

func (g systemCandidateGatherer) gatherUDP(opt gathererOptions) ([]*localUDPCandidate, error) {
	addrs, err := g.addr.Gather()
	if err != nil {
		// Failed to gather host addresses.
		return nil, err
	}
	hostAddr, err := HostAddresses(addrs)
	if err != nil {
		return nil, err
	}
	var candidates []*localUDPCandidate
	for component := 1; component <= opt.Components; component++ {
		for _, addr := range hostAddr {
			if opt.IPv4Only && addr.IP.To4() == nil {
				continue
			}
			zeroPort := net.UDPAddr{
				IP:   addr.IP,
				Port: 0,
			}
			l, err := net.ListenPacket("udp", zeroPort.String())
			if err != nil {
				return nil, err
			}
			a := l.LocalAddr().(*net.UDPAddr)
			c := Candidate{
				Base: Addr{
					IP:    addr.IP,
					Port:  a.Port,
					Proto: ct.UDP,
				},
				Type: ct.Host,
				Addr: Addr{
					IP:    addr.IP,
					Port:  a.Port,
					Proto: ct.UDP,
				},
				ComponentID:     component,
				LocalPreference: addr.LocalPreference,
			}
			c.Foundation = Foundation(&c, Addr{})
			c.Priority = Priority(TypePreference(c.Type), addr.LocalPreference, c.ComponentID)
			candidates = append(candidates, &localUDPCandidate{
				candidate: c,
				conn:      l,
			})
		}
	}
	return candidates, nil
}
