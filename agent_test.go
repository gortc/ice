package ice

import (
	"net"
	"sort"
	"testing"

	"github.com/gortc/ice/candidate"
)

func newUDPCandidate(t *testing.T, addr HostAddr) (Candidate, func()) {
	t.Helper()
	zeroPort := net.UDPAddr{
		IP:   addr.IP,
		Port: 0,
	}
	l, err := net.ListenPacket("udp", zeroPort.String())
	if err != nil {
		t.Fatal(err)
	}
	f := func() {
		if cErr := l.Close(); cErr != nil {
			t.Error(cErr)
		}
	}
	a := l.LocalAddr().(*net.UDPAddr)
	c := Candidate{
		Base: Addr{
			IP:    addr.IP,
			Port:  a.Port,
			Proto: candidate.UDP,
		},
		Type: candidate.Host,
		Addr: Addr{
			IP:    addr.IP,
			Port:  a.Port,
			Proto: candidate.UDP,
		},
		ComponentID: 1,
	}
	c.Foundation = Foundation(&c, Addr{})
	c.Priority = Priority(TypePreference(c.Type),
		addr.LocalPreference, c.ComponentID,
	)
	return c, f
}

func TestAgentAPI(t *testing.T) {
	// 0) Gather interfaces.
	addr, err := Gather()
	if err != nil {
		t.Fatal(err)
	}
	hostAddr, err := HostAddresses(addr)
	if err != nil {
		t.Error(err)
	}
	t.Logf("got host candidates: %d", len(hostAddr))
	for _, a := range hostAddr {
		t.Logf(" %s (%d)", a.IP, a.LocalPreference)
	}
	var toClose []func()
	defer func() {
		for _, f := range toClose {
			f()
		}
	}()
	var local, remote Candidates
	for _, a := range hostAddr {
		l, f := newUDPCandidate(t, a)
		toClose = append(toClose, f)
		local = append(local, l)
		r, fRem := newUDPCandidate(t, a)
		remote = append(remote, r)
		toClose = append(toClose, fRem)
	}
	sort.Sort(local)
	sort.Sort(remote)
	list := new(Checklist)
	list.Pairs = NewPairs(local, remote)
	list.ComputePriorities(Controlling)
	list.Order()
	list.Prune()
	t.Logf("got %d pairs", len(list.Pairs))
	for _, p := range list.Pairs {
		t.Logf("%s -> %s [%x]", p.Local.Addr, p.Remote.Addr, p.Foundation())
	}
}
