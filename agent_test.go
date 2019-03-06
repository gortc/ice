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
	list.Sort()
	list.Prune()
	t.Logf("got %d pairs", len(list.Pairs))
	for _, p := range list.Pairs {
		p.SetFoundation()
		t.Logf("%s -> %s [%x]", p.Local.Addr, p.Remote.Addr, p.Foundation)
	}
	if *writeGolden {
		saveGoldenJSON(t, list, "checklist.json")
	}
}

func TestAgent_updateState(t *testing.T) {
	for _, tc := range []struct {
		Name  string
		State State
		Agent *Agent
	}{
		{
			Name:  "OneCompleted",
			State: Completed,
			Agent: &Agent{
				set: ChecklistSet{
					{State: ChecklistCompleted},
				},
			},
		},
		{
			Name:  "OneFailed",
			State: Failed,
			Agent: &Agent{
				set: ChecklistSet{
					{State: ChecklistFailed},
				},
			},
		},
		{
			Name:  "OneRunning",
			State: Running,
			Agent: &Agent{
				set: ChecklistSet{
					{State: ChecklistRunning},
				},
			},
		},
		{
			Name:  "OneCompletedOneRunning",
			State: Running,
			Agent: &Agent{
				set: ChecklistSet{
					{State: ChecklistRunning},
					{State: ChecklistCompleted},
				},
			},
		},
		{
			Name:  "OneFailedOneRunning",
			State: Running,
			Agent: &Agent{
				set: ChecklistSet{
					{State: ChecklistRunning},
					{State: ChecklistFailed},
				},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			tc.Agent.updateState()
			if tc.State != tc.Agent.state {
				t.Errorf("%s (got) != %s (expected)", tc.Agent.state, tc.State)
			}
		})
	}

}

func TestAgent_init(t *testing.T) {
	a := Agent{}
	var c Checklist
	loadGoldenJSON(t, &c, "checklist.json")
	a.set = append(a.set, c)
	a.init()
	a.updateState()
	t.Logf("state: %s", a.state)
	if *writeGolden {
		saveGoldenJSON(t, a.set[0], "checklist_updated.json")
	}
	var cGolden Checklist
	loadGoldenJSON(t, &cGolden, "checklist_updated.json")
	if !cGolden.Equal(a.set[0]) {
		t.Error("got unexpected checklist after init")
	}
}

func BenchmarkPairContextKey(b *testing.B) {
	p := Pair{
		Remote: Candidate{},
		Local: Candidate{
			Addr: Addr{
				IP:    net.IPv4(127, 0, 0, 1),
				Port:  31223,
				Proto: candidate.UDP,
			},
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k := pairContextKey(&p)
		if k.Port == 0 {
			b.Fatal("bad port")
		}
	}
}
