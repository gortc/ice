package ice

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"sort"
	"testing"

	"github.com/gortc/ice/candidate"
	"github.com/gortc/stun"
)

func newUDPCandidate(t *testing.T, addr HostAddr) candidateAndConn {
	t.Helper()
	zeroPort := net.UDPAddr{
		IP:   addr.IP,
		Port: 0,
	}
	l, err := net.ListenPacket("udp", zeroPort.String())
	if err != nil {
		t.Fatal(err)
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
	c.Priority = Priority(TypePreference(c.Type), addr.LocalPreference, c.ComponentID)
	return candidateAndConn{
		Candidate: c,
		Conn:      l,
	}
}

type stunMock struct {
	do func(m *stun.Message, f func(stun.Event)) error
}

func (s *stunMock) Do(m *stun.Message, f func(stun.Event)) error { return s.do(m, f) }

func TestAgent_check(t *testing.T) {
	a := Agent{}
	var c Checklist
	loadGoldenJSON(t, &c, "checklist.json")
	a.set = append(a.set, c)
	randSource := rand.NewSource(1)
	a.rand = rand.New(randSource)
	if err := a.init(); err != nil {
		t.Fatal(err)
	}
	if a.tieBreaker != 5721121980023635282 {
		t.Fatal(a.tieBreaker)
	}
	if a.role != Controlling {
		t.Fatal("bad role")
	}
	a.updateState()
	t.Logf("state: %s", a.state)
	pair := &a.set[0].Pairs[0]
	integrity := stun.NewShortTermIntegrity("RPASS")
	stunAgent := &stunMock{}
	a.ctx[pairContextKey(pair)] = context{
		localUsername:  "LFRAG",
		remoteUsername: "RFRAG",
		remotePassword: "RPASS",
		localPassword:  "LPASS",
		stun:           stunAgent,
		localPref:      10,
	}
	t.Run("OK", func(t *testing.T) {
		checkMessage := func(t *testing.T, m *stun.Message) {
			t.Helper()
			if err := integrity.Check(m); err != nil {
				t.Errorf("failed to check integrity: %v", err)
			}
			var u stun.Username
			if err := u.GetFrom(m); err != nil {
				t.Errorf("failed to get username: %v", err)
			}
			if u.String() != "RFRAG:LFRAG" {
				t.Errorf("unexpected username: %s", u)
			}
			var p PriorityAttr
			if err := p.GetFrom(m); err != nil {
				t.Error("failed to get priority attribute")
			}
			if p != 1845496575 {
				t.Errorf("unexpected priority: %d", p)
			}
		}
		t.Run("Controlling", func(t *testing.T) {
			stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
				checkMessage(t, m)
				var (
					rControlling AttrControlling
					rControlled  AttrControlled
				)
				if rControlled.GetFrom(m) == nil {
					t.Error("unexpected controlled attribute")
				}
				if err := rControlling.GetFrom(m); err != nil {
					t.Error(err)
				}
				if rControlling != 5721121980023635282 {
					t.Errorf("unexpected tie-breaker: %d", rControlling)
				}
				f(stun.Event{Message: stun.MustBuild(m, stun.BindingSuccess, integrity, stun.Fingerprint)})
				return nil
			}
			if err := a.check(pair); err != nil {
				t.Fatal("failed to check", err)
			}
		})
		t.Run("Controlled", func(t *testing.T) {
			a.role = Controlled
			stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
				checkMessage(t, m)
				var (
					rControlling AttrControlling
					rControlled  AttrControlled
				)
				if rControlling.GetFrom(m) == nil {
					t.Error("unexpected controlled attribute")
				}
				if err := rControlled.GetFrom(m); err != nil {
					t.Error(err)
				}
				if rControlled != 5721121980023635282 {
					t.Errorf("unexpected tie-breaker: %d", rControlled)
				}
				f(stun.Event{Message: stun.MustBuild(m, stun.BindingSuccess, integrity, stun.Fingerprint)})
				return nil
			}
			if err := a.check(pair); err != nil {
				t.Fatal("failed to check", err)
			}
		})
	})
	t.Run("STUN Agent failure", func(t *testing.T) {
		stunErr := errors.New("failed")
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			return stunErr
		}
		if err := a.check(pair); err != stunErr {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN Event error", func(t *testing.T) {
		stunErr := errors.New("failed")
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			f(stun.Event{
				Error: stunErr,
			})
			return nil
		}
		if err := a.check(pair); err != stunErr {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN Unrecoverable error", func(t *testing.T) {
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			f(stun.Event{
				Message: stun.MustBuild(m, stun.BindingError, stun.CodeBadRequest, integrity, stun.Fingerprint),
			})
			return nil
		}
		codeErr := unrecoverableErrorCodeErr{Code: stun.CodeBadRequest}
		if err := a.check(pair); err != codeErr {
			t.Fatalf("unexpected error %v", err)
		}
	})
	t.Run("STUN Error response without code", func(t *testing.T) {
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			f(stun.Event{
				Message: stun.MustBuild(m, stun.BindingError, integrity, stun.Fingerprint),
			})
			return nil
		}
		if err := a.check(pair); err == nil {
			t.Fatal("unexpected success")
		}
	})
	t.Run("STUN Role conflict", func(t *testing.T) {
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			f(stun.Event{
				Message: stun.MustBuild(m, stun.BindingError, stun.CodeRoleConflict, integrity, stun.Fingerprint),
			})
			return nil
		}
		if err := a.check(pair); err != errRoleConflict {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN Integrity error", func(t *testing.T) {
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			i := stun.NewShortTermIntegrity("RPASS+BAD")
			response := stun.MustBuild(m, stun.BindingSuccess, i, stun.Fingerprint)
			f(stun.Event{Message: response})
			return nil
		}
		if err := a.check(pair); err != stun.ErrIntegrityMismatch {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN No fingerprint", func(t *testing.T) {
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			response := stun.MustBuild(m, stun.BindingSuccess, integrity)
			f(stun.Event{Message: response})
			return nil
		}
		if err := a.check(pair); err != errFingerprintNotFound {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN Bad fingerprint", func(t *testing.T) {
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			badFP := stun.RawAttribute{Type: stun.AttrFingerprint, Value: []byte{'b', 'a', 'd', 0}}
			response := stun.MustBuild(m, stun.BindingSuccess, integrity, badFP)
			f(stun.Event{Message: response})
			return nil
		}
		if err := a.check(pair); err != stun.ErrFingerprintMismatch {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Run("Should be done before integrity check", func(t *testing.T) {
			stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
				i := stun.NewShortTermIntegrity("RPASS+BAD")
				badFP := stun.RawAttribute{Type: stun.AttrFingerprint, Value: []byte{'b', 'a', 'd', 0}}
				response := stun.MustBuild(m, stun.BindingSuccess, i, badFP)
				f(stun.Event{Message: response})
				return nil
			}
			if err := a.check(pair); err != stun.ErrFingerprintMismatch {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	})
	t.Run("STUN Wrong response message type", func(t *testing.T) {
		stunAgent.do = func(m *stun.Message, f func(stun.Event)) error {
			f(stun.Event{
				Message: stun.MustBuild(m, stun.BindingRequest, stun.CodeBadRequest, integrity, stun.Fingerprint),
			})
			return nil
		}
		typeErr := unexpectedResponseTypeErr{Type: stun.BindingRequest}
		if err := a.check(pair); err != typeErr {
			t.Fatalf("unexpected success")
		}
	})
}

type candidateAndConn struct {
	Candidate Candidate
	Conn      net.PacketConn
}

func (c candidateAndConn) Close() error {
	return c.Conn.Close()
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
	var toClose []io.Closer
	defer func() {
		for _, f := range toClose {
			if cErr := f.Close(); cErr != nil {
				t.Error(cErr)
			}
		}
	}()
	var local, remote Candidates
	for _, a := range hostAddr {
		l, r := newUDPCandidate(t, a), newUDPCandidate(t, a)
		toClose = append(toClose, l, r)
		local = append(local, l.Candidate)
		remote = append(remote, r.Candidate)
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
	if err := a.init(); err != nil {
		t.Fatal(err)
	}
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
		Local: Candidate{
			Addr: Addr{
				IP:    net.IPv4(127, 0, 0, 1),
				Port:  31223,
				Proto: candidate.UDP,
			},
		},
		Remote: Candidate{
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
		if k.LocalPort == 0 {
			b.Fatal("bad port")
		}
	}
}
