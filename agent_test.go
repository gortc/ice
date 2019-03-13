package ice

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/gortc/ice/candidate"
	"github.com/gortc/ice/gather"
	"github.com/gortc/stun"

	"go.uber.org/zap"
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
	start func(m *stun.Message) error
}

func (s *stunMock) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	panic("implement me")
}

func (s *stunMock) Close() error {
	panic("implement me")
}

func (s *stunMock) LocalAddr() net.Addr {
	panic("implement me")
}

func (s *stunMock) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (s *stunMock) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (s *stunMock) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func (s *stunMock) WriteTo(buf []byte, addr net.Addr) (int, error) {
	m := &stun.Message{Raw: buf}
	if err := m.Decode(); err != nil {
		return 0, err
	}
	return len(m.Raw), s.start(m)
}

func mustInit(t *testing.T, a *Agent) {
	t.Helper()
	if err := a.init(); err != nil {
		t.Fatal(err)
	}
}

func TestAgent_processUDP(t *testing.T) {
	t.Run("Blank", func(t *testing.T) {
		a := &Agent{
			log: zap.NewNop(),
		}
		mustInit(t, a)
		t.Run("Not STUN", func(t *testing.T) {
			if err := a.processUDP([]byte{1, 2}, &localUDPCandidate{}, &net.UDPAddr{}); err != errNotSTUNMessage {
				t.Errorf("should be notStun, got %v", err)
			}
		})
		t.Run("No transaction", func(t *testing.T) {
			m := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
			if err := a.processUDP(m.Raw, &localUDPCandidate{}, &net.UDPAddr{}); err != nil {
				t.Error(err)
			}
		})
		t.Run("Bad STUN", func(t *testing.T) {
			m := stun.MustBuild(stun.TransactionID, stun.BindingSuccess, stun.XORMappedAddress{
				IP: net.IPv4(1, 2, 3, 4),
			}, stun.Fingerprint)
			if err := a.processUDP(m.Raw[:len(m.Raw)-2], &localUDPCandidate{}, &net.UDPAddr{}); err == nil {
				t.Error("should error")
			} else {
				if err == errNotSTUNMessage {
					t.Error("unexpected notStun err")
				}
				t.Log(err)
			}
		})
	})
}

func TestAgent_handleBindingResponse(t *testing.T) {
	cl0 := Checklist{
		Pairs: Pairs{
			{
				Local: Candidate{
					Addr: Addr{
						Port: 10230,
						IP:   net.IPv4(10, 0, 0, 2),
					},
				},
				Remote: Candidate{
					Addr: Addr{
						Port: 31230,
						IP:   net.IPv4(10, 0, 0, 1),
					},
				},
				Foundation: []byte{1, 3},
				Priority:   1234,
			},
		},
	}
	a := &Agent{
		set: ChecklistSet{cl0},
		localCandidates: [][]localUDPCandidate{
			{
				{candidate: Candidate{
					Addr: Addr{
						Port: 10230,
						IP:   net.IPv4(10, 0, 0, 2),
					},
				}},
			},
		},
	}
	mustInit(t, a)
	_, cID := a.nextChecklist()
	a.checklist = cID
	pair, err := a.pickPair()
	if err != nil {
		t.Fatal(err)
	}
	at := &agentTransaction{
		id:        stun.NewTransactionID(),
		pair:      0,
		checklist: 0,
	}
	a.SetRemoteCredentials("RFRAG", "RPASS")
	a.SetLocalCredentials("LFRAG", "LPASS")
	integrity := stun.NewShortTermIntegrity("RPASS")
	xorAddr := stun.XORMappedAddress{
		IP:   pair.Local.Addr.IP,
		Port: pair.Local.Addr.Port,
	}
	msg := stun.MustBuild(at.id, stun.BindingSuccess,
		stun.NewUsername("RFRAG:LFRAG"), &xorAddr,
		integrity, stun.Fingerprint,
	)
	if err := a.handleBindingResponse(at, pair, msg, pair.Remote.Addr); err != nil {
		t.Fatal(err)
	}
	if len(a.set[0].Valid) == 0 {
		t.Error("valid set is empty")
	}
}

func TestAgent_check(t *testing.T) {
	a := &Agent{}
	var c Checklist
	loadGoldenJSON(t, &c, "checklist.json")
	a.set = append(a.set, c)
	randSource := rand.NewSource(1)
	a.rand = rand.New(randSource)
	if err := a.init(); err != nil {
		t.Fatal(err)
	}
	if a.tiebreaker != 5721121980023635282 {
		t.Fatal(a.tiebreaker)
	}
	if a.role != Controlling {
		t.Fatal("bad role")
	}
	a.updateState()
	t.Logf("state: %s", a.state)
	pair := &a.set[0].Pairs[0]
	pair.Local.LocalPreference = 10
	integrity := stun.NewShortTermIntegrity("RPASS")
	stunAgent := &stunMock{}
	xorAddr := &stun.XORMappedAddress{
		IP:   pair.Local.Addr.IP,
		Port: pair.Local.Addr.Port,
	}
	a.localCandidates = [][]localUDPCandidate{
		{
			{
				candidate: pair.Local,
				conn:      stunAgent,
			},
		},
	}
	a.SetRemoteCredentials("RFRAG", "RPASS")
	a.SetLocalCredentials("LFRAG", "LPASS")
	now := time.Time{}
	t.Run("OK", func(t *testing.T) {
		checkMessage := func(t *testing.T, m *stun.Message) {
			t.Helper()
			if err := integrity.Check(m); err != nil {
				t.Errorf("failed to startCheck integrity: %v", err)
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
			var tid transactionID
			stunAgent.start = func(m *stun.Message) error {
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
					t.Errorf("unexpected tiebreaker: %d", rControlling)
				}
				tid = m.TransactionID
				return nil
			}
			if err := a.startCheck(pair, now); err != nil {
				t.Fatal("failed to startCheck", err)
			}
			resp := stun.MustBuild(stun.NewTransactionIDSetter(tid), stun.BindingSuccess, xorAddr, integrity, stun.Fingerprint)
			if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != nil {
				t.Error(err)
			}
		})
		t.Run("Controlled", func(t *testing.T) {
			a.role = Controlled
			var tid transactionID
			stunAgent.start = func(m *stun.Message) error {
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
					t.Errorf("unexpected tiebreaker: %d", rControlled)
				}
				tid = m.TransactionID
				return nil
			}
			if err := a.startCheck(pair, now); err != nil {
				t.Fatal("failed to startCheck", err)
			}
			resp := stun.MustBuild(stun.NewTransactionIDSetter(tid), stun.BindingSuccess, xorAddr, integrity, stun.Fingerprint)
			if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != nil {
				t.Error(err)
			}
		})
	})
	t.Run("STUN Agent failure", func(t *testing.T) {
		stunErr := errors.New("failed")
		stunAgent.start = func(m *stun.Message) error {
			return stunErr
		}
		if err := a.startCheck(pair, now); err != stunErr {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN Unrecoverable error", func(t *testing.T) {
		var tid transactionID
		stunAgent.start = func(m *stun.Message) error {
			tid = m.TransactionID
			return nil
		}
		codeErr := unrecoverableErrorCodeErr{Code: stun.CodeBadRequest}
		if err := a.startCheck(pair, now); err != nil {
			t.Fatal(err)
		}
		resp := stun.MustBuild(stun.NewTransactionIDSetter(tid), stun.BindingError, stun.CodeBadRequest, integrity, stun.Fingerprint)
		if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != codeErr {
			t.Fatalf("unexpected error %v", err)
		}
	})
	t.Run("STUN Error response without code", func(t *testing.T) {
		var tid transactionID
		stunAgent.start = func(m *stun.Message) error {
			tid = m.TransactionID
			return nil
		}
		if err := a.startCheck(pair, now); err != nil {
			t.Fatal(err)
		}
		resp := stun.MustBuild(tid, stun.BindingError, integrity, stun.Fingerprint)
		if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err == nil {
			t.Fatal("unexpected success")
		}
	})
	t.Run("STUN Role conflict", func(t *testing.T) {
		var tid transactionID
		stunAgent.start = func(m *stun.Message) error {
			tid = m.TransactionID
			return nil
		}
		resp := stun.MustBuild(tid, stun.BindingError, stun.CodeRoleConflict, xorAddr, integrity, stun.Fingerprint)
		if err := a.startCheck(pair, now); err != nil {
			t.Fatal(err)
		}
		if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != errRoleConflict {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN Integrity error", func(t *testing.T) {
		var tid transactionID
		stunAgent.start = func(m *stun.Message) error {
			tid = m.TransactionID
			return nil
		}
		if err := a.startCheck(pair, now); err != nil {
			t.Fatal(err)
		}
		i := stun.NewShortTermIntegrity("RPASS+BAD")
		resp := stun.MustBuild(tid, stun.BindingSuccess, i, xorAddr, stun.Fingerprint)
		if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != stun.ErrIntegrityMismatch {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN No fingerprint", func(t *testing.T) {
		var tid transactionID
		stunAgent.start = func(m *stun.Message) error {
			tid = m.TransactionID
			return nil
		}
		if err := a.startCheck(pair, now); err != nil {
			t.Fatal(err)
		}
		resp := stun.MustBuild(tid, stun.BindingSuccess, integrity)
		if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != errFingerprintNotFound {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("STUN Bad fingerprint", func(t *testing.T) {
		var tid transactionID
		stunAgent.start = func(m *stun.Message) error {
			tid = m.TransactionID
			return nil
		}
		if err := a.startCheck(pair, now); err != nil {
			t.Fatal(err)
		}
		badFP := stun.RawAttribute{Type: stun.AttrFingerprint, Value: []byte{'b', 'a', 'd', 0}}
		resp := stun.MustBuild(tid, stun.BindingSuccess, integrity, badFP)
		if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != stun.ErrFingerprintMismatch {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Run("Should be done before integrity startCheck", func(t *testing.T) {
			var tid transactionID
			stunAgent.start = func(m *stun.Message) error {
				tid = m.TransactionID
				return nil
			}
			if err := a.startCheck(pair, now); err != nil {
				t.Fatal(err)
			}
			i := stun.NewShortTermIntegrity("RPASS+BAD")
			badFP := stun.RawAttribute{Type: stun.AttrFingerprint, Value: []byte{'b', 'a', 'd', 0}}
			resp := stun.MustBuild(tid, stun.BindingSuccess, i, badFP)
			if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != stun.ErrFingerprintMismatch {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	})
	t.Run("STUN Wrong response message type", func(t *testing.T) {
		var tid transactionID
		stunAgent.start = func(m *stun.Message) error {
			tid = m.TransactionID
			return nil
		}
		typeErr := unexpectedResponseTypeErr{Type: stun.BindingRequest}
		if err := a.startCheck(pair, now); err != nil {
			t.Fatal(err)
		}
		resp := stun.MustBuild(tid, stun.BindingRequest, stun.CodeBadRequest, integrity, stun.Fingerprint)
		if err := a.processBindingResponse(nil, pair, resp, pair.Remote.Addr); err != typeErr {
			t.Fatalf("unexpected success")
		}
	})
}

type candidateAndConn struct {
	Candidate Candidate
	Conn      net.PacketConn
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
		toClose = append(toClose, l.Conn, r.Conn)
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

func TestAgent_nextChecklist(t *testing.T) {
	for _, tc := range []struct {
		Name    string
		Set     ChecklistSet
		ID      int
		Current int
	}{
		{
			Name:    "blank",
			ID:      noChecklist,
			Current: noChecklist,
		},
		{
			Name:    "first",
			Set:     ChecklistSet{{}},
			ID:      0,
			Current: noChecklist,
		},
		{
			Name:    "no running",
			Set:     ChecklistSet{{State: ChecklistFailed}},
			ID:      noChecklist,
			Current: noChecklist,
		},
		{
			Name:    "second",
			Set:     ChecklistSet{{}, {}},
			ID:      1,
			Current: 0,
		},
		{
			Name:    "second running",
			Set:     ChecklistSet{{}, {State: ChecklistFailed}, {}},
			ID:      2,
			Current: 0,
		},
		{
			Name:    "circle",
			Set:     ChecklistSet{{}, {State: ChecklistFailed}, {}},
			ID:      0,
			Current: 2,
		},
		{
			Name:    "circle without running",
			Set:     ChecklistSet{{State: ChecklistFailed}, {State: ChecklistFailed}},
			ID:      noChecklist,
			Current: 1,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			a := &Agent{set: tc.Set, checklist: tc.Current}
			_, id := a.nextChecklist()
			if id != tc.ID {
				t.Errorf("nextChecklist %d (got) != %d (expected)", id, tc.ID)
			}
		})
	}
}

func TestAgent_pickPair(t *testing.T) {
	for _, tc := range []struct {
		Name      string
		Set       ChecklistSet
		Checklist int
		Pair      Pair
		Err       error
	}{
		{
			Name:      "no checklist",
			Checklist: noChecklist,
			Err:       errNoChecklist,
		},
		{
			Name:      "no pair",
			Checklist: 0,
			Err:       errNoPair,
			Set:       ChecklistSet{{}},
		},
		{
			Name:      "first",
			Checklist: 0,
			Set: ChecklistSet{
				{Pairs: Pairs{{State: PairWaiting}}},
			},
			Pair: Pair{State: PairInProgress},
		},
		{
			Name:      "all failed",
			Checklist: 0,
			Err:       errNoPair,
			Set: ChecklistSet{
				{Pairs: Pairs{{State: PairFailed}}},
			},
		},
		{
			Name:      "simple unfreeze",
			Checklist: 0,
			Set: ChecklistSet{
				{Pairs: Pairs{{State: PairFrozen}}},
			},
			Pair: Pair{State: PairInProgress},
		},
		{
			Name:      "simple no unfreeze",
			Checklist: 0,
			Set: ChecklistSet{
				{Pairs: Pairs{
					{State: PairFrozen, Foundation: []byte{1}, Priority: 10},
					{State: PairWaiting, Foundation: []byte{1}, Priority: 9},
				}},
			},
			Pair: Pair{State: PairInProgress, Foundation: []byte{1}, Priority: 9},
		},
		{
			Name:      "no unfreeze from other checklist",
			Checklist: 1,
			Err:       errNoPair,
			Set: ChecklistSet{
				{Pairs: Pairs{
					{State: PairWaiting, Foundation: []byte{1}},
				}},
				{Pairs: Pairs{
					{State: PairFrozen, Foundation: []byte{1}},
				}},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			a := &Agent{set: tc.Set, checklist: tc.Checklist}
			pair, err := a.pickPair()
			if err != tc.Err {
				t.Errorf("pickPair error %v (got) != %v (expected)", err, tc.Err)
			}
			if tc.Err == nil && !tc.Pair.Equal(pair) {
				t.Errorf("picked wrong pair: {%s}", pair.State)
			}
		})
	}
	t.Run("first unfreeze only", func(t *testing.T) {
		a := &Agent{
			checklist: 0,
			set: ChecklistSet{
				{Pairs: Pairs{
					{State: PairFrozen, Foundation: []byte{1}},
					{State: PairFrozen, Foundation: []byte{2}},
				}},
			},
		}
		_, err := a.pickPair()
		if err != nil {
			t.Fatal(err)
		}
		if a.set[0].Pairs[1].State != PairFrozen {
			t.Error("second pair should be frozen")
		}
		if a.set[0].Pairs[0].State != PairInProgress {
			t.Error("first pair should be in progress")
		}
	})
}

func BenchmarkAgent_pickPair(b *testing.B) {
	b.Run("Simple", func(b *testing.B) {
		a := &Agent{
			set: ChecklistSet{{
				Pairs: Pairs{
					{
						Foundation: []byte{1, 2, 3, 100, 31, 22},
					},
				},
			}},
		}
		if err := a.init(); err != nil {
			b.Fatal(err)
		}
		_, checklist := a.nextChecklist()
		if checklist == noChecklist {
			b.Fatal("no checklist")
		}
		a.checklist = checklist

		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := a.pickPair()
			if err != nil {
				b.Fatal(err)
			}
			a.setPairState(a.checklist, 0, PairWaiting)
		}
	})
	b.Run("Frozen", func(b *testing.B) {
		a := &Agent{
			checklist: 0,
			set: ChecklistSet{
				{
					Pairs: Pairs{
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 22}},
						{State: PairFailed, Foundation: []byte{1, 2, 3, 100, 31, 22}},
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 22}},
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 24}},
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 23}},
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 22}},
					},
				},
				{
					Pairs: Pairs{
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 21}},
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 22}},
						{State: PairWaiting, Foundation: []byte{1, 2, 3, 100, 31, 21}},
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 22}},
						{State: PairWaiting, Foundation: []byte{1, 2, 3, 100, 31, 23}},
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 20}},
					},
				},
				{
					Pairs: Pairs{
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 22}},
					},
				},
				{
					Pairs: Pairs{
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 22}},
					},
				},

				{
					Pairs: Pairs{
						{State: PairFrozen, Foundation: []byte{1, 2, 3, 100, 31, 22}},
					},
				},
			},
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := a.pickPair()
			if err != nil {
				b.Fatal(err)
			}
			a.setPairState(a.checklist, 0, PairFrozen)
		}
	})
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

func shouldNotAllocate(t *testing.T, f func()) {
	t.Helper()
	if a := testing.AllocsPerRun(10, f); a > 0 {
		t.Errorf("unexpected allocations: %f", a)
	}
}

func TestFoundationSet(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		fs := make(foundationSet)
		shouldNotAllocate(t, func() {
			fs.Add([]byte{1, 2})
		})
		if !fs.Contains([]byte{1, 2}) {
			t.Error("does not contain {1, 2}")
		}
	})
	t.Run("Contains", func(t *testing.T) {
		fs := make(foundationSet)
		fs.Add([]byte{1, 2})
		if !fs.Contains([]byte{1, 2}) {
			t.Error("does not contain {1, 2}")
		}
		shouldNotAllocate(t, func() {
			fs.Contains([]byte{1, 2})
		})
		if fs.Contains([]byte{1, 3}) {
			t.Error("should not contain {1, 3}")
		}
	})
	t.Run("Panic on too big foundation", func(t *testing.T) {
		fs := make(foundationSet)
		f := make([]byte, 200)
		t.Run("Contains", func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("no panic")
				}
			}()
			fs.Contains(f)
		})
		t.Run("Add", func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("no panic")
				}
			}()
			fs.Add(f)
		})
	})
}

func TestAgentRTO(t *testing.T) {
	t.Run("Blank", func(t *testing.T) {
		a := &Agent{}
		mustInit(t, a)
		if rto := a.rto(); rto != time.Millisecond*500 {
			t.Errorf("bad rto %s", rto)
		}
	})
	t.Run("Default", func(t *testing.T) {
		a := &Agent{
			// Note that after init() state will change,
			// there will be 12 in "waiting/progress".
			set: ChecklistSet{
				{
					Pairs: Pairs{
						{State: PairFailed},
					},
				},
				{
					Pairs: Pairs{
						{State: PairFailed},
						{State: PairFrozen},
						{State: PairWaiting},
						{State: PairWaiting},
						{State: PairWaiting},
						{State: PairWaiting},
						{State: PairWaiting},
						{State: PairWaiting},
						{State: PairWaiting},
						{State: PairWaiting},
						{State: PairWaiting},
						{State: PairInProgress},
					},
				},
			},
		}
		mustInit(t, a)
		if rto := a.rto(); rto != time.Millisecond*7800 {
			t.Errorf("bad rto %s", rto)
		}
	})
}

func mustClose(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil {
		t.Error(err)
	}
}

type mockGatherer struct {
	udp func(opt gathererOptions) ([]localUDPCandidate, error)
}

func (g *mockGatherer) gatherUDP(opt gathererOptions) ([]localUDPCandidate, error) {
	return g.udp(opt)
}

type mockPacketConn struct{}

func (mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, io.EOF
}

func (mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	panic("implement me")
}

func (mockPacketConn) Close() error { return nil }

func (mockPacketConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (mockPacketConn) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (mockPacketConn) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (mockPacketConn) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func TestAgent(t *testing.T) {
	t.Run("Solo", func(t *testing.T) {
		a, err := NewAgent()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.LocalCandidates(); err != errNoStreamFound {
			t.Errorf("expected not to find stream, got %v", err)
		}
		if err = a.GatherCandidates(); err != nil {
			t.Errorf("failed to gather candidates: %v", err)
		}
		if err = a.GatherCandidates(); err != errStreamAlreadyExist {
			t.Errorf("expected stream alrady exist error, got %v", err)
		}
		localCandidates, err := a.LocalCandidates()
		if err != nil {
			t.Errorf("failed to get local candidates: %v", err)
		}
		t.Logf("got %d candidate(s)", len(localCandidates))
		if len(localCandidates) == 0 {
			t.Error("no local candidates provided")
		}
		if err = a.Close(); err != nil {
			t.Fatalf("failed to close: %v", err)
		}
	})
	t.Run("Dual", func(t *testing.T) {
		a, err := NewAgent()
		if err != nil {
			t.Fatal(err)
		}
		defer mustClose(t, a)
		if err = a.GatherCandidates(); err != nil {
			t.Errorf("failed to gather candidates: %v", err)
		}
		b, err := NewAgent()
		if err != nil {
			t.Fatal(err)
		}
		defer mustClose(t, b)
		if err = b.GatherCandidates(); err != nil {
			t.Errorf("failed to gather candidates: %v", err)
		}
		aCandidates, err := a.LocalCandidates()
		if err != nil {
			t.Fatal(err)
		}
		bCandidates, err := b.LocalCandidates()
		if err != nil {
			t.Fatal(err)
		}
		if err = a.AddRemoteCandidates(bCandidates); err != nil {
			t.Fatal(err)
		}
		if err = b.AddRemoteCandidates(aCandidates); err != nil {
			t.Fatal(err)
		}
		if err = a.PrepareChecklistSet(); err != nil {
			t.Fatal(err)
		}
		if err = b.PrepareChecklistSet(); err != nil {
			t.Fatal(err)
		}
		t.Logf("got pairs: %d", len(a.set[0].Pairs))
		for _, p := range a.set[0].Pairs {
			t.Logf("%s -> %s [%d]", p.Local.Addr, p.Remote.Addr, p.Priority)
		}
	})
	t.Run("Custom gatherer", func(t *testing.T) {
		a, err := NewAgent(withGatherer(&mockGatherer{
			udp: func(opt gathererOptions) (candidates []localUDPCandidate, e error) {
				ip := net.IPv4(10, 0, 0, 2)
				addrs, err := HostAddresses([]gather.Addr{
					{
						IP:         ip,
						Precedence: gather.Precedence(ip),
					},
				})
				if err != nil {
					panic(err)
				}
				a := Addr{
					IP:    addrs[0].IP,
					Port:  30001,
					Proto: candidate.UDP,
				}
				c := localUDPCandidate{
					candidate: Candidate{
						Base: Addr{
							IP:    a.IP,
							Port:  a.Port,
							Proto: candidate.UDP,
						},
						Type: candidate.Host,
						Addr: Addr{
							IP:    a.IP,
							Port:  a.Port,
							Proto: candidate.UDP,
						},
						ComponentID: 1,
					},
					conn: mockPacketConn{},
				}
				return []localUDPCandidate{c}, nil
			},
		}))
		if err != nil {
			t.Fatal(err)
		}
		defer mustClose(t, a)
		if err = a.GatherCandidates(); err != nil {
			t.Errorf("failed to gather candidates: %v", err)
		}
		b, err := NewAgent(withGatherer(&mockGatherer{
			udp: func(opt gathererOptions) (candidates []localUDPCandidate, e error) {
				ip := net.IPv4(10, 0, 0, 2)
				addrs, addrErr := HostAddresses([]gather.Addr{
					{
						IP:         ip,
						Precedence: gather.Precedence(ip),
					},
				})
				if addrErr != nil {
					panic(addrErr)
				}
				a := Addr{
					IP:    addrs[0].IP,
					Port:  30002,
					Proto: candidate.UDP,
				}
				c := localUDPCandidate{
					candidate: Candidate{
						Base: Addr{
							IP:    a.IP,
							Port:  a.Port,
							Proto: candidate.UDP,
						},
						Type: candidate.Host,
						Addr: Addr{
							IP:    a.IP,
							Port:  a.Port,
							Proto: candidate.UDP,
						},
						ComponentID: 1,
					},
					conn: mockPacketConn{},
				}
				return []localUDPCandidate{c}, nil
			},
		}), WithRole(Controlled))
		if err != nil {
			t.Fatal(err)
		}
		defer mustClose(t, b)
		if err = b.GatherCandidates(); err != nil {
			t.Errorf("failed to gather candidates: %v", err)
		}
		aCandidates, err := a.LocalCandidates()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("a:", aCandidates[0].Addr)
		bCandidates, err := b.LocalCandidates()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("b:", bCandidates[0].Addr)
		if err = a.AddRemoteCandidates(bCandidates); err != nil {
			t.Fatal(err)
		}
		if err = b.AddRemoteCandidates(aCandidates); err != nil {
			t.Fatal(err)
		}
		if err = a.PrepareChecklistSet(); err != nil {
			t.Fatal(err)
		}
		if err = b.PrepareChecklistSet(); err != nil {
			t.Fatal(err)
		}
		t.Logf("got pairs: %d", len(a.set[0].Pairs))
		for _, p := range a.set[0].Pairs {
			if p.Local.Addr.Equal(p.Remote.Addr) {
				t.Error("local address is equal to remote")
			}
			t.Logf("%s -> %s [%d]", p.Local.Addr, p.Remote.Addr, p.Priority)
		}
	})
}

type pipePacketConn struct {
	conn       net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *pipePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.conn.Read(p)
	return n, c.remoteAddr, err
}

func (c *pipePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.conn.Write(p)
}

func (c pipePacketConn) Close() error {
	return c.conn.Close()
}

func (pipePacketConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (pipePacketConn) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (pipePacketConn) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (pipePacketConn) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func packetPipe(local, remote net.Addr) (net.PacketConn, net.PacketConn) {
	l, r := net.Pipe()
	lCon := &pipePacketConn{
		conn:       l,
		remoteAddr: remote,
		localAddr:  local,
	}
	rCon := &pipePacketConn{
		conn:       r,
		remoteAddr: local,
		localAddr:  remote,
	}
	return lCon, rCon
}

func TestAgent_Conclude(t *testing.T) {
	t.Skip("TODO: Implement conclude")
	t.Run("Custom gatherer", func(t *testing.T) {
		log, err := zap.NewDevelopment()
		if err != nil {
			t.Fatal(err)
		}
		lAddr := &net.UDPAddr{
			IP:   net.IPv4(10, 0, 0, 1),
			Port: 1000,
		}
		rAddr := &net.UDPAddr{
			IP:   net.IPv4(10, 0, 0, 2),
			Port: 2000,
		}
		connL, connR := packetPipe(lAddr, rAddr)
		a, err := NewAgent(withGatherer(&mockGatherer{
			udp: func(opt gathererOptions) (candidates []localUDPCandidate, e error) {
				addrs, addrErr := HostAddresses([]gather.Addr{
					{
						IP:         lAddr.IP,
						Precedence: gather.Precedence(lAddr.IP),
					},
				})
				if addrErr != nil {
					panic(addrErr)
				}
				a := Addr{
					IP:    addrs[0].IP,
					Port:  lAddr.Port,
					Proto: candidate.UDP,
				}
				c := localUDPCandidate{
					log: log.Named("L").Named("C"),
					candidate: Candidate{
						Base: Addr{
							IP:    a.IP,
							Port:  a.Port,
							Proto: candidate.UDP,
						},
						Type: candidate.Host,
						Addr: Addr{
							IP:    a.IP,
							Port:  a.Port,
							Proto: candidate.UDP,
						},
						ComponentID: 1,
					},
					conn: connL,
				}
				return []localUDPCandidate{c}, nil
			},
		}), WithLogger(log.Named("L")))
		if err != nil {
			t.Fatal(err)
		}
		defer mustClose(t, a)
		if err = a.GatherCandidates(); err != nil {
			t.Errorf("failed to gather candidates: %v", err)
		}
		b, err := NewAgent(withGatherer(&mockGatherer{
			udp: func(opt gathererOptions) (candidates []localUDPCandidate, e error) {
				addrs, addrErr := HostAddresses([]gather.Addr{
					{
						IP:         rAddr.IP,
						Precedence: gather.Precedence(rAddr.IP),
					},
				})
				if addrErr != nil {
					panic(addrErr)
				}
				a := Addr{
					IP:    addrs[0].IP,
					Port:  rAddr.Port,
					Proto: candidate.UDP,
				}
				c := localUDPCandidate{
					log: log.Named("R").Named("C"),
					candidate: Candidate{
						Base: Addr{
							IP:    a.IP,
							Port:  a.Port,
							Proto: candidate.UDP,
						},
						Type: candidate.Host,
						Addr: Addr{
							IP:    a.IP,
							Port:  a.Port,
							Proto: candidate.UDP,
						},
						ComponentID: 1,
					},
					conn: connR,
				}
				return []localUDPCandidate{c}, nil
			},
		}), WithRole(Controlled), WithLogger(log.Named("R")))
		if err != nil {
			t.Fatal(err)
		}
		defer mustClose(t, b)
		if err = b.GatherCandidates(); err != nil {
			t.Errorf("failed to gather candidates: %v", err)
		}
		aCandidates, err := a.LocalCandidates()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("a:", aCandidates[0].Addr)
		bCandidates, err := b.LocalCandidates()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("b:", bCandidates[0].Addr)
		if err = a.AddRemoteCandidates(bCandidates); err != nil {
			t.Fatal(err)
		}
		if err = b.AddRemoteCandidates(aCandidates); err != nil {
			t.Fatal(err)
		}
		if err = a.PrepareChecklistSet(); err != nil {
			t.Fatal(err)
		}
		if err = b.PrepareChecklistSet(); err != nil {
			t.Fatal(err)
		}
		t.Logf("got pairs: %d", len(a.set[0].Pairs))
		for _, p := range a.set[0].Pairs {
			if p.Local.Addr.Equal(p.Remote.Addr) {
				t.Error("local address is equal to remote")
			}
			t.Logf("%s -> %s [%d]", p.Local.Addr, p.Remote.Addr, p.Priority)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			if err := b.Conclude(ctx); err != nil {
				t.Error(err)
			}
		}()
		if err := a.Conclude(ctx); err != nil {
			t.Error(err)
		}
	})
}
