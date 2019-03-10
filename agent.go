package ice

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	ct "github.com/gortc/ice/candidate"
	"github.com/gortc/stun"
)

// Role represents ICE agent role, which can be controlling or controlled.
type Role byte

// UnmarshalText implements TextUnmarshaler.
func (r *Role) UnmarshalText(text []byte) error {
	switch string(text) {
	case "controlling":
		*r = Controlling
	case "controlled":
		*r = Controlled
	default:
		return fmt.Errorf("unknown role %q", text)
	}
	return nil
}

// MarshalText implements TextMarshaler.
func (r Role) MarshalText() (text []byte, err error) {
	return []byte(r.String()), nil
}

func (r Role) String() string {
	switch r {
	case Controlling:
		return "controlling"
	case Controlled:
		return "controlled"
	default:
		return "unknown"
	}
}

// Possible ICE agent roles.
const (
	Controlling Role = iota
	Controlled
)

// contextKey is map key for candidate pair context.
type contextKey struct {
	LocalPort   int
	RemotePort  int
	LocalIP     [net.IPv6len]byte
	RemoteIP    [net.IPv6len]byte
	LocalProto  ct.Protocol
	RemoteProto ct.Protocol
}

// ChecklistSet represents ordered list of checklists.
type ChecklistSet []Checklist

const noChecklist = -1

type transactionID [stun.TransactionIDSize]byte

func (t transactionID) AddTo(m *stun.Message) error {
	m.TransactionID = t
	return nil
}

// agentTransaction represents transaction in progress.
//
// Concurrent access is invalid.
type agentTransaction struct {
	checklist int
	pair      int
	// id      transactionID
	// attempt int32
	// calls   int32
	// start   time.Time
	// rto     time.Duration
	// raw     []byte
	// ...
}

// Agent implements ICE Agent.
type Agent struct {
	set         ChecklistSet
	checklist   int // index in set or -1
	foundations [][]byte
	ctx         map[contextKey]context
	tiebreaker  uint64
	role        Role
	state       State
	rand        io.Reader
	t           map[transactionID]*agentTransaction
}

type ctxSTUNClient interface {
	Start(m *stun.Message) error
}

// context wraps resources for candidate.
type context struct {
	// STUN Agent, TURN client, socket, etc.
	stun ctxSTUNClient // local (client) -> remote (server)

	localUsername  string // LFRAG
	localPassword  string // LPASS
	remoteUsername string // RFRAG
	remotePassword string // RPASS

	localPref int // local candidate address preference
}

func (c *context) SendSTUN(m *stun.Message) error { return c.stun.Start(m) }

func (c *context) Close() error { return nil }

func (a *Agent) updateState() {
	var (
		state        = Running
		allCompleted = true
		allFailed    = true
	)
	for _, c := range a.set {
		switch c.State {
		case ChecklistFailed:
			allCompleted = false
		case ChecklistCompleted:
			allFailed = false
		default:
			allFailed = false
			allCompleted = false
		}
	}
	if allCompleted {
		state = Completed
	} else if allFailed {
		state = Failed
	}
	a.state = state
}

func pairContextKey(p *Pair) contextKey {
	k := contextKey{
		LocalProto:  p.Local.Addr.Proto,
		LocalPort:   p.Local.Addr.Port,
		RemoteProto: p.Remote.Addr.Proto,
		RemotePort:  p.Remote.Addr.Port,
	}
	copy(k.LocalIP[:], p.Remote.Addr.IP)
	copy(k.RemoteIP[:], p.Remote.Addr.IP)
	return k
}

var (
	errFingerprintNotFound = errors.New("STUN message fingerprint attribute not found")
	errRoleConflict        = errors.New("role conflict")
)

type unexpectedResponseTypeErr struct{ Type stun.MessageType }

func (e unexpectedResponseTypeErr) Error() string {
	return fmt.Sprintf("peer responded with unexpected STUN message %s", e.Type)
}

type unrecoverableErrorCodeErr struct{ Code stun.ErrorCode }

func (e unrecoverableErrorCodeErr) Error() string {
	return fmt.Sprintf("peer responded with unrecoverable error code %d", e.Code)
}

var errPeerReflexiveNotImplemented = errors.New("adding peer-reflexive candidates is not implemented")

func (a *Agent) addPeerReflexive(p *Pair, addr Addr) error {
	// TODO: Implement.
	// See https://tools.ietf.org/html/rfc8445#section-7.2.5.3.1
	log.Println("peer reflexive:", p, addr)
	return errPeerReflexiveNotImplemented
}

const maxPairFoundationBytes = 64

type foundationKey [maxPairFoundationBytes]byte

type foundationSet map[foundationKey]struct{}

func getFoundationKey(f []byte) foundationKey {
	k := foundationKey{}
	copy(k[:], f)
	return k
}

func assertFoundationLength(f []byte) {
	if len(f) > maxPairFoundationBytes {
		panic("length of foundation is greater that maximum")
	}
}

func (s foundationSet) Contains(f []byte) bool {
	assertFoundationLength(f)
	_, ok := s[getFoundationKey(f)]
	return ok
}

func (s foundationSet) Add(f []byte) {
	assertFoundationLength(f)
	s[getFoundationKey(f)] = struct{}{}
}

func (a *Agent) setPairState(checklist, pair int, state PairState) {
	c := a.set[checklist]
	p := c.Pairs[pair]
	p.State = state
	c.Pairs[pair] = p
	a.set[checklist] = c
}

var (
	errNoPair      = errors.New("no pair in checklist can be picked")
	errNoChecklist = errors.New("no checklist is active")
)

const noPair = -1

func (a *Agent) pickPair() (pairID int, err error) {
	if a.checklist == noChecklist {
		return noPair, errNoChecklist
	}
	// Step 1. Picking from triggered startCheck queue.
	// TODO: Implement triggered-startCheck queue.
	// Step 2. Handling frozen pairs.
	pairs := a.set[a.checklist].Pairs
	anyWaiting := false
	for id := range pairs {
		if pairs[id].State == PairWaiting {
			anyWaiting = true
			break
		}
	}
	if !anyWaiting {
		foundations := make(foundationSet)
		for _, checklist := range a.set {
			for id := range checklist.Pairs {
				if checklist.Pairs[id].State.In(PairInProgress, PairWaiting) {
					foundations.Add(checklist.Pairs[id].Foundation)
				}
			}
		}
		for id := range pairs {
			if pairs[id].State != PairFrozen {
				continue
			}
			if foundations.Contains(pairs[id].Foundation) {
				continue
			}
			a.setPairState(a.checklist, id, PairWaiting)
			break // to step 3
		}
	}
	// Step 3. Looking for waiting pairs.
	for id := range pairs {
		if pairs[id].State == PairWaiting {
			a.setPairState(a.checklist, id, PairInProgress)
			return id, nil
		}
	}
	// Step 4. No check could be performed.
	return noPair, errNoPair
}

var errNotSTUN = errors.New("packet is not STUN")

func (a *Agent) processUDP(buf []byte, addr net.UDPAddr) error {
	if !stun.IsMessage(buf) {
		return errNotSTUN
	}
	m := &stun.Message{Raw: buf}
	if err := m.Decode(); err != nil {
		return err
	}
	t, ok := a.t[m.TransactionID]
	if !ok {
		// Transaction is not found.
		return nil
	}
	p := a.set[t.checklist].Pairs[t.pair]
	switch m.Type {
	case stun.BindingSuccess, stun.BindingError:
		return a.processBindingResponse(&p, m, Addr{Port: addr.Port, IP: addr.IP, Proto: ct.UDP})
	}
	return nil
}

var errNonSymmetricAddr = errors.New("peer address is not symmetric")

func (a *Agent) handleBindingResponse(t *agentTransaction, p *Pair, m *stun.Message, raddr Addr) {
	if err := a.processBindingResponse(p, m, raddr); err != nil {
		a.setPairState(t.checklist, t.pair, PairFailed)
		return
	}
	a.setPairState(t.checklist, t.pair, PairSucceeded)
}

func (a *Agent) processBindingResponse(p *Pair, m *stun.Message, raddr Addr) error {
	ctx := a.ctx[pairContextKey(p)]
	integrity := stun.NewShortTermIntegrity(ctx.remotePassword)
	if err := stun.Fingerprint.Check(m); err != nil {
		if err == stun.ErrAttributeNotFound {
			return errFingerprintNotFound
		}
		return err
	}
	if err := integrity.Check(m); err != nil {
		return err
	}
	if !raddr.Equal(p.Remote.Addr) {
		return errNonSymmetricAddr
	}
	if m.Type == stun.BindingError {
		var errCode stun.ErrorCodeAttribute
		if err := errCode.GetFrom(m); err != nil {
			return err
		}
		if errCode.Code == stun.CodeRoleConflict {
			return errRoleConflict
		}
		return unrecoverableErrorCodeErr{Code: errCode.Code}
	}
	if m.Type != stun.BindingSuccess {
		return unexpectedResponseTypeErr{Type: m.Type}
	}
	var xAddr stun.XORMappedAddress
	if err := xAddr.GetFrom(m); err != nil {
		return fmt.Errorf("can't get xor mapped address: %v", err)
	}
	addr := Addr{
		IP:    xAddr.IP,
		Port:  xAddr.Port,
		Proto: p.Local.Addr.Proto,
	}
	// TODO: Check all other local addresses.
	if !addr.Equal(p.Local.Addr) {
		if err := a.addPeerReflexive(p, addr); err != nil {
			return err
		}
	}
	return nil
}

// startCheck initializes connectivity check for pair.
func (a *Agent) startCheck(p *Pair) error {
	// Once the agent has picked a candidate pair for which a connectivity
	// check is to be performed, the agent starts a check and sends the
	// Binding request from the base associated with the local candidate of
	// the pair to the remote candidate of the pair, as described in
	// Section 7.2.4.
	ctx := a.ctx[pairContextKey(p)]
	// See RFC 8445 Section 7.2.2. Forming Credentials.
	integrity := stun.NewShortTermIntegrity(ctx.remotePassword)
	// The PRIORITY attribute MUST be included in a Binding request and be
	// set to the value computed by the algorithm in Section 5.1.2 for the
	// local candidate, but with the candidate type preference of peer-
	// reflexive candidates.
	priority := PriorityAttr(Priority(TypePreference(ct.PeerReflexive), ctx.localPref, p.Local.ComponentID))
	role := AttrControl{Role: a.role, Tiebreaker: a.tiebreaker}
	username := stun.NewUsername(ctx.remoteUsername + ":" + ctx.localUsername)
	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest,
		&username, &priority, &role,
		&integrity, stun.Fingerprint,
	)
	return ctx.stun.Start(m)
}

func randUint64(r io.Reader) (uint64, error) {
	buf := make([]byte, 8)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf), nil
}

func (a *Agent) nextChecklist() (c Checklist, id int) {
	if a.checklist == noChecklist {
		for id, c = range a.set {
			if c.State == ChecklistRunning {
				return c, id
			}
		}
		return Checklist{}, noChecklist
	}
	// Picking checklist
	i := a.checklist + 1
	for {
		if i >= len(a.set) {
			i = 0
		}
		if a.set[i].State == ChecklistRunning {
			return a.set[i], i
		}
		if i == a.checklist {
			// Made a circle, nothing found.
			return Checklist{}, noChecklist
		}
		i++
	}
}

// init sets initial states for checklist sets.
func (a *Agent) init() error {
	if a.t == nil {
		a.t = make(map[transactionID]*agentTransaction)
	}
	if a.rand == nil {
		a.rand = rand.Reader
	}
	if a.ctx == nil {
		a.ctx = make(map[contextKey]context)
	}
	// Generating random tiebreaker number.
	tbValue, err := randUint64(a.rand)
	if err != nil {
		return err
	}
	a.tiebreaker = tbValue
	// Gathering all unique foundations.
	foundations := make(foundationSet)
	for _, c := range a.set {
		for i := range c.Pairs {
			pair := c.Pairs[i]
			if foundations.Contains(pair.Foundation) {
				continue
			}
			// Initializing context.
			k := pairContextKey(&pair)
			a.ctx[k] = context{}
			foundations.Add(pair.Foundation)
			a.foundations = append(a.foundations, pair.Foundation)
		}
	}
	// For each foundation, the agent sets the state of exactly one
	// candidate pair to the Waiting state (unfreezing it).  The
	// candidate pair to unfreeze is chosen by finding the first
	// candidate pair (ordered by the lowest component ID and then the
	// highest priority if component IDs are equal) in the first
	// checklist (according to the usage-defined checklist set order)
	// that has that foundation.
	for _, f := range a.foundations {
		for _, c := range a.set {
			for i := range c.Pairs {
				if !bytes.Equal(c.Pairs[i].Foundation, f) {
					continue
				}
				c.Pairs[i].State = PairWaiting
				break
			}
		}
	}
	a.checklist = noChecklist
	return nil
}
