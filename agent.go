package ice

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	ct "github.com/gortc/ice/candidate"
	"github.com/gortc/ice/gather"
	"github.com/gortc/stun"

	"go.uber.org/zap"
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

// contextKey is map key for candidate pair candidateCtx.
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
	pairKey   contextKey
	checklist int
	pair      int
	nominate  bool
	id        transactionID
	start     time.Time
	rto       time.Duration
	deadline  time.Time
	raw       []byte
	// attempt int32
	// calls   int32
	// start   time.Time
	// rto     time.Duration
	// raw     []byte
	// ...
}

type AgentOption func(a *Agent)

func withGatherer(g candidateGatherer) AgentOption {
	return func(a *Agent) { a.gatherer = g }
}

// WithRole sets agent mode to Controlling or Controlled.
func WithRole(r Role) AgentOption {
	return func(a *Agent) {
		a.role = r
	}
}

const defaultMaxChecks = 100

func NewAgent(opts ...AgentOption) (*Agent, error) {
	a := &Agent{
		gatherer:  systemCandidateGatherer{addr: gather.DefaultGatherer},
		maxChecks: defaultMaxChecks,
		ta:        defaultAgentTa,
	}
	for _, o := range opts {
		o(a)
	}
	if err := a.init(); err != nil {
		return nil, err
	}
	return a, nil
}

type localUDPCandidate struct {
	log        *zap.Logger
	candidate  Candidate
	preference int
	conn       net.PacketConn
	stream     int
}

func (c *localUDPCandidate) Close() error {
	return c.conn.Close()
}

func (c *localUDPCandidate) readUntilClose(a *Agent) {
	buf := make([]byte, 1024)
	for {
		n, addr, err := c.conn.ReadFrom(buf)
		if err != nil {
			break
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			break
		}
		if err := a.processUDP(buf[:n], c, udpAddr); err != nil {
			c.log.Error("processUDP failed", zap.Error(err))
		}
	}
}

type gathererOptions struct {
	Components int
}

type candidateGatherer interface {
	gatherUDP(opt gathererOptions) ([]localUDPCandidate, error)
}

// Agent implements ICE Agent.
type Agent struct {
	set              ChecklistSet
	checklist        int // index in set or -1
	foundations      [][]byte
	ctx              map[contextKey]candidateCtx
	tiebreaker       uint64
	role             Role
	state            State
	rand             io.Reader
	t                map[transactionID]*agentTransaction
	localCandidates  [][]localUDPCandidate
	remoteCandidates [][]Candidate
	gatherer         candidateGatherer

	maxChecks int
	ta        time.Duration // section 15.2, Ta
}

// tick of ta.
func (a *Agent) tick(t time.Time) error {
	pID, err := a.pickPair()
	if err == errNoPair {
		_, cID := a.nextChecklist()
		if cID == noChecklist {
			return errNoChecklist
		}
		a.checklist = cID
		return a.tick(t)
	}
	pair := a.set[a.checklist].Pairs[pID]
	a.setPairState(a.checklist, pID, PairInProgress)
	return a.startCheck(&pair, t)
}

// Conclude starts connectivity checks and returns when ICE is fully concluded.
func (a *Agent) Conclude(ctx context.Context) error {
	// TODO: Start async job.
	ticker := time.NewTicker(a.ta)
	for t := range ticker.C {
		if err := a.tick(t); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) localCandidateByAddr(addr Addr) (candidate localUDPCandidate, ok bool) {
	for _, cs := range a.localCandidates {
		for i := range cs {
			if addr.Equal(cs[i].candidate.Addr) {
				return cs[i], true
			}
		}
	}
	return localUDPCandidate{}, false
}

// Close immediately stops all transactions and frees underlying resources.
func (a *Agent) Close() error {
	for _, streamCandidates := range a.localCandidates {
		for i := range streamCandidates {
			_ = streamCandidates[i].conn.Close()
		}
	}
	return nil
}

// GatherCandidates gathers local candidates for single data stream.
func (a *Agent) GatherCandidates() error {
	return a.GatherCandidatesForStream(defaultStreamID)
}

var errStreamAlreadyExist = errors.New("data stream with provided id exists")

const defaultStreamID = 0

// GatherCandidatesForStream allows gathering candidates for multiple streams.
// The streamID is integer that starts from zero.
func (a *Agent) GatherCandidatesForStream(streamID int) error {
	if len(a.localCandidates) > streamID {
		return errStreamAlreadyExist
	}
	candidates, err := a.gatherer.gatherUDP(gathererOptions{Components: 1})
	if err != nil {
		return err
	}
	for i := range candidates {
		go candidates[i].readUntilClose(a)
	}
	a.localCandidates = append(a.localCandidates, candidates)
	return nil
}

// LocalCandidates returns list of local candidates for first data stream.
func (a *Agent) LocalCandidates() ([]Candidate, error) {
	return a.LocalCandidatesForStream(defaultStreamID)
}

var errNoStreamFound = errors.New("data stream with provided id not found")

// LocalCandidates returns list of local candidates for stream.
func (a *Agent) LocalCandidatesForStream(streamID int) ([]Candidate, error) {
	if len(a.localCandidates) <= streamID {
		return nil, errNoStreamFound
	}
	var localCandidates []Candidate
	for i := range a.localCandidates[streamID] {
		localCandidates = append(localCandidates, a.localCandidates[streamID][i].candidate)
	}
	return localCandidates, nil
}

// AddRemoteCandidates adds remote candidate list, associating them with first data
// stream.
func (a *Agent) AddRemoteCandidates(c []Candidate) error {
	return a.AddRemoteCandidatesForStream(defaultStreamID, c)
}

func (a *Agent) AddRemoteCandidatesForStream(streamID int, c []Candidate) error {
	if len(a.remoteCandidates) > streamID {
		return errStreamAlreadyExist
	}
	a.remoteCandidates = append(a.remoteCandidates, c)
	return nil
}

var errStreamCountMismatch = errors.New("remote and local stream count mismatch")

// PrepareChecklistSet initializes checklists for each data stream, generating
// candidate pairs for each local and remote candidates.
func (a *Agent) PrepareChecklistSet() error {
	if len(a.remoteCandidates) != len(a.localCandidates) {
		return errStreamCountMismatch
	}
	for streamID := 0; streamID < len(a.localCandidates); streamID++ {
		var localCandidates []Candidate
		for i := range a.localCandidates[streamID] {
			localCandidates = append(localCandidates, a.localCandidates[streamID][i].candidate)
		}
		pairs := NewPairs(localCandidates, a.remoteCandidates[streamID])
		list := Checklist{Pairs: pairs}
		list.ComputePriorities(a.role)
		list.Sort()
		list.Prune()
		list.Limit(a.maxChecks)
		a.set = append(a.set, list)
	}
	return a.init()
}

const minRTO = time.Millisecond * 500

// rto calculates RTO based on pairs in checklist set and number of connectivity checks.
func (a *Agent) rto() time.Duration {
	// See Section 14.3, RTO.
	// RTO = MAX (500ms, Ta * N * (Num-Waiting + Num-In-Progress))
	var n, total int
	for _, c := range a.set {
		for i := range c.Pairs {
			total++
			if c.Pairs[i].State.In(PairWaiting, PairInProgress) {
				n++
			}
		}
	}
	rto := time.Duration(total*n) * a.ta
	if rto < minRTO {
		rto = minRTO
	}
	return rto
}

const defaultAgentTa = time.Millisecond * 50

// candidateCtx wraps resources for candidate.
type candidateCtx struct {
	localUsername  string // LFRAG
	localPassword  string // LPASS
	remoteUsername string // RFRAG
	remotePassword string // RPASS

	localPref int // local candidate address preference
}

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
	// Step 1. Picking from triggered check queue.
	// TODO: Implement triggered-check queue.
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

var errNotSTUNMessage = errors.New("packet is not STUN Message")

func (a *Agent) processUDP(buf []byte, c *localUDPCandidate, addr *net.UDPAddr) error {
	if !stun.IsMessage(buf) {
		return errNotSTUNMessage
	}
	m := &stun.Message{Raw: buf}
	if err := m.Decode(); err != nil {
		return err
	}
	raddr := Addr{Port: addr.Port, IP: addr.IP, Proto: ct.UDP}
	if m.Type == stun.BindingRequest {
		return a.handleBindingRequest(m, c, raddr)
	}
	t, ok := a.t[m.TransactionID]
	if !ok {
		// Transaction is not found.
		return nil
	}
	p := a.set[t.checklist].Pairs[t.pair]
	switch m.Type {
	case stun.BindingSuccess, stun.BindingError:
		return a.handleBindingResponse(t, &p, m, raddr)
	}
	return nil
}

func (a *Agent) remoteCandidateByAddr(addr Addr) (Candidate, bool) {
	for _, s := range a.remoteCandidates {
		for i := range s {
			if s[i].Addr.Equal(addr) {
				return s[i], true
			}
		}
	}
	return Candidate{}, false
}

func (a *Agent) handleBindingRequest(m *stun.Message, c *localUDPCandidate, raddr Addr) error {
	if err := stun.Fingerprint.Check(m); err != nil {
		return err
	}
	remoteCandidate, ok := a.remoteCandidateByAddr(raddr)
	if !ok {
		return errCandidateNotFound
	}
	pair := Pair{
		Local:  c.candidate,
		Remote: remoteCandidate,
	}
	pair.SetFoundation()
	pair.SetPriority(a.role)
	list := a.set[c.stream]
	list.Pairs = append(list.Pairs, pair)
	list.Sort()
	return nil
}

var errNonSymmetricAddr = errors.New("peer address is not symmetric")

func (a *Agent) handleBindingResponse(t *agentTransaction, p *Pair, m *stun.Message, raddr Addr) error {
	if err := a.processBindingResponse(p, m, raddr); err != nil {
		// TODO: Handle nomination failure.
		a.setPairState(t.checklist, t.pair, PairFailed)
		return err
	}
	a.setPairState(t.checklist, t.pair, PairSucceeded)
	// Adding to valid list.
	// TODO: Construct valid pair as in https://tools.ietf.org/html/rfc8445#section-7.2.5.3.2
	// Handling case "1" only, when valid pair is equal to generated pair p.
	validPair := *p
	cl := a.set[t.checklist]

	// Setting all candidate paris with same foundation to "Waiting".
	for cID, c := range a.set {
		for i := range c.Pairs {
			if bytes.Equal(c.Pairs[i].Foundation, p.Foundation) {
				a.setPairState(cID, i, PairWaiting)
				continue
			}
			if bytes.Equal(c.Pairs[i].Foundation, validPair.Foundation) {
				a.setPairState(cID, i, PairWaiting)
			}
		}
	}

	// Nominating.
	if t.nominate {
		validPair.Nominated = true
	}
	cl.Valid = append(cl.Valid, validPair)
	a.set[t.checklist] = cl

	// Updating checklist states.
	a.updateState()
	return nil
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
		// TODO: Copy xAddr.IP, the *m attribute values should not be held.
		if err := a.addPeerReflexive(p, addr); err != nil {
			return err
		}
	}
	return nil
}

var errCandidateNotFound = errors.New("candidate not found")
var errUnsupportedProtocol = errors.New("protocol not supported")

func (a *Agent) startBinding(p *Pair, m *stun.Message, t time.Time) error {
	if p.Remote.Addr.Proto != ct.UDP {
		return errUnsupportedProtocol
	}
	c, ok := a.localCandidateByAddr(p.Local.Addr)
	if !ok {
		return errCandidateNotFound
	}
	rto := a.rto()
	a.t[m.TransactionID] = &agentTransaction{
		id:        m.TransactionID,
		start:     t,
		rto:       rto,
		deadline:  t.Add(rto),
		pairKey:   pairContextKey(p),
		raw:       m.Raw,
		checklist: a.checklist,
	}
	udpAddr := &net.UDPAddr{
		IP:   p.Remote.Addr.IP,
		Port: p.Remote.Addr.Port,
	}
	_, err := c.conn.WriteTo(m.Raw, udpAddr)
	// TODO: Add write deadline.
	// TODO: Check n if needed.
	if err != nil {
		return err
	}
	return nil
}

// startCheck initializes connectivity check for pair.
func (a *Agent) startCheck(p *Pair, t time.Time) error {
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
	return a.startBinding(p, m, t)
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
	if a.ta == 0 {
		a.ta = defaultAgentTa
	}
	if a.t == nil {
		a.t = make(map[transactionID]*agentTransaction)
	}
	if a.rand == nil {
		a.rand = rand.Reader
	}
	if a.ctx == nil {
		a.ctx = make(map[contextKey]candidateCtx)
	}
	// Generating random tiebreaker number.
	tbValue, err := randUint64(a.rand)
	if err != nil {
		return err
	}
	a.tiebreaker = tbValue
	a.foundations = a.foundations[:0]
	// Gathering all unique foundations.
	foundations := make(foundationSet)
	for _, c := range a.set {
		for i := range c.Pairs {
			pair := c.Pairs[i]
			if foundations.Contains(pair.Foundation) {
				continue
			}
			// Initializing candidateCtx.
			k := pairContextKey(&pair)
			a.ctx[k] = candidateCtx{}
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
