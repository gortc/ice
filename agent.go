package ice

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	ct "github.com/gortc/ice/candidate"
	"github.com/gortc/ice/gather"
	"github.com/gortc/stun"
	"github.com/gortc/turn"
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
	pair      pairKey
	priority  int
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

// Server represents ICE server (TURN or STUN) which will be used for
// connectivity establishment.
type Server struct {
	URI        []string // STUN or TURN URI list
	Username   string
	Credential string
}

const defaultMaxChecks = 100

// NewAgent initializes new ICE agent using provided options and returns error
// if any.
func NewAgent(opts ...AgentOption) (*Agent, error) {
	a := &Agent{
		gatherer:  systemCandidateGatherer{addr: gather.DefaultGatherer},
		maxChecks: defaultMaxChecks,
		ta:        defaultAgentTa,
	}
	for _, o := range opts {
		if err := o(a); err != nil {
			return nil, err
		}
	}
	if err := a.init(); err != nil {
		return nil, err
	}
	return a, nil
}

type stunServerOptions struct {
	uri      stun.URI
	username string
	password string
}

type turnServerOptions struct {
	uri      turn.URI
	username string
	password string
}

// Agent implements ICE Agent.
type Agent struct {
	set              ChecklistSet
	checklist        int // index in set or -1
	foundations      [][]byte
	tiebreaker       uint64
	role             Role
	state            State
	ipv4Only         bool
	rand             io.Reader
	t                map[transactionID]*agentTransaction
	tMux             sync.Mutex
	localCandidates  [][]*localUDPCandidate
	remoteCandidates [][]Candidate
	gatherer         candidateGatherer
	log              *zap.Logger
	mux              sync.Mutex

	localUsername  string
	localPassword  string
	remoteUsername string
	remotePassword string

	maxChecks int
	ta        time.Duration // section 15.2, Ta

	turn []turnServerOptions
	stun []stunServerOptions
}

// SetLocalCredentials sets local username fragment and password.
func (a *Agent) SetLocalCredentials(username, password string) {
	a.localUsername = username
	a.localPassword = password
}

// Username returns local username fragment.
func (a *Agent) Username() string { return a.localUsername }

// Password returns local password.
func (a *Agent) Password() string { return a.localPassword }

// SetRemoteCredentials sets ufrag and password for remote candidate.
func (a *Agent) SetRemoteCredentials(username, password string) {
	a.remoteUsername = username
	a.remotePassword = password
}

// tick of ta.
func (a *Agent) tick(t time.Time, metChecklists map[int]bool) error {
	a.mux.Lock()
	if a.checklist == noChecklist {
		_, cID := a.nextChecklist()
		if cID == noChecklist {
			a.mux.Unlock()
			return errNoChecklist
		}
		a.checklist = cID
	}
	if a.shouldNominate(a.checklist) {
		if err := a.startNomination(a.checklist); err != nil {
			a.mux.Unlock()
			return err
		}
	}
	pair, err := a.pickPair()
	if err != nil {
		a.log.Debug("pickPair", zap.Error(err))
	} else {
		a.log.Debug("pickPair OK")
	}
	if err == errNoPair || err == errNoChecklist {
		metChecklists[a.checklist] = true
		_, cID := a.nextChecklist()
		if cID == noChecklist || metChecklists[cID] {
			a.mux.Unlock()
			return errNoChecklist
		}
		a.checklist = cID
		a.mux.Unlock()
		return a.tick(t, metChecklists)
	}
	if err != nil {
		a.mux.Unlock()
		return err
	}
	a.mux.Unlock()
	return a.startCheck(pair, t)
}

// Conclude starts connectivity checks and returns when ICE is fully concluded.
func (a *Agent) Conclude(ctx context.Context) error {
	// TODO: Start async job.
	ticker := time.NewTicker(a.ta)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			if err := a.tick(t, make(map[int]bool)); err != nil {
				return err
			}
			a.mux.Lock()
			state := a.state
			a.mux.Unlock()
			if state == Completed {
				a.log.Debug("concluded")
				return nil
			}
			if state == Failed {
				return errors.New("failed")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (a *Agent) localCandidateByAddr(addr Addr) (candidate *localUDPCandidate, ok bool) {
	for _, cs := range a.localCandidates {
		for i := range cs {
			if addr.Equal(cs[i].candidate.Addr) {
				return cs[i], true
			}
		}
	}
	return nil, false
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

// LocalCandidates returns list of local candidates for first data stream.
func (a *Agent) LocalCandidates() ([]Candidate, error) {
	return a.LocalCandidatesForStream(defaultStreamID)
}

var errNoStreamFound = errors.New("data stream with provided id not found")

// LocalCandidatesForStream returns list of local candidates for stream.
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

// AddRemoteCandidatesForStream adds remote candidate list, associating
// them with data stream with provided id.
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
	a.mux.Lock()
	for _, c := range a.set {
		for i := range c.Pairs {
			total++
			if c.Pairs[i].State.In(PairWaiting, PairInProgress) {
				n++
			}
		}
	}
	a.mux.Unlock()
	rto := time.Duration(total*n) * a.ta
	if rto < minRTO {
		rto = minRTO
	}
	return rto
}

const defaultAgentTa = time.Millisecond * 50

func (a *Agent) updateState() {
	var (
		state        = Running
		allCompleted = true
		allFailed    = true
	)
	for streamID, c := range a.set {
		if a.concluded(streamID) {
			a.log.Debug("checklist concluded", zap.Int("stream", streamID))
			c.State = ChecklistCompleted
			a.set[streamID] = c
		}
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

var errCandidateNotFound = errors.New("candidate not found")

func (a *Agent) addPeerReflexive(t *agentTransaction, p *Pair, addr Addr) error {
	// See https://tools.ietf.org/html/rfc8445#section-7.2.5.3.1
	pr := Candidate{
		Type:     ct.PeerReflexive,
		Base:     p.Local.Addr,
		Addr:     addr,
		Priority: t.priority,
	}
	pr.Foundation = Foundation(&pr, Addr{})
	a.mux.Lock()
	defer a.mux.Unlock()
	c, ok := a.localCandidateByAddr(p.Local.Addr)
	if !ok {
		return errCandidateNotFound
	}
	a.localCandidates[c.stream] = append(a.localCandidates[c.stream], &localUDPCandidate{
		conn:      c.conn,
		candidate: pr,
		stream:    c.stream,
	})
	return nil
}

func (a *Agent) setPairState(checklist, pair int, state PairState) {
	c := a.set[checklist]
	p := c.Pairs[pair]
	p.State = state
	c.Pairs[pair] = p
	a.set[checklist] = c
}

func (a *Agent) setPairStateByKey(checklist int, k pairKey, state PairState) {
	c := a.set[checklist]
	for i := range c.Pairs {
		if k.Equal(&c.Pairs[i]) {
			c.Pairs[i].State = state
			break
		}
	}
	a.set[checklist] = c
}

var (
	errNoPair      = errors.New("no pair in checklist can be picked")
	errNoChecklist = errors.New("no checklist is active")
)

func (a *Agent) pickPair() (*Pair, error) {
	if a.checklist == noChecklist {
		return nil, errNoChecklist
	}
	// Step 1. Picking from triggered check queue.
	if len(a.set[a.checklist].Triggered) > 0 {
		// FIFO. Picking top first.
		triggered := a.set[a.checklist].Triggered
		pair := triggered[len(triggered)-1]
		pair.State = PairInProgress
		triggered = triggered[:len(triggered)-1]
		a.set[a.checklist].Triggered = triggered
		return &pair, nil
	}
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
			return &pairs[id], nil
		}
	}
	// Step 4. No check could be performed.
	return nil, errNoPair
}

var errNotSTUNMessage = errors.New("packet is not STUN Message")

func (a *Agent) getPair(streamID int, k pairKey) (*Pair, bool) {
	set := a.set[streamID]
	for i := range set.Pairs {
		if k.Equal(&set.Pairs[i]) {
			return &set.Pairs[i], true
		}
	}
	return nil, false
}

func (a *Agent) processUDP(buf []byte, c *localUDPCandidate, addr *net.UDPAddr) error {
	a.log.Debug("got udp packet",
		zap.Stringer("local", c.candidate.Addr),
		zap.Stringer("from", addr),
	)
	if !stun.IsMessage(buf) {
		return errNotSTUNMessage
	}
	m := &stun.Message{Raw: buf}
	if err := m.Decode(); err != nil {
		return err
	}
	a.log.Debug("got message", zap.Stringer("m", m))
	raddr := Addr{Port: addr.Port, IP: addr.IP, Proto: ct.UDP}
	if m.Type == stun.BindingRequest {
		return a.handleBindingRequest(m, c, raddr)
	}

	a.tMux.Lock()
	t, ok := a.t[m.TransactionID]
	a.tMux.Unlock()

	if !ok {
		// Transaction is not found.
		a.log.Debug("transaction not found")
		return nil
	}

	a.mux.Lock()
	p, _ := a.getPair(t.checklist, t.pair)
	a.mux.Unlock()

	switch m.Type {
	case stun.BindingSuccess, stun.BindingError:
		return a.handleBindingResponse(t, p, m, raddr)
	default:
		a.log.Debug("unknown message type", zap.Stringer("t", m.Type))
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

var errNonSymmetricAddr = errors.New("peer address is not symmetric")

func samePair(a, b *Pair) bool {
	if a.ComponentID != b.ComponentID {
		return false
	}
	if !a.Local.Addr.Equal(b.Local.Addr) {
		return false
	}
	if !a.Remote.Addr.Equal(b.Remote.Addr) {
		return false
	}
	return true
}

func (a *Agent) concluded(streamID int) bool {
	s := a.set[streamID]
	if len(s.Valid) == 0 {
		return false
	}
	comps := make(map[int]bool)
	for i := range s.Pairs {
		comps[s.Pairs[i].ComponentID] = true
	}
	nominatedComps := make(map[int]bool)
	for i := range s.Valid {
		if s.Valid[i].Nominated {
			continue
		}
		nominatedComps[s.Valid[i].ComponentID] = true
	}
	return len(comps) == len(nominatedComps)
}

func (a *Agent) shouldNominate(streamID int) bool {
	s := a.set[streamID]
	if len(s.Valid) == 0 {
		return false
	}
	comps := make(map[int]bool)
	for i := range s.Pairs {
		comps[s.Pairs[i].ComponentID] = true
	}
	for i := range s.Valid {
		if !comps[s.Valid[i].ComponentID] {
			return false
		}
	}
	// TODO: Improve stopping criterion.
	return true
}

func (a *Agent) startNomination(streamID int) error {
	s := a.set[streamID]
	for i := range s.Valid {
		if s.Valid[i].Nominated {
			continue
		}
		pair := s.Valid[i]
		pair.Nominated = true
		s.Triggered = append(s.Triggered, pair)
		a.set[streamID] = s
		a.log.Debug("starting nomination")
		return nil
	}
	return errNoPair
}

// startCheck initializes connectivity check for pair.
func (a *Agent) startCheck(p *Pair, t time.Time) error {
	a.log.Debug("startCheck",
		zap.Stringer("remote", p.Remote.Addr),
		zap.Stringer("local", p.Local.Addr),
		zap.Int("component", p.ComponentID),
	)

	// Once the agent has picked a candidate pair for which a connectivity
	// check is to be performed, the agent starts a check and sends the
	// Binding request from the base associated with the local candidate of
	// the pair to the remote candidate of the pair, as described in
	// Section 7.2.4.
	// See RFC 8445 Section 7.2.2. Forming Credentials.
	integrity := stun.NewShortTermIntegrity(a.remotePassword)
	// The PRIORITY attribute MUST be included in a Binding request and be
	// set to the value computed by the algorithm in Section 5.1.2 for the
	// local candidate, but with the candidate type preference of peer-
	// reflexive candidates.
	localPref := p.Local.LocalPreference
	priority := Priority(TypePreference(ct.PeerReflexive), localPref, p.Local.ComponentID)
	role := AttrControl{Role: a.role, Tiebreaker: a.tiebreaker}
	username := stun.NewUsername(a.remoteUsername + ":" + a.localUsername)
	attrs := []stun.Setter{
		stun.TransactionID, stun.BindingRequest,
		&username, PriorityAttr(priority), &role,
	}
	if p.Nominated {
		attrs = append(attrs, UseCandidate)
	}
	attrs = append(attrs, &integrity, stun.Fingerprint)
	m := stun.MustBuild(attrs...)
	return a.startBinding(p, m, priority, t)
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
	if a.log == nil {
		a.log = zap.NewNop()
	}
	if a.ta == 0 {
		a.ta = defaultAgentTa
	}
	if a.t == nil {
		a.t = make(map[transactionID]*agentTransaction)
	}
	if a.rand == nil {
		a.rand = rand.Reader
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
