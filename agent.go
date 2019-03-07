package ice

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/gortc/stun"

	ct "github.com/gortc/ice/candidate"
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

// contextKey is map key for candidate context.
type contextKey struct {
	IP    [net.IPv6len]byte
	Proto ct.Protocol
	Port  int
}

// ChecklistSet represents ordered list of checklists.
type ChecklistSet []Checklist

const maxFoundationLength = 64

// Agent implements ICE Agent.
type Agent struct {
	set         ChecklistSet
	foundations [][]byte
	ctx         map[contextKey]context
	tieBreaker  uint64
	role        Role
	state       State
	rand        io.Reader
}

type ctxSTUNClient interface {
	Do(m *stun.Message, f func(stun.Event)) error
}

// context wraps resources for candidate.
type context struct {
	// STUN Agent, TURN client, socket, etc.
	stun ctxSTUNClient // local (client) -> remote (server)

	localUsername  string // LFRAG
	localPassword  string // LPASS
	remoteUsername string // RFRAG
	remotePassword string // RPASS
}

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

type foundationKey [maxFoundationLength]byte

func pairContextKey(p *Pair) contextKey {
	k := contextKey{
		Proto: p.Local.Addr.Proto,
		Port:  p.Local.Addr.Port,
	}
	copy(k.IP[:], p.Local.Addr.IP)
	return k
}

// check performs connectivity check for pair.
func (a *Agent) check(p *Pair) error {
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
	priority := PriorityAttr(p.Local.Priority) // TODO(ar): compute as peer-reflexive
	var tieBreakerAttr stun.Setter = AttrControlling(a.tieBreaker)
	if a.role == Controlled {
		tieBreakerAttr = AttrControlled(a.tieBreaker)
	}
	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest,
		stun.NewUsername(ctx.remoteUsername+":"+ctx.localUsername), priority, tieBreakerAttr,
		integrity, stun.Fingerprint,
	)
	var bindingErr error
	doErr := ctx.stun.Do(m, func(event stun.Event) {
		if event.Error != nil {
			bindingErr = event.Error
			return
		}
		if event.Message.Type == stun.BindingError {
			var errCode stun.ErrorCodeAttribute
			if bindingErr = errCode.GetFrom(m); bindingErr != nil {
				return
			}
			if errCode.Code == stun.CodeRoleConflict {
				bindingErr = errors.New("role conflict")
				return
			}
			bindingErr = fmt.Errorf("error %s", errCode)
			return
		}
		if event.Message.Type != stun.BindingSuccess {
			bindingErr = fmt.Errorf("bad responce message type: %s", event.Message.Type)
			return
		}
	})
	if doErr != nil {
		return doErr
	}
	if bindingErr != nil {
		return bindingErr
	}
	return nil
}

func randUint64(r io.Reader) (uint64, error) {
	buf := make([]byte, 8)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf), nil
}

// init sets initial states for checklist sets.
func (a *Agent) init() error {
	if a.rand == nil {
		a.rand = rand.Reader
	}
	if a.ctx == nil {
		a.ctx = make(map[contextKey]context)
	}
	// Generating random tie-breaker number.
	tbValue, err := randUint64(a.rand)
	if err != nil {
		return err
	}
	a.tieBreaker = tbValue
	// Gathering all unique foundations.
	foundations := make(map[foundationKey]struct{})
	for _, c := range a.set {
		for i := range c.Pairs {
			// Initializing context.
			k := pairContextKey(&c.Pairs[i])
			a.ctx[k] = context{}

			f := c.Pairs[i].Foundation
			fKey := foundationKey{}
			copy(fKey[:], f)
			if _, ok := foundations[fKey]; ok {
				continue
			}
			foundations[fKey] = struct{}{}
			a.foundations = append(a.foundations, f)
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
	return nil
}
