package ice

import (
	"bytes"
	"fmt"
	"net"

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
	ctx         map[contextKey]context
	set         ChecklistSet
	state       State
	foundations [][]byte
}

// context wraps resources for candidate.
type context struct {
	// STUN Agent, TURN client, socket, etc.
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

func pairContextKey(p Pair) contextKey {
	k := contextKey{
		Proto: p.Local.Addr.Proto,
		Port:  p.Local.Addr.Port,
	}
	copy(k.IP[:], p.Local.Addr.IP)
	return k
}

// init sets initial states for checklist sets.
func (a *Agent) init() {
	if a.ctx == nil {
		a.ctx = make(map[contextKey]context)
	}
	// Gathering all unique foundations.
	foundations := make(map[foundationKey]struct{})
	for _, c := range a.set {
		for i := range c.Pairs {
			// Initializing context.
			k := pairContextKey(c.Pairs[i])
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
}
