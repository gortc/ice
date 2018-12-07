package ice

import (
	"bytes"
	"net"

	ct "github.com/gortc/ice/candidate"
)

// Role represents ICE agent role, which can be controlling or controlled.
type Role byte

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

// init sets initial states for checklist sets.
func (a *Agent) init() {
	// Gathering all unique foundations.
	foundations := make(map[foundationKey]struct{})
	for _, c := range a.set {
		for i := range c.Pairs {
			// Initializing context.
			k := contextKey{}
			l := c.Pairs[i].Local
			copy(k.IP[:], l.Addr.IP)
			k.Port = l.Addr.Port
			k.Proto = l.Addr.Proto
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
Loop:
	for _, f := range a.foundations {
		for _, c := range a.set {
			for i := range c.Pairs {
				if !bytes.Equal(c.Pairs[i].Foundation, f) {
					continue
				}
				c.Pairs[i].State = PairWaiting
				continue Loop
			}
		}
	}
}
