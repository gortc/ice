package ice

import (
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

// Agent implements ICE Agent.
type Agent struct {
	ctx   map[contextKey]context
	set   ChecklistSet
	state State
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
