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

type connectionKey struct {
	IP    [net.IPv6len]byte
	Proto ct.Protocol
	Port  int
}

type ChecklistSet []Checklist

// Agent implements ICE Agent.
type Agent struct {
	con   map[connectionKey]net.Conn
	set   ChecklistSet
	state State
}

func (a *Agent) updateState() {
	state := Running
	var (
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
