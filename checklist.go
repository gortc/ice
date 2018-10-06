package ice

import "sort"

// Checklist is set of pairs.
//
//
// From RFC 8455 Section 6.1.2:
//
// 	There is one checklist for each data stream.  To form a checklist,
// 	initiating and responding ICE agents form candidate pairs, compute
// 	pair priorities, order pairs by priority, prune pairs, remove lower-
// 	priority pairs, and set checklist states.  If candidates are added to
// 	a checklist (e.g., due to detection of peer-reflexive candidates),
// 	the agent will re-perform these steps for the updated checklist.
type Checklist struct {
	Pairs Pairs
}

// ComputePriorities computes priorities for all pairs based on agent role.
//
// The role determines whether local candidate is from controlling or from
// controlled agent.
func (c *Checklist) ComputePriorities(role Role) {
	for i := range c.Pairs {
		var (
			controlling = c.Pairs[i].Local.Priority
			controlled  = c.Pairs[i].Remote.Priority
		)
		if role == Controlled {
			controlling, controlled = controlled, controlling
		}
		c.Pairs[i].Priority = PairPriority(controlling, controlled)
	}
}

// Order is ordering pairs by priority descending.
// First element will have highest priority.
func (c *Checklist) Order() { sort.Sort(c.Pairs) }

// Prune removes redundant candidates.
//
// Two candidate pairs are redundant if their local candidates have the same
// base and their remote candidates are identical
func (c *Checklist) Prune() {
	// Pruning algorithm is not optimal but should work for small numbers,
	// where len(c.Pairs) ~ 100.
	result := make(Pairs, 0, len(c.Pairs))
	for i := range c.Pairs {
		base := c.Pairs[i].Local.Base
		redundant := false
		for j := range result {
			// Check if local candidates have the same base.
			if !result[j].Local.Base.Equal(base) {
				continue
			}
			// Check if remote candidates are identical.
			if !result[j].Remote.Equal(c.Pairs[i].Remote) {
				continue
			}
			redundant = true
			break
		}
		if redundant {
			continue
		}
		result = append(result, c.Pairs[i])
	}
	c.Pairs = result
}
