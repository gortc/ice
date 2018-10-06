package ice

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
