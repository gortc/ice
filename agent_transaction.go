package ice

import (
	"errors"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/gortc/stun"
)

type transactionID [stun.TransactionIDSize]byte

func (t transactionID) AddTo(m *stun.Message) error {
	m.TransactionID = t
	return nil
}

// agentTransaction represents transaction in progress.
//
// Concurrent access is invalid.
type agentTransaction struct {
	checklist   int
	pair        pairKey
	priority    int
	nominate    bool
	id          transactionID
	start       time.Time
	rto         time.Duration
	deadline    time.Time
	raw         []byte
	attempt     int
	maxAttempts int
}

func (t *agentTransaction) nextDeadline(now time.Time) time.Time {
	return now.Add(time.Duration(t.attempt+1) * t.rto)
}

// handleTimeout handles maximum attempts reached state for transaction,
// updating the pair states to failed.
func (a *Agent) handleTimeout(t *agentTransaction) error {
	a.mux.Lock()
	p, ok := a.getPair(t.checklist, t.pair)
	if !ok {
		a.mux.Unlock()
		return errors.New("no pair found")
	}
	cl := a.set[t.checklist]
	for i := range cl.Triggered {
		if samePair(&cl.Triggered[i], p) {
			cl.Triggered[i].State = PairFailed
		}
	}
	for i := range cl.Pairs {
		if samePair(&cl.Pairs[i], p) {
			cl.Pairs[i].State = PairFailed
		}
	}
	a.mux.Unlock()
	return nil
}

// retry re-sends same binding request to associated candidate.
func (a *Agent) retry(t *agentTransaction) {
	a.mux.Lock()
	p, ok := a.getPair(t.checklist, t.pair)
	a.mux.Unlock()
	if !ok {
		a.log.Warn("failed to pick pair for retry")
		return
	}
	c, ok := a.localCandidateByAddr(p.Local.Addr)
	if !ok {
		a.log.Warn("failed to pick local candidate for retry")
		return
	}
	udpAddr := &net.UDPAddr{
		IP:   p.Remote.Addr.IP,
		Port: p.Remote.Addr.Port,
	}
	_, err := c.conn.WriteTo(t.raw, udpAddr)
	if err != nil {
		a.log.Error("failed to write", zap.Error(err))
	}
}

const defaultTransactionCap = 30

// collect handles transaction timeouts, performing retry or updating the
// pair state if max attempts reached.
func (a *Agent) collect(now time.Time) {
	toHandle := make([]*agentTransaction, 0, defaultTransactionCap)
	toDelete := make([]transactionID, 0, defaultTransactionCap)

	a.tMux.Lock()
	for id, t := range a.t {
		if t.deadline.Before(now) {
			toDelete = append(toDelete, id)
			toHandle = append(toHandle, t)
		}
	}
	for _, id := range toDelete {
		delete(a.t, id)
	}
	a.tMux.Unlock()

	if len(toHandle) == 0 {
		return
	}

	toRetry := make([]*agentTransaction, 0, defaultTransactionCap)
	for _, t := range toHandle {
		if t.attempt < t.maxAttempts {
			t.attempt++
			t.deadline = t.nextDeadline(now)
			toRetry = append(toRetry, t)
			continue
		}
		if err := a.handleTimeout(t); err != nil {
			a.log.Error("failed to handle timeout", zap.Error(err))
		}
	}

	a.tMux.Lock()
	for _, t := range toRetry {
		a.t[t.id] = t
	}
	a.tMux.Unlock()

	for _, t := range toRetry {
		a.retry(t)
	}
}
