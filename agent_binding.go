package ice

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/gortc/ice/candidate"
	"github.com/gortc/stun"
)

func (a *Agent) handleBindingRequest(m *stun.Message, c *localUDPCandidate, raddr Addr) error {
	a.log.Debug("handling binding request",
		zap.Stringer("remote", raddr),
		zap.Stringer("local", c.candidate.Addr),
	)
	if err := stun.Fingerprint.Check(m); err != nil {
		return err
	}
	integrity := stun.NewShortTermIntegrity(a.localPassword)
	if err := integrity.Check(m); err != nil {
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

	a.mux.Lock()
	defer a.mux.Unlock()
	list := a.set[c.stream]

	for i := range list.Pairs {
		if !list.Pairs[i].Local.Equal(&pair.Local) {
			continue
		}
		if !list.Pairs[i].Remote.Equal(&pair.Remote) {
			continue
		}
		state := list.Pairs[i].State
		a.log.Debug("found", zap.Stringer("state", state))
		pair.State = PairWaiting
		list.Triggered = append(list.Triggered, list.Pairs[i])
		a.set[c.stream] = list
		a.log.Debug("added to triggered set",
			zap.Stringer("local", pair.Local.Addr),
			zap.Stringer("remote", pair.Remote.Addr),
		)
		// Sending response.
		res := stun.MustBuild(m, stun.BindingSuccess,
			&stun.XORMappedAddress{
				IP:   raddr.IP,
				Port: raddr.Port,
			},
			integrity, stun.Fingerprint,
		)
		a.log.Debug("writing", zap.Stringer("m", res))
		_, err := c.conn.WriteTo(res.Raw, &net.UDPAddr{
			Port: raddr.Port,
			IP:   raddr.IP,
		})
		if err == nil {
			a.log.Debug("wrote response", zap.Stringer("m", res))
		} else {
			a.log.Debug("write err", zap.Error(err))
		}
		return err
	}

	list.Pairs = append(list.Pairs, pair)
	list.Sort()
	a.set[c.stream] = list
	return nil
}

func (a *Agent) handleBindingResponse(t *agentTransaction, p *Pair, m *stun.Message, raddr Addr) error {
	if err := a.processBindingResponse(t, p, m, raddr); err != nil {
		// TODO: Handle nomination failure.

		a.mux.Lock()
		a.setPairStateByKey(t.checklist, t.pair, PairFailed)
		a.mux.Unlock()

		a.log.Debug("response process failed", zap.Error(err),
			zap.Stringer("remote", p.Remote.Addr),
			zap.Stringer("local", p.Local.Addr),
		)
		return err
	}

	a.mux.Lock()
	a.setPairStateByKey(t.checklist, t.pair, PairSucceeded)
	a.mux.Unlock()

	a.log.Debug("response succeeded",
		zap.Stringer("remote", p.Remote.Addr),
		zap.Stringer("local", p.Local.Addr),
	)
	// Adding to valid list.
	// TODO: Construct valid pair as in https://tools.ietf.org/html/rfc8445#section-7.2.5.3.2
	// Handling case "1" only, when valid pair is equal to generated pair p.
	validPair := *p
	a.mux.Lock()
	cl := a.set[t.checklist]

	// Setting all candidate paris with same foundation to "Waiting".
	for cID, c := range a.set {
		for i := range c.Pairs {
			if samePair(p, &c.Pairs[i]) {
				continue
			}
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
	a.log.Debug("added to valid list",
		zap.Stringer("local", validPair.Local.Addr),
		zap.Stringer("remote", validPair.Remote.Addr),
	)
	found := false
	for i := range cl.Valid {
		if cl.Valid[i].ComponentID != validPair.ComponentID {
			continue
		}
		if !cl.Valid[i].Remote.Addr.Equal(validPair.Remote.Addr) {
			continue
		}
		if !cl.Valid[i].Local.Addr.Equal(validPair.Local.Addr) {
			continue
		}
		a.log.Debug("nominating",
			zap.Stringer("remote", validPair.Remote.Addr),
			zap.Stringer("local", validPair.Local.Addr),
		)
		found = true
		cl.Valid[i].Nominated = true
	}
	if !found {
		cl.Valid = append(cl.Valid, validPair)
	}
	a.set[t.checklist] = cl
	// Updating checklist states.
	a.updateState()
	a.mux.Unlock()

	return nil
}

var (
	errFingerprintNotFound = errors.New("STUN message fingerprint attribute not found")
	errRoleConflict        = errors.New("role conflict")
)

func (a *Agent) processBindingResponse(t *agentTransaction, p *Pair, m *stun.Message, raddr Addr) error {
	integrity := stun.NewShortTermIntegrity(a.remotePassword)
	if err := stun.Fingerprint.Check(m); err != nil {
		if err == stun.ErrAttributeNotFound {
			return errFingerprintNotFound
		}
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
		a.log.Debug("got binding error",
			zap.String("reason", string(errCode.Reason)),
			zap.Int("code", int(errCode.Code)),
		)
		return unrecoverableErrorCodeErr{Code: errCode.Code}
	}
	if err := integrity.Check(m); err != nil {
		return err
	}
	if m.Type != stun.BindingSuccess {
		return unexpectedResponseTypeErr{Type: m.Type}
	}
	var xAddr stun.XORMappedAddress
	if err := xAddr.GetFrom(m); err != nil {
		return fmt.Errorf("can't get xor mapped address: %v", err)
	}
	addr := Addr{
		IP:    make(net.IP, len(xAddr.IP)),
		Port:  xAddr.Port,
		Proto: p.Local.Addr.Proto,
	}
	copy(addr.IP, xAddr.IP)
	if _, ok := a.localCandidateByAddr(addr); !ok {
		if err := a.addPeerReflexive(t, p, addr); err != nil {
			return err
		}
	}
	return nil
}

var errUnsupportedProtocol = errors.New("protocol not supported")

func (a *Agent) startBinding(p *Pair, m *stun.Message, priority int, t time.Time) error {
	if p.Remote.Addr.Proto != candidate.UDP {
		return errUnsupportedProtocol
	}
	c, ok := a.localCandidateByAddr(p.Local.Addr)
	if !ok {
		return errCandidateNotFound
	}
	a.mux.Lock()
	checklist := a.checklist
	a.mux.Unlock()

	at := &agentTransaction{
		id:          m.TransactionID,
		start:       t,
		rto:         a.rto(),
		raw:         m.Raw,
		checklist:   checklist,
		priority:    priority,
		nominate:    p.Nominated,
		pair:        getPairKey(p),
		attempt:     1,
		maxAttempts: a.maxAttempts,
	}
	at.setDeadline(t)

	a.tMux.Lock()
	a.t[m.TransactionID] = at
	a.tMux.Unlock()

	udpAddr := &net.UDPAddr{
		IP:   p.Remote.Addr.IP,
		Port: p.Remote.Addr.Port,
	}
	_, err := c.conn.WriteTo(m.Raw, udpAddr)
	// TODO: Add write deadline.
	// TODO: Check n if needed.
	if err != nil {
		a.log.Warn("failed to write",
			zap.Stringer("to", udpAddr),
			zap.Stringer("from", c.candidate.Addr),
			zap.Error(err),
		)

		// TODO: If temporary, just perform STUN retries normally.
		a.tMux.Lock()
		delete(a.t, m.TransactionID)
		a.tMux.Unlock()

		a.mux.Lock()
		cl := a.set[checklist]
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
	a.log.Debug("started",
		zap.Stringer("remote", udpAddr),
		zap.Stringer("msg", m),
	)
	return nil
}

type unexpectedResponseTypeErr struct{ Type stun.MessageType }

func (e unexpectedResponseTypeErr) Error() string {
	return fmt.Sprintf("peer responded with unexpected STUN message %s", e.Type)
}

type unrecoverableErrorCodeErr struct{ Code stun.ErrorCode }

func (e unrecoverableErrorCodeErr) Error() string {
	return fmt.Sprintf("peer responded with unrecoverable error code %d", e.Code)
}
