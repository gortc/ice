package ice

import (
	"io"
	"net"
	"strconv"
	"sync"

	"go.uber.org/zap"

	"gortc.io/stun"
	"gortc.io/turn"
	"gortc.io/turnc"
)

func withGatherer(g candidateGatherer) AgentOption {
	return func(a *Agent) error {
		a.gatherer = g
		return nil
	}
}

type gathererOptions struct {
	Components int
	IPv4Only   bool
}

type candidateGatherer interface {
	gatherUDP(opt gathererOptions) ([]*localUDPCandidate, error)
}

func (c *localUDPCandidate) Close() error {
	return c.conn.Close()
}

func (c *localUDPCandidate) readUntilClose(a *Agent) {
	for {
		buf := make([]byte, 1024)
		n, addr, err := c.conn.ReadFrom(buf)
		if err != nil {
			break
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			break
		}
		c.mux.Lock()
		var pipe localPipe
		for _, p := range c.pipes {
			if !p.addr.IP.Equal(udpAddr.IP) {
				continue
			}
			if p.addr.Port != udpAddr.Port {
				continue
			}
			pipe = p
		}
		c.mux.Unlock()
		if pipe.addr != nil {
			_, err = pipe.conn.Write(buf[:n])
			if err != nil && err != io.ErrClosedPipe {
				c.log.Debug("pipe write failed", zap.Error(err))
			} else {
				continue
			}
		}
		go func() {
			if err := a.processUDP(buf[:n], c, udpAddr); err != nil {
				c.log.Error("processUDP failed", zap.Error(err))
			} else {
				c.log.Debug("processed")
			}
		}()
	}
}

// GatherCandidatesForStream allows gathering candidates for multiple streams.
// The streamID is integer that starts from zero.
func (a *Agent) GatherCandidatesForStream(streamID int) error {
	if len(a.localCandidates) > streamID {
		return errStreamAlreadyExist
	}
	candidates, err := a.gatherer.gatherUDP(gathererOptions{Components: 1, IPv4Only: a.ipv4Only})
	if err != nil {
		return err
	}
	a.localCandidates = append(a.localCandidates, candidates)
	for i := range candidates {
		candidates[i].log = a.log.Named("candidate").With(
			zap.Stringer("addr", candidates[i].candidate.Addr),
		)
		go candidates[i].readUntilClose(a)
	}
	if len(a.stun) > 0 {
		if err = a.gatherServerReflexiveCandidatesFor(streamID); err != nil {
			return err
		}
	}
	if len(a.turn) > 0 {
		if err = a.gatherRelayedCandidatesFor(streamID); err != nil {
			return err
		}
	}
	return nil
}

func resolveSTUN(uri stun.URI) (*net.UDPAddr, error) {
	if uri.Port == 0 {
		uri.Port = stun.DefaultPort
	}
	hostPort := net.JoinHostPort(uri.Host, strconv.Itoa(uri.Port))
	addr, err := net.ResolveUDPAddr("udp", hostPort)
	return addr, err
}

func resolveTURN(uri turn.URI) (*net.UDPAddr, error) {
	if uri.Port == 0 {
		uri.Port = turn.DefaultPort
	}
	hostPort := net.JoinHostPort(uri.Host, strconv.Itoa(uri.Port))
	addr, err := net.ResolveUDPAddr("udp", hostPort)
	return addr, err
}

func (a *Agent) gatherServerReflexiveCandidatesFor(streamID int) error {
	localCandidates := a.localCandidates[streamID]
	for _, c := range localCandidates {
		if c.candidate.Addr.IP.To4() == nil {
			continue
		}
		for _, s := range a.stun {
			a.log.Debug("trying STUN",
				zap.Stringer("uri", s.uri), zap.Stringer("addr", c.candidate.Addr),
			)
			addr, err := resolveSTUN(s.uri)
			if err != nil {
				return err
			}
			lconn, rconn := net.Pipe()
			c.mux.Lock()
			c.pipes = append(c.pipes, localPipe{
				addr: addr,
				conn: rconn,
			})
			c.mux.Unlock()
			go func() {
				for {
					buf := make([]byte, 1024)
					n, readErr := rconn.Read(buf)
					if readErr != nil {
						break
					}
					_, writeErr := c.conn.WriteTo(buf[:n], addr)
					if writeErr != nil {
						a.log.Debug("WriteTo failed", zap.Error(writeErr))
						_ = rconn.Close()
					}
				}
			}()
			// TODO: Setup correct RTO.
			client, err := stun.NewClient(lconn, stun.WithRTO(a.ta/2))
			if err != nil {
				return err
			}
			var bindErr error
			if doErr := client.Do(stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint), func(event stun.Event) {
				if event.Error != nil {
					bindErr = event.Error
					return
				}
				var mappedAddr stun.XORMappedAddress
				if getErr := mappedAddr.GetFrom(event.Message); getErr != nil {
					bindErr = getErr
				}
				a.log.Debug("got server reflexive candidate", zap.Stringer("addr", mappedAddr))
			}); doErr != nil {
				return doErr
			}
			if err = client.Close(); err != nil {
				return err
			}
			if bindErr != nil {
				a.log.Debug("binding error", zap.Error(bindErr))
			}
		}
	}
	return nil
}

func (a *Agent) gatherRelayedCandidatesFor(streamID int) error {
	localCandidates := a.localCandidates[streamID]
	for _, c := range localCandidates {
		if c.candidate.Addr.IP.To4() == nil {
			continue
		}
		for _, s := range a.turn {
			a.log.Debug("trying TURN",
				zap.Stringer("uri", s.uri), zap.Stringer("addr", c.candidate.Addr),
			)
			addr, err := resolveTURN(s.uri)
			if err != nil {
				return err
			}
			lconn, rconn := net.Pipe()
			c.mux.Lock()
			c.pipes = append(c.pipes, localPipe{
				addr: addr,
				conn: rconn,
			})
			c.mux.Unlock()
			go func() {
				for {
					buf := make([]byte, 1024)
					n, readErr := rconn.Read(buf)
					if readErr != nil {
						break
					}
					_, writeErr := c.conn.WriteTo(buf[:n], addr)
					if writeErr != nil {
						a.log.Debug("WriteTo failed", zap.Error(writeErr))
						_ = rconn.Close()
					}
				}
			}()
			// TODO: Setup correct RTO.
			client, err := turnc.New(turnc.Options{
				Conn:     lconn,
				Username: s.username,
				Password: s.password,
				Log:      a.log.Named("turn").With(zap.Stringer("local", c.candidate.Addr)),
				RTO:      a.ta / 2,
			})
			if err != nil {
				return err
			}
			alloc, err := client.Allocate()
			if err != nil {
				a.log.Warn("failed to allocate", zap.Error(err))
				continue
			}
			c.alloc = alloc
			a.log.Debug("turn allocated")
		}
	}
	return nil
}

type localUDPCandidate struct {
	log       *zap.Logger
	candidate Candidate
	conn      net.PacketConn
	stream    int
	alloc     *turnc.Allocation

	pipes []localPipe
	mux   sync.Mutex
}

type localPipe struct {
	addr *net.UDPAddr
	conn net.Conn
}
