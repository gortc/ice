package ice

import (
	"strings"

	"go.uber.org/zap"

	"gortc.io/stun"
	"gortc.io/turn"
)

// AgentOption represents configuration option for Agent.
type AgentOption func(a *Agent) error

// WithRole sets agent mode to Controlling or Controlled.
func WithRole(r Role) AgentOption {
	return func(a *Agent) error {
		a.role = r
		return nil
	}
}

// WithLogger sets *zap.Logger for Agent.
func WithLogger(l *zap.Logger) AgentOption {
	return func(a *Agent) error {
		a.log = l
		return nil
	}
}

// WithServer configures ICE server or servers for Agent.
func WithServer(servers ...Server) AgentOption {
	return func(a *Agent) error {
		for _, s := range servers {
			for _, uri := range s.URI {
				if strings.HasPrefix(uri, stun.Scheme) {
					u, err := stun.ParseURI(uri)
					if err != nil {
						return err
					}
					a.stun = append(a.stun, stunServerOptions{
						username: s.Username,
						password: s.Credential,
						uri:      u,
					})
				} else {
					u, err := turn.ParseURI(uri)
					if err != nil {
						return err
					}
					a.turn = append(a.turn, turnServerOptions{
						username: s.Username,
						password: s.Credential,
						uri:      u,
					})
				}
			}
		}
		return nil
	}
}

// WithSTUN configures Agent to use STUN server.
//
// Use WithServer to add STUN with credentials or multiple servers at once.
func WithSTUN(uri string) AgentOption {
	return func(a *Agent) error {
		u, err := stun.ParseURI(uri)
		if err != nil {
			return err
		}
		a.stun = append(a.stun, stunServerOptions{
			uri: u,
		})
		return nil
	}
}

// WithTURN configures Agent to use TURN server.
//
// Use WithServer to add multiple servers at once.
func WithTURN(uri, username, credential string) AgentOption {
	return func(a *Agent) error {
		u, err := turn.ParseURI(uri)
		if err != nil {
			return err
		}
		a.turn = append(a.turn, turnServerOptions{
			password: credential,
			username: username,
			uri:      u,
		})
		return nil
	}
}

// WithIPv4Only enables IPv4-only mode, where IPv6 candidates are not used.
var WithIPv4Only AgentOption = func(a *Agent) error {
	a.ipv4Only = true
	return nil
}
