package grpcapi

import (
	"context"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/network"
)

// LBNetworkEffects owns route discovery and forwarding on this server's host.
// Configure it before serving requests; nil keeps the production host effects.
type LBNetworkEffects interface {
	DefaultRouteIface() string
	EnableIPForwarding() error
	InterfaceForIP(string) string
}

func (s *Server) SetLBNetworkEffects(e LBNetworkEffects) { s.lbNetworkEffects = e }
func (s *Server) lbDefaultRouteIface() string {
	if s.lbNetworkEffects != nil {
		return s.lbNetworkEffects.DefaultRouteIface()
	}
	return network.DefaultRouteIface()
}
func (s *Server) lbEnableIPForwarding() error {
	if s.lbNetworkEffects != nil {
		return s.lbNetworkEffects.EnableIPForwarding()
	}
	return network.EnableIPForwarding()
}

// SetLBObservations supplies host-local health observations before first use.
func (s *Server) SetLBObservations(health func(context.Context, string) (map[string]string, error), running func(string) bool) {
	s.lbHealthOverride, s.lbKeepalivedOverride = health, running
}

// startNetworkWork registers detached LB/VTEP work before it can run.
func (s *Server) startNetworkWork(fn func()) {
	s.networkWorkMu.Lock()
	if s.networkWorkCount == 0 {
		s.networkWorkIdle = make(chan struct{})
	}
	s.networkWorkCount++
	s.networkWorkGeneration++
	s.networkWorkMu.Unlock()
	go func() {
		defer func() {
			s.networkWorkMu.Lock()
			s.networkWorkCount--
			if s.networkWorkCount == 0 {
				close(s.networkWorkIdle)
			}
			s.networkWorkMu.Unlock()
		}()
		fn()
	}()
}

// WaitNetworkWork joins registered LB/VTEP work and returns its registration
// generation. New registrations may arrive while waiting (including peer
// requests). A caller joining several servers must quiesce external producers
// and repeat until the generation vector is stable. Unrelated daemon consumers
// are not covered.
func (s *Server) WaitNetworkWork() uint64 {
	for {
		s.networkWorkMu.Lock()
		if s.networkWorkCount == 0 {
			generation := s.networkWorkGeneration
			s.networkWorkMu.Unlock()
			return generation
		}
		idle := s.networkWorkIdle
		s.networkWorkMu.Unlock()
		<-idle
	}
}

func (s *Server) lbInterfaceForIP(ip string) string {
	if s.lbNetworkEffects != nil {
		return s.lbNetworkEffects.InterfaceForIP(ip)
	}
	return lb.DetectInterfaceForIP(ip)
}
