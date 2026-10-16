package grpcapi

import (
	"context"
	"sync"
	"testing"
)

type privateLBNetwork struct {
	mu               sync.Mutex
	routes, forwards int
}

func (e *privateLBNetwork) DefaultRouteIface() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.routes++
	return "private-uplink"
}
func (e *privateLBNetwork) EnableIPForwarding() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.forwards++
	return nil
}
func isolateLBEffects(t *testing.T, s *Server) *privateLBNetwork {
	t.Helper()
	e := &privateLBNetwork{}
	s.SetLBNetworkEffects(e)
	s.SetLBObservations(func(context.Context, string) (map[string]string, error) { return map[string]string{}, nil }, func(string) bool { return true })
	t.Cleanup(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.routes != e.forwards {
			t.Errorf("route/forward calls %d/%d", e.routes, e.forwards)
		}
	})
	return e
}

func (e *privateLBNetwork) InterfaceForIP(string) string { return "private-uplink" }
