package grpcapi

import "context"

// SetFenceCandidates installs the function that lists the hosts the failover
// coordinator would fence now. It is injected so grpcapi does not import
// failover.
func (s *Server) SetFenceCandidates(fn func(ctx context.Context) ([]string, error)) {
	s.fenceCandidates = fn
}
