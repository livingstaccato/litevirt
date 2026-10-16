package grpcapi

import (
	"context"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// PrepareAutomationSource is an internal producer entry, not an RPC. Its result
// cannot be exported or used as final publication/readiness authority.
func (s *Server) PrepareAutomationSource(ctx context.Context, request corrosion.AutomationSourceRequest) (*corrosion.AutomationSourcePreparation, error) {
	s.automationMu.Lock()
	if s.automationSource == nil {
		s.automationSource = corrosion.NewAutomationSourcePreparer(s.db, s.pkiDir)
	}
	producer := s.automationSource
	s.automationMu.Unlock()
	return producer.Prepare(ctx, request)
}
