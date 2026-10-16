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

// InitializeAutomationSource reconciles only completed signed evidence after
// schema/identity recovery and configured policy. Failure leaves publication
// unavailable; it does not grant export/import or readiness.
func (s *Server) InitializeAutomationSource(ctx context.Context) error {
	s.automationMu.Lock()
	if s.automationSource == nil {
		s.automationSource = corrosion.NewAutomationSourcePreparer(s.db, s.pkiDir)
	}
	producer := s.automationSource
	s.automationMu.Unlock()
	return producer.InitializePublication(ctx)
}

// PublishAutomationSource is an internal typed producer, not a network export.
func (s *Server) PublishAutomationSource(ctx context.Context, candidate *corrosion.AutomationSourcePreparation) (string, error) {
	s.automationMu.Lock()
	producer := s.automationSource
	s.automationMu.Unlock()
	return producer.Publish(ctx, candidate)
}
