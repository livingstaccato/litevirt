package grpcapi

import (
	"context"
	"path/filepath"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InitializeAutomationCustody composes the actual daemon owners without
// creating a root, key, enrollment, established authority or certified epoch.
func (s *Server) InitializeAutomationCustody(ctx context.Context) error {
	_, err := s.custodyProducer()
	return err
}
func (s *Server) custodyProducer() (*corrosion.AutomationCustodyProducer, error) {
	s.automationMu.Lock()
	defer s.automationMu.Unlock()
	if s.automationCustody != nil {
		return s.automationCustody, nil
	}
	if !filepath.IsAbs(s.dataDir) {
		return nil, status.Error(codes.Unavailable, "custody unavailable")
	}
	p, err := corrosion.NewAutomationCustodyProducer(s.db, s.pkiDir, filepath.Join(s.dataDir, "automation-custody"))
	if err != nil {
		return nil, status.Error(codes.Unavailable, "custody unavailable")
	}
	s.automationCustody = p
	return p, nil
}
func (s *Server) CloseAutomationCustody() error {
	s.automationMu.Lock()
	defer s.automationMu.Unlock()
	if s.automationCustody != nil {
		return s.automationCustody.Close()
	}
	return nil
}
func (s *Server) PrepareAutomationCustodyRecipient(ctx context.Context, r *pb.PrepareAutomationCustodyRecipientRequest) (*pb.PrepareAutomationCustodyRecipientResponse, error) {
	if err := s.requireAutomationExportPeer(ctx); err != nil {
		return nil, err
	}
	if r == nil || len(r.ProtoReflect().GetUnknown()) != 0 || len(r.RequestJson) == 0 || len(r.RequestJson) > 1<<20 {
		return nil, status.Error(codes.InvalidArgument, "invalid custody request")
	}
	p, err := s.custodyProducer()
	if err != nil {
		return nil, err
	}
	raw, err := p.PrepareCustodyRecipient(ctx, r.RequestJson, peerLeafCert(ctx).Raw)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "custody recipient unavailable")
	}
	return &pb.PrepareAutomationCustodyRecipientResponse{RecipientJson: raw}, nil
}
func (s *Server) ImportAutomationCustodyEquality(ctx context.Context, r *pb.ImportAutomationCustodyEqualityRequest) (*pb.ImportAutomationCustodyEqualityResponse, error) {
	if err := s.requireAutomationExportPeer(ctx); err != nil {
		return nil, err
	}
	if r == nil || len(r.ProtoReflect().GetUnknown()) != 0 || len(r.RequestJson) == 0 || len(r.RequestJson) > 1<<20 || len(r.Capsule) == 0 || len(r.Capsule) > 65536 {
		return nil, status.Error(codes.InvalidArgument, "invalid custody request")
	}
	p, err := s.custodyProducer()
	if err != nil {
		return nil, err
	}
	raw, err := p.CompleteCustodyImport(ctx, r.RequestJson, r.Capsule, peerLeafCert(ctx).Raw)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "custody import unavailable")
	}
	return &pb.ImportAutomationCustodyEqualityResponse{CompletionJson: raw}, nil
}
