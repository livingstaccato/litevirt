package grpcapi

import (
	"context"
	"fmt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const automationExportConcurrent = 2
const automationExportMaxWire = 3867975

// This is a direct peer repair operation. It intentionally remains outside
// staleReplicaGated's workload mutations and enrollmentOnlyMethods/skipAuth.
// Unlike requirePeerCert alone it accepts neither on-node root nor a relay.
func (s *Server) requireAutomationExportPeer(ctx context.Context) error {
	if callerAuthMethod(ctx) != authMethodMTLS || callerPrincipalKind(ctx) != principalKindPeer {
		return status.Error(codes.PermissionDenied, "direct peer mTLS required")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	count, total := 0, 0
	for key, values := range md {
		if len(key) > 128 {
			return status.Error(codes.InvalidArgument, "export metadata key exceeds bound")
		}
		for _, v := range values {
			count++
			if count > 32 || len(v) > 2048 || total > 8192-len(key)-len(v) {
				return status.Error(codes.InvalidArgument, "export metadata exceeds bound")
			}
			total += len(key) + len(v)
		}
	}
	if count > 32 || len(md.Get("authorization")) != 0 || len(md.Get(pki.FwdBearerMDKey)) != 0 {
		return status.Error(codes.PermissionDenied, "user or forwarded export context refused")
	}
	if err := s.connIdentityGate(ctx); err != nil {
		return err
	}
	if err := s.requirePeerCert(ctx); err != nil {
		return err
	}
	if peerLeafCert(ctx) == nil {
		return status.Error(codes.PermissionDenied, "actual export TLS identity required")
	}
	return nil
}
func checkedAutomationExportRequest(r *pb.AutomationSourceExportRequest) (corrosion.AutomationExportRequest, error) {
	var out corrosion.AutomationExportRequest
	if r == nil || r.Version != 1 || r.Purpose != "automation-membership-source" || r.Stream != "automation" || len(r.ProtoReflect().GetUnknown()) != 0 || len(r.Sources) > 7 || len(r.Target) > 253 || len(r.Job) > 128 || len(r.PublicationId) > 64 || len(r.Cursor) > corrosion.AutomationExportMaxCursor {
		return out, status.Error(codes.InvalidArgument, "invalid bounded source export request")
	}
	out = corrosion.AutomationExportRequest{Intent: corrosion.AutomationSourceRequest{Generation: r.Generation, Target: r.Target, Job: r.Job, Revision: r.Revision}, Publication: r.PublicationId, Component: r.Component, Cursor: r.Cursor, MaxRecords: r.MaxRecords, MaxBytes: r.MaxBytes}
	for _, m := range r.Sources {
		if m == nil || len(m.Name) > 253 || len(m.Incarnation) > 128 || len(m.ProtoReflect().GetUnknown()) != 0 {
			return out, status.Error(codes.InvalidArgument, "invalid source roster")
		}
		out.Intent.Sources = append(out.Intent.Sources, corrosion.VoterMember{Name: m.Name, Incarnation: m.Incarnation})
	}
	return out, nil
}
func automationExportResponse(page corrosion.AutomationExportPage) (*pb.AutomationSourceExportResponse, error) {
	out := &pb.AutomationSourceExportResponse{Version: 1, PublicationId: page.Publication, Component: page.Component, Metadata: page.Metadata, Records: page.Records, Chunk: page.Chunk, Cursor: page.Cursor, Terminal: page.Terminal, TerminalRecords: page.TerminalRecords, TerminalBytes: page.TerminalBytes, TerminalDigest: page.TerminalDigest}
	if err := checkAutomationExportWire(out); err != nil {
		return nil, err
	}
	return out, nil
}
func checkAutomationExportWire(p *pb.AutomationSourceExportResponse) error {
	if p == nil || p.Version != 1 || p.Component >= 12 || len(p.PublicationId) != 64 || len(p.TerminalDigest) != 64 || len(p.Metadata) > 131072 || len(p.Cursor) > 1024 || len(p.Records) > 64 || len(p.Chunk) > corrosion.AutomationExportChunkBytes || p.TerminalRecords < 0 || p.TerminalBytes < 0 {
		return fmt.Errorf("invalid export response bounds")
	}
	remaining := corrosion.AutomationExportMaxBytes
	for _, r := range p.Records {
		if len(r) > remaining {
			return fmt.Errorf("export record byte budget exceeded")
		}
		remaining -= len(r)
	}
	if len(p.Chunk) > 0 && len(p.Records) > 0 {
		return fmt.Errorf("mixed export component")
	}
	// Complete generated protobuf size includes all repeated/field/unknown
	// overhead. The separate five-byte gRPC frame remains below default4MiB.
	other := proto.Size(p)
	for _, r := range p.Records {
		other -= protowire.SizeTag(5) + protowire.SizeBytes(len(r))
	}
	if len(p.Metadata) > 0 {
		other -= protowire.SizeTag(4) + protowire.SizeBytes(len(p.Metadata))
	}
	if len(p.Cursor) > 0 {
		other -= protowire.SizeTag(7) + protowire.SizeBytes(len(p.Cursor))
	}
	if len(p.Chunk) > 0 {
		other -= protowire.SizeTag(6) + protowire.SizeBytes(len(p.Chunk))
	}
	if other > 65536 {
		return fmt.Errorf("export wrapper/unknown overhead exceeds bound")
	}
	if proto.Size(p) > automationExportMaxWire {
		return fmt.Errorf("complete export protobuf exceeds peer budget")
	}
	return nil
}
func (s *Server) ExportAutomationSource(r *pb.AutomationSourceExportRequest, stream grpc.ServerStreamingServer[pb.AutomationSourceExportResponse]) error {
	ctx := stream.Context()
	if s.automationExportSem == nil {
		return status.Error(codes.Unavailable, "source export admission unavailable")
	}
	select {
	case s.automationExportSem <- struct{}{}:
		defer func() { <-s.automationExportSem }()
	default:
		return status.Error(codes.ResourceExhausted, "source export capacity reached")
	}
	if err := s.requireAutomationExportPeer(ctx); err != nil {
		return err
	}
	request, err := checkedAutomationExportRequest(r)
	if err != nil {
		return err
	}
	if request.Intent.Target != callerMTLSCommonName(ctx) {
		return status.Error(codes.PermissionDenied, "export recipient differs from direct peer")
	}
	s.automationMu.Lock()
	if s.automationSource == nil {
		s.automationSource = corrosion.NewAutomationSourcePreparer(s.db, s.pkiDir)
	}
	owner := s.automationSource
	s.automationMu.Unlock()
	page, err := owner.ExportAutomationSource(ctx, request)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "source export unavailable: %v", err)
	}
	response, err := automationExportResponse(page)
	if err != nil {
		return status.Error(codes.ResourceExhausted, err.Error())
	}
	if err := s.connIdentityGate(ctx); err != nil {
		return err
	}
	return stream.Send(response)
}
