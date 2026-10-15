package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxAutomationRecordBytes = corrosion.MaxAutomationRecordBytes

// AutomationEngine is dependency injection for internal orchestration. Neither
// construction nor serving prefix RPCs enables admission or public capability.
func (s *Server) AutomationEngine() (*automation.Engine, error) {
	s.automationMu.Lock()
	defer s.automationMu.Unlock()
	if s.automationEngine != nil {
		return s.automationEngine, nil
	}
	_, v, err := s.claimIdentity()
	if err != nil {
		return nil, err
	}
	s.automationEngine = automation.NewEngine(s.hostName, s.db, v, serverAutomationTransport{s})
	return s.automationEngine, nil
}
func encodeAutomationRecord(r corrosion.AutomationRecord) ([]byte, error) {
	b, e := json.Marshal(r)
	if e != nil || len(b) > maxAutomationRecordBytes {
		return nil, fmt.Errorf("automation record exceeds bound")
	}
	return b, nil
}
func decodeAutomationRecord(b []byte) (corrosion.AutomationRecord, error) {
	var r corrosion.AutomationRecord
	if len(b) == 0 || len(b) > maxAutomationRecordBytes {
		return r, fmt.Errorf("automation record exceeds bound")
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	canonical, err := encodeAutomationRecord(r)
	if err != nil || string(canonical) != string(b) {
		return r, fmt.Errorf("noncanonical automation record")
	}
	return r, nil
}
func (s *Server) GetAutomationDecision(ctx context.Context, req *pb.GetAutomationDecisionRequest) (*pb.GetAutomationDecisionResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	r, ok, err := s.db.AutomationRecord(ctx, req.GetSequence())
	if err != nil {
		return nil, status.Error(codes.Unavailable, "automation history unavailable")
	}
	if !ok {
		return &pb.GetAutomationDecisionResponse{}, nil
	}
	b, err := encodeAutomationRecord(r)
	if err != nil {
		return nil, err
	}
	return &pb.GetAutomationDecisionResponse{Found: true, RecordJson: b}, nil
}
func (s *Server) InstallAutomationDecision(ctx context.Context, req *pb.InstallAutomationDecisionRequest) (*pb.InstallAutomationDecisionResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	r, err := decodeAutomationRecord(req.GetRecordJson())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid automation record")
	}
	e, err := s.AutomationEngine()
	if err != nil {
		return nil, err
	}
	if err = e.Install(ctx, r); err != nil {
		return nil, status.Error(codes.Unavailable, "automation prefix unavailable")
	}
	h, err := s.db.AutomationHead(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.InstallAutomationDecisionResponse{AppliedSequence: h.Sequence}, nil
}

type serverAutomationTransport struct{ s *Server }

func (t serverAutomationTransport) Prepare(ctx context.Context, voter string, k corrosion.ClaimKey, b corrosion.Ballot, gen int64, ev *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	return (serverClaimTransport{t.s}).Prepare(ctx, voter, k, b, gen, ev)
}
func (t serverAutomationTransport) Accept(ctx context.Context, voter string, k corrosion.ClaimKey, b corrosion.Ballot, v corrosion.ClaimValue, gen int64) (corrosion.AcceptResult, error) {
	return (serverClaimTransport{t.s}).Accept(ctx, voter, k, b, v, gen)
}
func (t serverAutomationTransport) Fetch(ctx context.Context, voter string, seq uint64) (corrosion.AutomationRecord, bool, error) {
	if voter == t.s.hostName {
		return t.s.db.AutomationRecord(ctx, seq)
	}
	cl, close, err := t.s.dialPeer(ctx, voter)
	if err != nil {
		return corrosion.AutomationRecord{}, false, err
	}
	defer close()
	resp, err := cl.GetAutomationDecision(ctx, &pb.GetAutomationDecisionRequest{Sequence: seq})
	if err != nil || !resp.GetFound() {
		return corrosion.AutomationRecord{}, false, err
	}
	r, err := decodeAutomationRecord(resp.GetRecordJson())
	return r, err == nil, err
}
func (t serverAutomationTransport) Install(ctx context.Context, voter string, r corrosion.AutomationRecord) error {
	if voter == t.s.hostName {
		e, err := t.s.AutomationEngine()
		if err != nil {
			return err
		}
		return e.Install(ctx, r)
	}
	b, err := encodeAutomationRecord(r)
	if err != nil {
		return err
	}
	cl, close, err := t.s.dialPeer(ctx, voter)
	if err != nil {
		return err
	}
	defer close()
	_, err = cl.InstallAutomationDecision(ctx, &pb.InstallAutomationDecisionRequest{RecordJson: b})
	return err
}
