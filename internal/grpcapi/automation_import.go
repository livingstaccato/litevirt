package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Certified-prefix import for a voter new to the automation electorate (F1
// Task 5G; corrosion/automation_import.go has the safety argument).

// automationImportSourceTimeout bounds one source attestation.
const automationImportSourceTimeout = 5 * time.Second

// GetAutomationImportSource answers an importer: this voter's adopted
// generation, whether it holds automation authority at the requested one, and
// its certified head. Direct peer mTLS only (the automation repair gate), and
// the caller must be a member of the requested generation. Read-only.
func (s *Server) GetAutomationImportSource(ctx context.Context, req *pb.GetAutomationImportSourceRequest) (*pb.GetAutomationImportSourceResponse, error) {
	if err := s.requireAutomationExportPeer(ctx); err != nil {
		return nil, err
	}
	gen := req.GetGeneration()
	if gen <= 0 || len(req.ProtoReflect().GetUnknown()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid automation import source request")
	}
	caller := callerMTLSCommonName(ctx)
	cfg, err := corrosion.GetVoterConfig(ctx, s.db, gen)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "voter configuration unavailable")
	}
	if cfg == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "voter generation %d is not known here", gen)
	}
	if _, ok := cfg.Member(caller); !ok {
		return nil, status.Errorf(codes.PermissionDenied, "%s is not a member of voter generation %d", caller, gen)
	}
	st, err := s.db.AutomationImportSourceState(ctx, gen)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "automation state unavailable")
	}
	return &pb.GetAutomationImportSourceResponse{
		Voter: st.Voter, Incarnation: st.Incarnation, AdoptedGeneration: st.Adopted, Authority: st.Authority,
		HeadSequence: st.Head.Sequence, HeadDigest: st.Head.Digest, ClusterUid: st.Head.ClusterUID,
	}, nil
}

// automationImportSources asks every member of plan's previous generation
// but this voter for its attestation. An unreachable or older peer simply does
// not answer.
func (s *Server) automationImportSources(ctx context.Context, plan corrosion.AutomationImportPlan) []corrosion.AutomationImportSource {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out []corrosion.AutomationImportSource
	)
	for _, m := range plan.Previous.Members {
		if m.Name == s.hostName {
			continue
		}
		wg.Add(1)
		go func(voter string) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, automationImportSourceTimeout)
			defer cancel()
			cl, closer, err := s.dialPeer(cctx, voter)
			if err != nil {
				return
			}
			defer closer()
			r, err := cl.GetAutomationImportSource(cctx, &pb.GetAutomationImportSourceRequest{Generation: plan.Generation})
			if err != nil || r.GetVoter() != voter {
				return
			}
			mu.Lock()
			out = append(out, corrosion.AutomationImportSource{
				Voter: voter, Incarnation: r.GetIncarnation(), Adopted: r.GetAdoptedGeneration(), Authority: r.GetAuthority(),
				Head: corrosion.AutomationPrefix{ClusterUID: r.GetClusterUid(), Sequence: r.GetHeadSequence(), Digest: r.GetHeadDigest()},
			})
			mu.Unlock()
		}(m.Name)
	}
	wg.Wait()
	return out
}

// ImportAutomationPrefix imports the certified automation prefix and, with
// it, automation authority at this voter's adopted generation, when this
// voter is new to the electorate there. It returns nil when there is nothing
// to do (authority already held), corrosion.ErrAutomationImportIneligible
// (wrapped) when this voter may not import, and any other error for an import
// to retry.
//
// The automation_state use is recorded (WithReleaseFeature) only once a
// majority of the old generation attests a nonempty certified prefix under
// authority, so a cluster that never used automation never records it.
func (s *Server) ImportAutomationPrefix(ctx context.Context) error {
	plan, err := s.db.AutomationImportPlan(ctx)
	if errors.Is(err, corrosion.ErrAutomationAlreadyImported) {
		return nil
	}
	if err != nil {
		return err
	}
	attested := s.automationImportSources(ctx, plan)
	target, sources, err := plan.Target(attested)
	if err != nil {
		return err
	}
	e, err := s.AutomationEngine()
	if err != nil {
		return err
	}
	return s.WithReleaseFeature(ctx, capabilities.FeatureAutomationState, func(ctx context.Context, grant capabilities.FeatureGrant) error {
		if err := e.ImportPrefix(ctx, grant, plan.Generation, target, sources); err != nil {
			return fmt.Errorf("automation import at voter generation %d: %w", plan.Generation, err)
		}
		return s.db.AutomationGrantImportedAuthority(ctx, grant, plan.Generation, attested)
	})
}
