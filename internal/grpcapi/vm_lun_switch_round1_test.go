package grpcapi

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Release-token switch, fix round 1 (switch-review-iscsi.md).

// lunRecordingGate is a release-feature gate that records the feature's use,
// as the real gate does on a first use, and counts its calls.
type lunRecordingGate struct {
	t     testing.TB
	db    *corrosion.Client
	host  string
	calls *atomic.Int32
}

func (g lunRecordingGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.calls.Add(1)
	if err := corrosion.RecordReleaseFeatureUse(ctx, g.db, capabilities.ReleaseToken, string(f), g.host, true); err != nil {
		return err
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g lunRecordingGate) FeatureAvailable(capabilities.Feature) bool { return true }

// forgetLUNUse removes the iscsi_lun_claim use lunTestServer records.
func forgetLUNUse(t *testing.T, s *Server) {
	t.Helper()
	if _, err := s.db.DB().ExecContext(context.Background(), `DELETE FROM cluster_policies WHERE key = ?`,
		"release_feature/"+capabilities.ReleaseToken+"/"+string(capabilities.FeatureISCSILUNClaim)); err != nil {
		t.Fatal(err)
	}
}

func lunUsed(t *testing.T, s *Server) bool {
	t.Helper()
	used, err := corrosion.ReleaseFeatureUsed(context.Background(), s.db, capabilities.ReleaseToken,
		string(capabilities.FeatureISCSILUNClaim))
	if err != nil {
		t.Fatal(err)
	}
	return used
}

// I-1: a create or re-create refused by a local check — a LUN held by a live
// VM, an image change that would not reach a kept LUN — writes no feature
// data, so it must not mark iscsi_lun_claim used either: the gate runs only
// once every local refusal has passed.
//
// Mutation: run the gate before the local refusals (where it was) — the gate
// is asked, the use recorded, and this goes red.
func TestISCSI_ALocalRefusalRecordsNoUse(t *testing.T) {
	ctx := adminCtx()
	t.Run("create on a LUN a live VM holds", func(t *testing.T) {
		s := lunTestServer(t)
		if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
			t.Fatalf("create a: %v", err)
		}
		forgetLUNUse(t, s)
		calls := &atomic.Int32{}
		s.SetReleaseFeatureGate(lunRecordingGate{t: t, db: s.db, host: s.hostName, calls: calls})
		_, err := s.CreateVM(ctx, lunVM("b", "lun0"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "a"`) {
			t.Fatalf("create b on a's LUN: got %v, want FailedPrecondition naming a", err)
		}
		if n := calls.Load(); n != 0 {
			t.Errorf("the gate was asked %d times for a create refused before any claim", n)
		}
		if lunUsed(t, s) {
			t.Error("a create refused \"held\" marked iscsi_lun_claim used")
		}
	})
	t.Run("re-create whose image change would not reach the kept LUN", func(t *testing.T) {
		s := lunTestServer(t)
		if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
			t.Fatalf("create a: %v", err)
		}
		forgetLUNUse(t, s)
		calls := &atomic.Int32{}
		s.SetReleaseFeatureGate(lunRecordingGate{t: t, db: s.db, host: s.hostName, calls: calls})
		spec := lunVM("a", "lun0").Spec
		spec.Image = "other-image"
		_, done, err := s.preflightLUNs(ctx, spec, vmRecord(t, s, "a"), s.hostName)
		if err == nil {
			done(recreateNotAttempted)
			t.Fatal("a re-create changing the image of a kept LUN without overwrite was not refused")
		}
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "overwrite") {
			t.Fatalf("preflight: got %v, want FailedPrecondition asking for overwrite", err)
		}
		if n := calls.Load(); n != 0 {
			t.Errorf("the gate was asked %d times for a re-create refused before any claim", n)
		}
		if lunUsed(t, s) {
			t.Error("a refused re-create marked iscsi_lun_claim used")
		}
	})
}

// M-6: a rebuild before the latch is refused by the preflight's release gate
// with the release text; the VM stays as it was, and no hold or claim is
// left.
//
// Mutation: drop the preflight's gate — the writers fail closed with Internal
// "no grant", and this goes red on the code and text.
func TestRebuildVM_ISCSI_RefusedUntilTheUpgradeFinishes(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create a: %v", err)
	}
	before := lunClaimRows(t, s)
	want := "the cluster upgrade must finish first (iscsi_lun_claim needs " + capabilities.ReleaseToken + ")"
	s.SetReleaseFeatureGate(fakeFeatureGate{err: status.Error(codes.FailedPrecondition, want+": not yet: node-2 (1.9.0)")})
	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "a"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
		t.Fatalf("rebuild before the latch: got %v, want FailedPrecondition %q", err, want)
	}
	if rec, gerr := corrosion.GetVM(context.Background(), s.db, "a"); gerr != nil || rec == nil {
		t.Fatalf("a after a refused rebuild: %v %v", rec, gerr)
	}
	if toks, terr := s.lunHoldTokens(); terr != nil || len(toks) != 0 {
		t.Fatalf("a refused rebuild left holds %v (%v)", toks, terr)
	}
	if n := lunClaimRows(t, s); n != before {
		t.Fatalf("LUN claim rows %d after a refused rebuild, want %d", n, before)
	}
}

// M-5: a plain delete under the REAL release gate, refusing because the token
// has not latched (a peer is unreachable, no durable marker): the delete
// stands, and the marker is not written — the gate refuses before the write
// runs.
//
// Mutation (health.WithFeature runs the write before its gate, M8): the
// marker is written under a refusal and this goes red.
func TestDeleteVM_ISCSI_ARefusingReleaseGateWritesNoMarker(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-host", Address: "10.0.0.10", State: "active"}); err != nil {
		t.Fatal(err)
	}
	s.SetReleaseFeatureGate(health.NewChecker(s.hostName, s.pkiDir, s.db))
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "a"}); err != nil {
		t.Fatalf("plain delete under a refusing release gate: %v", err)
	}
	requireNoVM(t, s, "a")
	if rec, err := corrosion.GetLUNPlainDelete(context.Background(), s.db, mustLUNKey(t, "10.0.0.1", "0")); err != nil || rec != "" {
		t.Fatalf("plain-delete record under a refusing gate = %q (%v), want none", rec, err)
	}
}

// lunBlockingGate blocks until its context ends, and reports the deadline it
// was given.
type lunBlockingGate struct{ deadline chan time.Duration }

func (g lunBlockingGate) WithFeature(ctx context.Context, _ capabilities.Feature,
	_ func(context.Context, capabilities.FeatureGrant) error) error {
	d, ok := ctx.Deadline()
	if !ok {
		g.deadline <- -1
		return status.Error(codes.Unavailable, "no deadline")
	}
	g.deadline <- time.Until(d)
	<-ctx.Done()
	return status.Error(codes.Unavailable, "acknowledgement timed out")
}

func (g lunBlockingGate) FeatureAvailable(capabilities.Feature) bool { return true }

// M-1: a plain delete waits on the gate for at most lunPlainDeleteGateTimeout
// (3s), not the gate's own acknowledgement budget, and is never refused.
//
// Mutation: drop the bound — the gate sees no deadline and this goes red.
func TestDeleteVM_ISCSI_ThePlainDeleteGateIsBounded(t *testing.T) {
	if lunPlainDeleteGateTimeout != 3*time.Second {
		t.Fatalf("lunPlainDeleteGateTimeout = %v, want 3s", lunPlainDeleteGateTimeout)
	}
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create a: %v", err)
	}
	g := lunBlockingGate{deadline: make(chan time.Duration, 1)}
	s.SetReleaseFeatureGate(g)
	start := time.Now()
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "a"}); err != nil {
		t.Fatalf("plain delete with a stalled gate: %v", err)
	}
	took := time.Since(start)
	d := <-g.deadline
	if d <= 0 || d > lunPlainDeleteGateTimeout {
		t.Fatalf("the gate's deadline was %v away, want within %v", d, lunPlainDeleteGateTimeout)
	}
	if took > lunPlainDeleteGateTimeout+5*time.Second {
		t.Fatalf("the delete took %v with a stalled gate", took)
	}
	requireNoVM(t, s, "a")
}
