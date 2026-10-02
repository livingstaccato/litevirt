package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// releaseFixture is `lv cluster claim-release`'s scenario on one node, which
// is the destination: VM A's reschedule to this node was claimed here and
// left in progress; A was deleted, B re-created under the name, and B's
// recovery after claim_incarnation_v1 latched re-proposed A's legacy
// decision, which the bridge could not exclude (it is in flight here), so
// ha.claim.legacy_held holds B.
func releaseFixture(t *testing.T) (*Server, *libvirtfake.Fake, corrosion.ClaimKey, corrosion.ClaimValue) {
	t.Helper()
	ctx := context.Background()
	s := claimingServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm-r", HostName: "dead", Spec: `{}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	stuck := corrosion.ActionProof{ID: "stuck", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm-r",
		DestHost: s.hostName, Coordinator: "coord", OwnerEpoch: "0"}
	if err := corrosion.WriteVMRescheduleProof(ctx, s.db, stuck, "vm-r", s.hostName); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.ClaimActionProof(ctx, s.db, stuck.ID, s.hostName); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "vm-r"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm-r", HostName: "dead", Spec: `{}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetVM(ctx, s.db, "vm-r")
	if err != nil || b == nil {
		t.Fatal(err)
	}
	key := corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm-r", OwnerEpoch: 0, Incarnation: corrosion.IncarnationOf(b.CreatedAt)}
	v := corrosion.ClaimValue{Proof: &stuck, SourceHost: "dead"}
	if excluded, why := s.legacyValueExcluded(ctx, key, v); excluded {
		t.Fatal("fixture: the bridge excluded a proof in flight on its destination")
	} else {
		s.noteLegacyHeld(ctx, key, v, why)
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, claimEvaluator, condClaimLegacyHeld, "vm", "vm-r")
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("fixture: ha.claim.legacy_held is not raised: %+v %v", row, err)
	}
	return s, fake, key, v
}

func releaseAudits(t *testing.T, s *Server, result string) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT 1 AS one FROM audit_log WHERE action = 'recovery_claim.release' AND target = 'vm/vm-r' AND result = ?`, result)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// TestReleaseLegacyHeldClaim_DestinationReleasesWhatNothingRuns: the release
// is the destination's signed foreign abandonment of a proof it left in
// flight, given once it has confirmed nothing runs it. Afterwards no runner
// can take the proof, this node's own resume included, and the bridge's next
// ask excludes it — so the next tick decides B afresh. The condition's text
// names the command, and the release is audited.
//
// Mutations: drop the operator_release override (abandon with the plain
// foreign exclusion) — the destination refuses the proof in flight; skip the
// audit on success — no audit row.
func TestReleaseLegacyHeldClaim_DestinationReleasesWhatNothingRuns(t *testing.T) {
	ctx := context.Background()
	s, _, key, v := releaseFixture(t)
	row, _, _ := corrosion.GetHealthCondition(ctx, s.db, claimEvaluator, condClaimLegacyHeld, "vm", "vm-r")
	if !strings.Contains(row.Evidence, "lv cluster claim-release vm/vm-r") {
		t.Fatalf("ha.claim.legacy_held does not name the release command: %s", row.Evidence)
	}

	resp, err := s.ReleaseLegacyHeldClaim(adminCtx(), &pb.ReleaseLegacyHeldClaimRequest{Kind: "vm", Name: "vm-r"})
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if resp.GetDestHost() != s.hostName || resp.GetProofId() != "stuck" {
		t.Fatalf("release answered %+v", resp)
	}
	if ok, _ := s.db.ProofAbandoned(ctx, "stuck"); !ok {
		t.Fatal("the destination did not record the abandonment")
	}
	if err := corrosion.ClaimActionProofFenced(ctx, s.db, "stuck", s.hostName, nil); !errors.Is(err, corrosion.ErrProofAbandoned) {
		t.Fatalf("a runner re-claimed the released proof: %v", err)
	}
	if excluded, why := s.legacyValueExcluded(ctx, key, v); !excluded {
		t.Fatalf("the bridge's next ask does not exclude the released proof: %s", why)
	}
	if n := releaseAudits(t, s, "ok"); n != 1 {
		t.Fatalf("%d audit rows for the release, want 1", n)
	}
}

// TestReleaseLegacyHeldClaim_RefusedWhileAnythingMightRunIt: each hold a
// runner takes, and a live domain, refuses the release; nothing is
// abandoned, and the refusal is audited.
//
// Mutations: skip the start-lease hold — the reconciler's lease does not
// refuse; skip the operation lock — an in-process operation does not refuse;
// skip the domain check — an active domain does not refuse; treat a missing
// libvirt backend as idle — it does not refuse.
func TestReleaseLegacyHeldClaim_RefusedWhileAnythingMightRunIt(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		what  string
		setup func(t *testing.T, s *Server, fake *libvirtfake.Fake) func()
	}{
		{"the reconciler holds the start lease", func(t *testing.T, s *Server, _ *libvirtfake.Fake) func() {
			if held, err := health.TryVMStartLease(ctx, s.db, s.hostName, "vm-r", time.Now()); err != nil || held != s.hostName {
				t.Fatalf("take the lease: %q %v", held, err)
			}
			return func() {}
		}},
		{"an operation holds the VM", func(t *testing.T, s *Server, _ *libvirtfake.Fake) func() {
			return s.lockVM("vm-r")
		}},
		{"a domain of the name is active", func(t *testing.T, s *Server, fake *libvirtfake.Fake) func() {
			fake.SetState("vm-r", libvirtfake.StateRunning)
			return func() {}
		}},
		{"a paused domain of the name is active", func(t *testing.T, s *Server, fake *libvirtfake.Fake) func() {
			fake.SetState("vm-r", libvirtfake.StatePaused)
			return func() {}
		}},
		{"no libvirt backend", func(t *testing.T, s *Server, _ *libvirtfake.Fake) func() {
			s.virt = nil
			return func() {}
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			s, fake, _, _ := releaseFixture(t)
			undo := tc.setup(t, s, fake)
			_, err := s.ReleaseLegacyHeldClaim(adminCtx(), &pb.ReleaseLegacyHeldClaimRequest{Kind: "vm", Name: "vm-r"})
			undo()
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("release while %s: %v, want FailedPrecondition", tc.what, err)
			}
			if ok, _ := s.db.ProofAbandoned(ctx, "stuck"); ok {
				t.Fatalf("the proof was abandoned while %s", tc.what)
			}
			if n := releaseAudits(t, s, "refused"); n != 1 {
				t.Fatalf("%d audit rows for the refused release, want 1", n)
			}
		})
	}
	// A shut-off leftover domain runs nothing: released.
	s, fake, _, _ := releaseFixture(t)
	fake.DefineStoppedDomain("vm-r", "52:54:00:00:00:01")
	if _, err := s.ReleaseLegacyHeldClaim(adminCtx(), &pb.ReleaseLegacyHeldClaimRequest{Kind: "vm", Name: "vm-r"}); err != nil {
		t.Fatalf("release beside a shut-off domain: %v", err)
	}
	// The release gives back what it took: a start may take the lease again.
	if held, err := health.TryVMStartLease(ctx, s.db, s.hostName, "vm-r", time.Now()); err != nil || held != s.hostName {
		t.Fatalf("the release kept the start lease: held by %q (%v)", held, err)
	}
}

// TestReleaseLegacyHeldClaim_UnreachableDestinationPointsAtRemoval: a
// destination that does not answer cannot confirm anything; nothing is
// released and the refusal names `lv host rm --dead`.
//
// Mutation: treat a dial failure as a refusal by the destination — the
// message no longer points at the removal.
func TestReleaseLegacyHeldClaim_UnreachableDestinationPointsAtRemoval(t *testing.T) {
	ctx := context.Background()
	s, _, key, v := releaseFixture(t)
	gone := *v.Proof
	gone.ID, gone.DestHost = "gone-proof", "gone-host"
	if err := corrosion.WriteActionProof(ctx, s.db, gone); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `DELETE FROM health_conditions WHERE code = ?`, condClaimLegacyHeld); err != nil {
		t.Fatal(err)
	}
	s.noteLegacyHeld(ctx, key, corrosion.ClaimValue{Proof: &gone, SourceHost: "dead"}, "gone-host did not answer")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("dial gone-host: connection refused")
	}
	_, err := s.ReleaseLegacyHeldClaim(adminCtx(), &pb.ReleaseLegacyHeldClaimRequest{Kind: "vm", Name: "vm-r"})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "lv host rm --dead gone-host") {
		t.Fatalf("release with an unreachable destination: %v, want Unavailable naming `lv host rm --dead gone-host`", err)
	}
	if n := releaseAudits(t, s, "refused"); n != 1 {
		t.Fatalf("%d audit rows for the refused release, want 1", n)
	}
}

// TestReleaseLegacyHeldClaim_Scope: admin only, and only for a workload an
// open ha.claim.legacy_held holds.
//
// Mutations: drop the role check — a viewer releases; drop the condition
// lookup — a workload nothing holds is released.
func TestReleaseLegacyHeldClaim_Scope(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := releaseFixture(t)
	viewer := context.WithValue(context.Background(), ctxKeyRole, "viewer")
	if _, err := s.ReleaseLegacyHeldClaim(viewer, &pb.ReleaseLegacyHeldClaimRequest{Kind: "vm", Name: "vm-r"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a viewer's release: %v, want PermissionDenied", err)
	}
	s.resolveLegacyHeld(ctx, true)
	if _, err := s.ReleaseLegacyHeldClaim(adminCtx(), &pb.ReleaseLegacyHeldClaimRequest{Kind: "vm", Name: "vm-r"}); status.Code(err) != codes.NotFound {
		t.Fatalf("a release with no open condition: %v, want NotFound", err)
	}
	if ok, _ := s.db.ProofAbandoned(ctx, "stuck"); ok {
		t.Fatal("a release out of scope abandoned the proof")
	}
}

// TestHoldWorkloadIdle_Container: a container is idle only under its
// operation lock, with no running container of the name.
//
// Mutations: skip the container lock — a held lock does not refuse; accept a
// running container — it does not refuse.
func TestHoldWorkloadIdle_Container(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	rt := &fakeCTRuntime{existsByName: map[string]bool{"ct-r": true}, stateByName: map[string]string{"ct-r": "running"}}
	s.SetContainerRuntime(rt)
	if _, err := s.holdWorkloadIdle(ctx, corrosion.ClaimKindContainer, "ct-r"); err == nil {
		t.Fatal("a running container was confirmed idle")
	}
	rt.stateByName["ct-r"] = "stopped"
	unlock := s.LockContainer("ct-r")
	if _, err := s.holdWorkloadIdle(ctx, corrosion.ClaimKindContainer, "ct-r"); err == nil {
		t.Fatal("a container an operation holds was confirmed idle")
	}
	unlock()
	release, err := s.holdWorkloadIdle(ctx, corrosion.ClaimKindContainer, "ct-r")
	if err != nil {
		t.Fatalf("a stopped container nothing holds: %v", err)
	}
	if _, ok := s.TryLockContainer("ct-r"); ok {
		t.Fatal("the hold does not keep the container lock")
	}
	release()
	if u, ok := s.TryLockContainer("ct-r"); !ok {
		t.Fatal("the release did not give the container lock back")
	} else {
		u()
	}
}
