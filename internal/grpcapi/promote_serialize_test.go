package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// operatorPromoteServer is claimingServer (this host the whole voter
// generation, claims enforced) with db-c on dead-host, a replica of its root
// here, and a libvirt fake. It returns db-c's row and its claim key.
func operatorPromoteServer(t *testing.T) (*Server, *corrosion.VMRecord, corrosion.ClaimKey) {
	t.Helper()
	s := claimingServer(t)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	seedReplicaOfAge(t, s, "db-c", "0 * * * *", 10*time.Minute)
	// A raw replica the overlay can be built on (seedReplicaOfAge's is a
	// 7-byte stand-in), newer, so it is the one chosen.
	dir, err := s.replicaPoolDir(context.Background(), "dr")
	if err != nil {
		t.Fatal(err)
	}
	seedReplica(t, dir, "", "db-c", "root", stamp(5*time.Minute), "raw", 1<<20)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "other-host", Address: "10.0.0.7", State: "active"}); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(context.Background(), s.db, "db-c")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	return s, vm, s.ClaimKeyFor(context.Background(), "vm", "db-c", vm.OwnerEpoch, vm.CreatedAt)
}

func operatorPromote(s *Server, vm string) error {
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}
	return s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: vm, Force: true, NoLocalize: true}, stream)
}

// decideValue decides v at key on s's voters, as a coordinator would.
func decideValue(t *testing.T, s *Server, key corrosion.ClaimKey, p corrosion.ActionProof) {
	t.Helper()
	out, err := s.DecideRecoveryClaim(context.Background(), key, corrosion.ClaimValue{Proof: &p, SourceHost: "dead-host"}, 5, nil)
	if err != nil || !out.Ours {
		t.Fatalf("decide %s at %s: ours=%v err=%v", p.ID, key, out.Ours, err)
	}
}

// Review PB-F1: an operator's promotion of a VM whose recovery the cluster has
// already decided — here a coordinator's reschedule to another host — is
// refused before anything is started, and the refusal names the decision and
// what to wait for. It used to go ahead: it never claimed, so with --force or
// another replica host both could start the VM.
//
// Mutation "no operator claim" (claimOperatorPromote not called) — red: the
// promotion starts db-c.
func TestPromote_AnOperatorsPromotionWaitsForADecidedRecovery(t *testing.T) {
	s, vm, key := operatorPromoteServer(t)
	decideValue(t, s, key, corrosion.ActionProof{ID: "coord-proof", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "db-c", DestHost: "other-host", Coordinator: "other-host", OwnerEpoch: strconv.FormatInt(vm.OwnerEpoch, 10)})

	err := operatorPromote(s, "db-c")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("operator promotion over a decided recovery = %v, want FailedPrecondition", err)
	}
	for _, want := range []string{"has decided its recovery", "reschedule to other-host by other-host (proof coord-proof)",
		"Wait for that recovery to finish", "lv cluster claim vm/db-c"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal = %q, want %q", err, want)
		}
	}
	if s.virt.(*libvirtfake.Fake).DomainExists("db-c") {
		t.Error("the refused promotion defined db-c")
	}
}

// The other order: the operator's promotion claims first and starts the VM;
// the coordinator's automated promotion of the same VM at the same owner
// epoch then learns the operator's decision and is refused. The decided
// value names the operator, never a host a coordinator would take for its own.
//
// Mutation "no operator claim" — red: the coordinator's claim is its own.
func TestPromote_AnOperatorsDecidedPromotionHoldsOffTheCoordinator(t *testing.T) {
	s, vm, _ := operatorPromoteServer(t)
	if err := operatorPromote(s, "db-c"); err != nil {
		t.Fatalf("operator promotion: %v", err)
	}
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("db-c"); st != "running" {
		t.Fatalf("db-c state = %q, want running", st)
	}
	// The coordinator, still reading the owner epoch the operator left.
	proof := &pb.RuntimeActionProof{Id: "auto-proof", Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: "db-c",
		DestHost: "other-host", Coordinator: s.hostName, LeaseHolder: s.hostName, OwnerEpoch: strconv.FormatInt(vm.OwnerEpoch, 10)}
	err := s.claimPromote(context.Background(), vm, proof)
	var lost *RecoveryClaimLostError
	if !errors.As(err, &lost) {
		t.Fatalf("the coordinator's claim after the operator's = %v, want RecoveryClaimLostError", err)
	}
	if lost.Decided.Coordinator != operatorClaimPrefix+s.hostName || lost.Decided.DestHost != s.hostName {
		t.Errorf("decided %+v, want the operator's promotion to %s", lost.Decided, s.hostName)
	}
}

// An operator's promotion here that decided the claim and failed before it
// started the VM leaves its decision holding the key: a re-run completes it
// rather than being refused by it.
func TestPromote_AnOperatorsReRunCompletesItsOwnDecision(t *testing.T) {
	s, vm, key := operatorPromoteServer(t)
	decideValue(t, s, key, corrosion.ActionProof{ID: "earlier-op", Action: corrosion.ActionPromote, TargetKind: "vm",
		TargetName: "db-c", DestHost: s.hostName, Coordinator: operatorClaimPrefix + s.hostName, LeaseHolder: s.hostName,
		OwnerEpoch: strconv.FormatInt(vm.OwnerEpoch, 10)})
	if err := operatorPromote(s, "db-c"); err != nil {
		t.Fatalf("re-run over this host's own operator decision: %v", err)
	}
}

// A coordinator's promote decided for this host that this host has abandoned
// (it failed before StartDomain and the coordinator fell back) never runs:
// the operator's claim moves past it to the next attempt on this host's own
// signed abandonment, and the promotion goes ahead. Without that a stuck
// fallback would refuse the operator's promotion for good.
//
// Mutation "no supersede" (operatorSupersedeEvidence returns nil) — red.
func TestPromote_AnOperatorsClaimMovesPastAnAbandonedPromote(t *testing.T) {
	s, vm, key := operatorPromoteServer(t)
	decideValue(t, s, key, corrosion.ActionProof{ID: "failed-auto", Action: corrosion.ActionPromote, TargetKind: "vm",
		TargetName: "db-c", DestHost: s.hostName, Coordinator: "other-host", OwnerEpoch: strconv.FormatInt(vm.OwnerEpoch, 10)})
	if err := s.db.AbandonProof(context.Background(), "failed-auto", key, "test: failed before StartDomain"); err != nil {
		t.Fatal(err)
	}
	if err := operatorPromote(s, "db-c"); err != nil {
		t.Fatalf("operator promotion past an abandoned promote: %v", err)
	}
	next := key
	next.Attempt = 1
	if st := mustClaimState(t, s, next); st.Value == nil || st.Value.Proof == nil ||
		st.Value.Proof.Coordinator != operatorClaimPrefix+s.hostName {
		t.Errorf("attempt 1 holds %+v, want the operator's promotion", st.Value)
	}
}

func mustClaimState(t *testing.T, s *Server, key corrosion.ClaimKey) corrosion.ClaimVoterState {
	t.Helper()
	st, _, err := s.db.ClaimState(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// Without claims, an operator's promotion refuses while this replica holds a
// recovery proof of the VM in flight at its current owner epoch: prepared or
// in progress, and either written within the freshness window or with a start
// recorded (the VM may be running at its destination). A stale one that never
// started, a terminal one, and one at another epoch do not count.
//
// Mutation "no in-flight check" (refuseWhileRecoveryInFlight returns nil) —
// red on the refused rows.
func TestPromote_AnOperatorsPromotionWaitsForARecoveryInFlight(t *testing.T) {
	for _, c := range []struct {
		name, action, status, steps, epoch string
		age                                time.Duration
		refused                            string
	}{
		{"a fresh promote", corrosion.ActionPromote, "in_progress", "", "0", time.Minute, "failover's promote of it to other-host"},
		{"a fresh reschedule", corrosion.ActionReschedule, "prepared", "", "0", time.Minute, "failover's reschedule of it to other-host"},
		{"a stale promote that started", corrosion.ActionPromote, "in_progress", "start_attempted", "0", 3 * time.Hour,
			"`lv doctor repair-owner db other-host`"},
		{"a stale promote that never started", corrosion.ActionPromote, "in_progress", "", "0", 3 * time.Hour, ""},
		{"a completed promote", corrosion.ActionPromote, "completed", "started", "0", time.Minute, ""},
		{"a promote at another epoch", corrosion.ActionPromote, "in_progress", "", "7", time.Minute, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			poolDir := setPromoteVMRows(t, s, "db", nil)
			seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
			ctx := context.Background()
			if err := corrosion.WriteActionProof(ctx, s.db, corrosion.ActionProof{ID: "p1", Action: c.action, TargetKind: "vm",
				TargetName: "db", DestHost: "other-host", Coordinator: "coord", OwnerEpoch: c.epoch}); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Execute(ctx, `UPDATE runtime_action_proofs SET status = ?, step_state = ?, updated_at = ? WHERE id = 'p1'`,
				c.status, c.steps, time.Now().Add(-c.age).UTC().Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}
			err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}, stream)
			if c.refused == "" {
				if err != nil {
					t.Fatalf("promotion = %v, want it to go ahead", err)
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), c.refused) ||
				!strings.Contains(err.Error(), "proof p1") {
				t.Fatalf("promotion = %v, want FailedPrecondition naming %q and the proof", err, c.refused)
			}
			if s.virt.(*libvirtfake.Fake).DomainExists("db") {
				t.Error("the refused promotion defined db")
			}
		})
	}
}

// decidedAt is the proof ID of the value s's voter accepted at key.
func decidedAt(t *testing.T, s *Server, key corrosion.ClaimKey) string {
	t.Helper()
	st := mustClaimState(t, s, key)
	if st.Value == nil || st.Value.Proof == nil {
		t.Fatalf("nothing accepted at %s", key)
	}
	return st.Value.Proof.ID
}

// Review I2: an operator's promotion whose claim was decided but which failed
// before the VM started releases the claim (this host abandons the value), so
// a coordinator can move past it; and a re-run here moves past it to the next
// attempt and starts the VM.
//
// Mutation "no release" (releaseOperatorClaim does nothing) — red.
func TestPromote_AFailedOperatorPromotionReleasesItsClaim(t *testing.T) {
	s, _, key := operatorPromoteServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	fake.FailStartDomain = func(string) error { return errors.New("qemu refused") }
	if err := operatorPromote(s, "db-c"); err == nil {
		t.Fatal("the promotion succeeded with StartDomain failing")
	}
	id := decidedAt(t, s, key)
	if abandoned, err := s.db.ProofAbandoned(context.Background(), id); err != nil || !abandoned {
		t.Fatalf("the failed promotion's claim %s is not released: abandoned=%v err=%v", id, abandoned, err)
	}
	if _, err := s.RequestAbandonment(context.Background(), s.hostName, key, id, "a coordinator moves past it"); err != nil {
		t.Fatalf("this host does not sign the released claim's abandonment: %v", err)
	}
	fake.FailStartDomain = nil
	if err := operatorPromote(s, "db-c"); err != nil {
		t.Fatalf("re-run after the release: %v", err)
	}
	if st, _ := fake.DomainState("db-c"); st != "running" {
		t.Errorf("db-c = %q, want running", st)
	}
}

// Review I2: once an operator's promotion has started the VM its claim value
// is never abandoned — not by a request (a coordinator moving past it), not
// by AbandonProof itself — so no later attempt is decided elsewhere while the
// VM runs here. A value abandoned before the start fence refuses the start.
//
// Mutation "no start fence" (fenceOperatorStart records nothing) — red.
func TestPromote_AStartedOperatorPromotionIsNeverAbandoned(t *testing.T) {
	s, _, key := operatorPromoteServer(t)
	s.db.SetStartedProofCheck(s.operatorStartRecorded)
	if err := operatorPromote(s, "db-c"); err != nil {
		t.Fatalf("operator promotion: %v", err)
	}
	id := decidedAt(t, s, key)
	if _, err := s.RequestAbandonment(context.Background(), s.hostName, key, id, "x"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("abandonment of a started operator promotion = %v, want FailedPrecondition", err)
	}
	if err := s.db.AbandonProof(context.Background(), id, key, "x"); !errors.Is(err, corrosion.ErrProofExecuted) {
		t.Errorf("AbandonProof of a started operator promotion = %v, want ErrProofExecuted", err)
	}
	if abandoned, _ := s.db.ProofAbandoned(context.Background(), id); abandoned {
		t.Error("the started operator promotion's claim was abandoned")
	}

	// The other order: abandoned first, then the fence refuses the start.
	oc := &operatorClaim{Key: key, ProofID: "abandoned-first"}
	if err := s.db.AbandonProof(context.Background(), oc.ProofID, key, "x"); err != nil {
		t.Fatal(err)
	}
	if err := s.fenceOperatorStart(context.Background(), oc); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("start fence over an abandoned claim = %v, want FailedPrecondition", err)
	}
}

// Review I-1: a StartDomain that fails while libvirt cannot be asked —
// the connection dropped, so the state read fails too — may have launched
// qemu. The start fence stays and the claim is not released: nothing can
// abandon the value, so no coordinator recovers the VM elsewhere while it may
// be running here. (A stall an operator resolves, never two starts.)
//
// Mutation "unfence on any read error" (round 2's DomainState shape) — red.
func TestPromote_AnAmbiguousStartFailureKeepsTheFence(t *testing.T) {
	s, _, key := operatorPromoteServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	dropped := errors.New("libvirt: connection dropped")
	fake.FailStartDomain = func(string) error { return dropped }
	fake.FailDomainState = func(string) error { return dropped }
	if err := operatorPromote(s, "db-c"); err == nil {
		t.Fatal("the promotion succeeded with StartDomain failing")
	}
	id := decidedAt(t, s, key)
	if !s.operatorStartRecorded(id) {
		t.Error("the start fence was withdrawn on an unanswerable start")
	}
	if abandoned, _ := s.db.ProofAbandoned(context.Background(), id); abandoned {
		t.Error("the claim of a start that may have run was released")
	}
	if _, err := s.RequestAbandonment(context.Background(), s.hostName, key, id, "a coordinator moves past it"); err == nil {
		t.Error("a coordinator's abandonment request was signed for a start that may have run")
	}
}

// Review I-1 (belt and braces) and m1: whatever the records say, nothing is
// abandoned on a host where a domain of the workload is active, or libvirt
// cannot say it is not. A value with no start fence — a promotion resumed
// over a domain an earlier run started — is still never abandoned while that
// domain runs.
//
// Mutation "no domain check in abandonRecoveryProof" — red.
func TestAbandon_IsRefusedWhileTheWorkloadsDomainMayRun(t *testing.T) {
	s, _, key := operatorPromoteServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("db-c", libvirtfake.StateRunning)
	if _, err := s.RequestAbandonment(context.Background(), s.hostName, key, "unfenced", "x"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("abandonment with db-c running here = %v, want FailedPrecondition", err)
	}
	fake.SetState("db-c", libvirtfake.StateShutdown)
	fake.FailDomainState = func(string) error { return errors.New("connection dropped") }
	if _, err := s.RequestAbandonment(context.Background(), s.hostName, key, "unfenced", "x"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("abandonment with libvirt unanswerable = %v, want FailedPrecondition", err)
	}
	fake.FailDomainState = nil
	if _, err := s.RequestAbandonment(context.Background(), s.hostName, key, "unfenced", "x"); err != nil {
		t.Errorf("abandonment with db-c shut off here: %v", err)
	}
}

// A promote test must keep its markers in its own data dir. The markers used
// to land in ./promote-markers and ./promote-started under the package
// directory, where concurrent test processes deleted each other's.
//
// The test runs in a fresh working directory of its own, so the check sees only
// a relative write by this test's server, never a directory some other process
// left in the shared package directory.
func TestPromoteMarkers_StayInTheServersDataDir(t *testing.T) {
	t.Chdir(t.TempDir())
	s := testServer(t)
	if s.dataDir == "" {
		t.Fatal("testServer has no dataDir; its markers would be written relative to the working directory")
	}
	if err := s.writePromoteMarker("guarddb", "proof-1"); err != nil {
		t.Fatalf("writePromoteMarker: %v", err)
	}
	if p := s.promoteMarkerPath("guarddb"); !filepath.IsAbs(p) {
		t.Fatalf("marker path %q is relative", p)
	}
	if !strings.HasPrefix(s.promoteMarkerPath("guarddb"), s.dataDir) {
		t.Fatalf("marker path %q is outside dataDir %q", s.promoteMarkerPath("guarddb"), s.dataDir)
	}
	if p := s.operatorStartPath("proof-1"); !strings.HasPrefix(p, s.dataDir) {
		t.Fatalf("operator start path %q is outside dataDir %q", p, s.dataDir)
	}
	for _, d := range []string{"promote-markers", "promote-started"} {
		if _, err := os.Stat(d); err == nil {
			t.Errorf("./%s exists under the working directory", d)
		}
	}
}
