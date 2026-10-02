package fleet

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

// TestFleet_RecoveryClaim_ClaimReleaseFreesALegacyProofStuckInFlight is the
// scoped escape for ha.claim.legacy_held (docs/design/recovery-claims.md §10
// item 37). Before claim_incarnation_v1 latched, VM A was recovered under a
// legacy claim to D, and D claimed the proof and left it in progress (a start
// that never finished). A was deleted and B re-created under the name on
// another host; that host died after the latch. B's claim re-proposes A's
// decision: D cannot exclude a proof it has in flight, and the voters refuse
// the value (it names A's source), so B is held and the condition names
// `lv cluster claim-release vm/<name>`.
//
// The release is D's: refused while D's own start lease shows a start of the
// name in progress, then given once D confirms nothing runs the proof. After
// it, D can never run A's proof — not even by resuming its own claim — and
// the next tick recovers B through a fresh claim. One owner of B results.
//
// Mutations: drop the operator_release override at the destination — D
// refuses and B stays held; skip the start-lease hold — the release is given
// while a start is in progress.
func TestFleet_RecoveryClaim_ClaimReleaseFreesALegacyProofStuckInFlight(t *testing.T) {
	ctx := context.Background()
	const name = "claimvm"
	c, cs, clock := incarnationFleet(t, 2571, func(_ *Cluster, a, victim *Node) {
		insertVM(t, a, name, victim.Name)
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: "full-" + a.Name, HostName: a.Name,
			Spec: `{}`, State: "running", CPUActual: 64, MemActual: 262144}, nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	latchIncarnation(c, false)
	a := c.Nodes[0]
	dead := map[string]bool{}

	// A: recovered under a legacy claim to D, which claims it and stalls.
	first := c.Nodes[4]
	alive := failHost(t, c, clock, dead, first)
	cs.Tick(ctx, a)
	vm := vmOn(t, a, name)
	if vm.PendingActionID == "" || vm.HostName == first.Name {
		t.Fatalf("A was not recovered under a legacy claim: %+v", vm)
	}
	stuck := vm.PendingActionID
	d := c.Node(vm.HostName)
	if d == a {
		t.Fatalf("the scenario needs D to be a peer of the coordinator, got %s", d.Name)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	if err := corrosion.ClaimActionProof(ctx, d.DB, stuck, d.Name); err != nil {
		t.Fatalf("D claims A's proof: %v", err)
	}
	c.WaitConverged(t, convergeTimeout, alive...)

	// A deleted; B re-created elsewhere; the latch forms; B's host dies.
	if err := corrosion.DeleteVM(ctx, a.DB, name); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	second := otherThan(t, alive, a, d)
	insertVM(t, a, name, second.Name)
	c.WaitConverged(t, convergeTimeout, alive...)
	latchIncarnation(c, true)
	alive = failHost(t, c, clock, dead, second)
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	if v := vmOn(t, a, name); v.HostName != second.Name || v.PendingActionID != "" {
		t.Fatalf("B was recovered beside a decision nobody excluded: %+v", v)
	}
	row, found, err := corrosion.GetHealthCondition(ctx, a.DB, "recovery_claim", "ha.claim.legacy_held", "vm", name)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved ||
		!strings.Contains(row.Evidence, stuck) || !strings.Contains(row.Evidence, "lv cluster claim-release vm/"+name) {
		t.Fatalf("ha.claim.legacy_held does not name proof %s and `lv cluster claim-release vm/%s`: found=%v err=%v %+v",
			stuck, name, found, err, row)
	}

	// A start of the name holds D's start lease: D refuses, nothing changes.
	lv := c.SelfClient(a)
	if held, err := health.TryVMStartLease(ctx, d.DB, d.Name, name, time.Now()); err != nil || held != d.Name {
		t.Fatalf("D's start lease: %q %v", held, err)
	}
	_, err = lv.ReleaseLegacyHeldClaim(ctx, &pb.ReleaseLegacyHeldClaimRequest{Kind: "vm", Name: name})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), d.Name) {
		t.Fatalf("release while D's start lease is held: %v, want D's refusal", err)
	}
	if ok, _ := d.DB.ProofAbandoned(ctx, stuck); ok {
		t.Fatal("D released a proof while a start of the name was in progress")
	}
	health.ReleaseVMStartLease(ctx, d.DB, d.Name, name)

	// Nothing runs it: D releases it.
	resp, err := lv.ReleaseLegacyHeldClaim(ctx, &pb.ReleaseLegacyHeldClaimRequest{Kind: "vm", Name: name})
	if err != nil {
		t.Fatalf("lv cluster claim-release vm/%s: %v", name, err)
	}
	if resp.GetDestHost() != d.Name || resp.GetProofId() != stuck {
		t.Fatalf("the release answered %+v, want %s releasing %s", resp, d.Name, stuck)
	}
	if ok, _ := d.DB.ProofAbandoned(ctx, stuck); !ok {
		t.Fatal("D did not record the release")
	}
	if err := corrosion.ClaimActionProofFenced(ctx, d.DB, stuck, d.Name, nil); !errors.Is(err, corrosion.ErrProofAbandoned) {
		t.Fatalf("D resumed its claim of a released proof: %v", err)
	}
	if rows, err := a.DB.Query(ctx, `SELECT 1 AS one FROM audit_log WHERE action = 'recovery_claim.release' AND target = ? AND result = 'ok'`,
		"vm/"+name); err != nil || len(rows) != 1 {
		t.Fatalf("the release wrote %d audit rows (%v), want 1", len(rows), err)
	}

	// The next tick recovers B through a fresh claim.
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	b := vmOn(t, a, name)
	if b.PendingActionID == "" || b.PendingActionID == stuck || b.HostName == second.Name {
		t.Fatalf("B was not recovered once D released A's proof: %+v", b)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, b.PendingActionID)
	if err != nil || !ok {
		t.Fatalf("read B's proof: ok=%v err=%v", ok, err)
	}
	assertFreshIncarnationClaim(t, a, pr.ActionProof, b.CreatedAt)
	a.Server.RecoveryClaimHealthTick(ctx)
	if row, found, _ := corrosion.GetHealthCondition(ctx, a.DB, "recovery_claim", "ha.claim.legacy_held", "vm", name); !found ||
		row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("ha.claim.legacy_held did not resolve once B was recovered: %+v", row)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	claimReconciler(t, c.Node(b.HostName)).ReconcileOnce(ctx)
	claimReconciler(t, d).ReconcileOnce(ctx)
	owners := 0
	for _, n := range alive {
		if st, _ := n.Virt.DomainState(name); st == string(libvirtfake.StateRunning) {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners of B after its recovery, want 1", owners)
	}
}
