package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// fakeFailoverGate is a configurable FailoverGate: DecisionGate/QuorumProof/Enforced
// all report "healthy + enforced" so a test can isolate the PeerSupports (mint-site
// destination) decision.
type fakeFailoverGate struct {
	supports map[string]bool
	// enforced maps token → enforcement decision. A nil map means "all enforced"
	// (back-compat for tests that only exercise the mint-site PeerSupports path).
	enforced map[string]bool
	// onDecision runs inside DecisionGate, which is the last thing the loop
	// does before acting on a VM. It is the seam for "the tenure ended
	// MID-LOOP" -- the only shape in which a stale-tenure write is reachable,
	// since a lapse before the tick is caught by the tick's own lease gate.
	onDecision func()
}

func (f fakeFailoverGate) DecisionGate(context.Context) health.GateResult {
	if f.onDecision != nil {
		f.onDecision()
	}
	return health.GateResult{OK: true}
}
func (f fakeFailoverGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	return health.QuorumYes, 2, 2
}
func (f fakeFailoverGate) Enforced(_ context.Context, token string) bool {
	if f.enforced == nil {
		return true
	}
	return f.enforced[token]
}
func (f fakeFailoverGate) PeerSupportsFresh(_ context.Context, peer, _ string) bool {
	return f.supports[peer]
}

// destAdvertisesGate is the fail-closed pre-mint check (Phase 1): the coordinator
// stamps a proof for a destination ONLY when a fresh Ping confirms it advertises
// the gate. A regressed/replaced target that no longer advertises is refused, and a
// nil gate fails closed — so a latched coordinator can never stamp a proof a target
// can't honor.
func TestDestAdvertisesGate(t *testing.T) {
	ctx := context.Background()
	c := &Coordinator{hostName: "node-a", Gate: fakeFailoverGate{supports: map[string]bool{"node-b": true}}}

	if !c.destAdvertisesGate(ctx, "node-b") {
		t.Fatal("a peer advertising the gate must pass")
	}
	if c.destAdvertisesGate(ctx, "node-c") {
		t.Fatal("a peer NOT advertising the gate must be refused (fail closed)")
	}
	// A nil gate fails closed.
	if (&Coordinator{hostName: "node-a"}).destAdvertisesGate(ctx, "node-b") {
		t.Fatal("nil gate must fail closed")
	}
	// A self-fenced coordinator never reports ITSELF as gate-capable (it de-advertises),
	// so it can't stamp a self-targeted proof — even if this build advertised the token.
	fenced := &Coordinator{hostName: "node-a", Gate: fakeFailoverGate{}, SelfFenced: func() bool { return true }}
	if fenced.destAdvertisesGate(ctx, "node-a") {
		t.Fatal("a self-fenced node must not report itself gate-capable")
	}
}

// The coordinator must bind image-recreate relocation authorization to the
// exact container ownership generation it observed. Otherwise a prepared proof
// can survive an ownership ABA cycle and authorize a later recreation.
func TestImageRecreateProofCarriesOwnerEpoch(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "dead", Name: "ct1", State: "running", Image: "alpine:3.19",
		OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := db.Execute(ctx, `UPDATE containers SET owner_epoch = 7 WHERE host_name = 'dead' AND name = 'ct1'`); err != nil {
		t.Fatalf("seed owner epoch: %v", err)
	}
	ct, err := corrosion.GetContainer(ctx, db, "dead", "ct1")
	if err != nil || ct == nil {
		t.Fatalf("GetContainer: %v / nil=%v", err, ct == nil)
	}
	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	c.imageRecreateOrSkip(ctx, &corrosion.HostRecord{Name: "dead"}, *ct, "live")

	rows, err := db.Query(ctx, `SELECT owner_epoch, relocation_token FROM runtime_action_proofs WHERE target_name = 'ct1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("proof rows=%d err=%v; want one", len(rows), err)
	}
	if rows[0].String("owner_epoch") != "7" || rows[0].String("relocation_token") == "" {
		t.Fatalf("proof owner/token=%q/%q; want 7/non-empty",
			rows[0].String("owner_epoch"), rows[0].String("relocation_token"))
	}
}

// VM reschedule uses a different mint path (proof + pending pointer in one
// transaction), so pin the same ownership-generation binding there too.
func TestVMRescheduleProofCarriesOwnerEpoch(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []string{"dead", "live"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'vm1'`); err != nil {
		t.Fatalf("seed owner epoch: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"coord", "live"}, "dead")

	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	c.run(ctx)

	rows, err := db.Query(ctx, `SELECT owner_epoch, dest_host FROM runtime_action_proofs WHERE target_name = 'vm1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("proof rows=%d err=%v; want one", len(rows), err)
	}
	if rows[0].String("owner_epoch") != "7" || rows[0].String("dest_host") != "live" {
		t.Fatalf("proof owner/dest=%q/%q; want 7/live",
			rows[0].String("owner_epoch"), rows[0].String("dest_host"))
	}
}

// TestVMRescheduleProofCarriesLeaseTerm: the reschedule proof must carry the
// fencing term of the tenure that minted it.
//
// reschedule is the ONE action in leaseTermRequiredActions, and this is its only
// mint site. Unstamped, judgeProofLeaseTerm sees term 0 with an empty key and
// returns ReasonStaleLeaseTerm the moment lease_term_v1 latches — so every VM
// failover in the cluster is refused and each VM sits state=pending forever.
// Enabling the feature meant to protect failover would have disabled it.
//
// Nothing detected this. LeaseTermReadiness withholds the token until this node
// can MINT a term, which says nothing about whether its producers STAMP one, and
// the two are independent: the mint gate was wired and working while every proof
// went out with a zero term. What makes stamping safe to rely on cluster-wide is
// that a build which does not stamp does not advertise lease_term_v1, so the
// latch cannot form across one.
//
// The term is read from what the coordinator recorded at acquisition, never from
// a fresh MAX(term) read — that would let a displaced holder adopt the winner's
// term, which is the hole the ledger exists to close.
func TestVMRescheduleProofCarriesLeaseTerm(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []string{"dead", "live"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"coord", "live"}, "dead")

	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	c.run(ctx)

	if c.LeaseTerm() <= 0 {
		t.Fatalf("coordinator holds term %d after a tick that took the lease; the rest of "+
			"this test is vacuous", c.LeaseTerm())
	}

	rows, err := db.Query(ctx,
		`SELECT lease_term, lease_key FROM runtime_action_proofs WHERE target_name = 'vm1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("proof rows=%d err=%v; want one", len(rows), err)
	}
	if got := rows[0].Int64("lease_term"); got != c.LeaseTerm() {
		t.Errorf("proof lease_term = %d, want %d (the coordinator's own recorded term). "+
			"An unstamped reschedule proof is refused as stale_lease_term once "+
			"lease_term_v1 latches, so every VM failover in the cluster stops and the "+
			"VMs sit pending forever", got, c.LeaseTerm())
	}
	if got := rows[0].String("lease_key"); got != corrosion.LeaseKeyFailover {
		t.Errorf("proof lease_key = %q, want %q. The three leases allocate terms "+
			"independently and their numbers collide by design, so a term without its "+
			"key cannot be judged against anything", got, corrosion.LeaseKeyFailover)
	}
}

// TestAutoPromoteAbandonsOnAStaleTenure is promote's half of the same rule.
//
// Promote is as destructive as reschedule -- it defines and starts a VM on a
// new host -- but coordinator.go called it with no leaseStamp guard, so a
// coordinator whose lease had lapsed mid-loop had its reschedule and relocate
// refused while its promote went through. gateEnforced/DecisionGate does not
// catch it, because a lapse is not quorum loss; and for a local-disk DR VM
// requireProofGradeFence does not fire either.
func TestAutoPromoteAbandonsOnAStaleTenure(t *testing.T) {
	seed := func(t *testing.T, db *corrosion.Client) *dbPromoter {
		t.Helper()
		ctx := context.Background()
		for _, h := range []string{"bad", "good"} {
			if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
				Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
				GRPCPort: 7443, State: "active", FenceStrategy: "manual",
			}); err != nil {
				t.Fatalf("InsertHost %s: %v", h, err)
			}
		}
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
			VMName: "vm1", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
			Type: "replication", TargetPool: "dr", TargetHost: "good", KeepReplicas: 3,
			Incremental: true, AutoPromote: true,
		}); err != nil {
			t.Fatalf("UpsertBackupSchedule: %v", err)
		}
		fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")
		return &dbPromoter{db: db, target: "promoted-host"}
	}

	// Positive control FIRST: without it, a fixture that never reaches the
	// promote branch would pass the real assertion for the wrong reason.
	t.Run("a held lease still promotes", func(t *testing.T) {
		db := newTestDB(t)
		prom := seed(t, db)
		c := newTestCoordinator("coordinator", db)
		c.Promoter = prom
		c.run(context.Background())
		if len(prom.promoted) != 1 {
			t.Fatalf("fixture inert: a coordinator holding the lease promoted %v, want [vm1]", prom.promoted)
		}
	})

	t.Run("a tenure that ends mid-loop does not", func(t *testing.T) {
		db := newTestDB(t)
		ctx := context.Background()
		prom := seed(t, db)
		c := newTestCoordinator("coordinator", db)
		c.Promoter = prom
		// The successor takes the lease DURING the tick, right before the
		// promote decision -- the coordinator passed its own lease gate at the
		// top of the tick and is now acting on a tenure it no longer holds.
		c.Gate = fakeFailoverGate{
			supports: map[string]bool{"good": true},
			enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
			onDecision: func() {
				if _, _, err := corrosion.AcquireLeaseWithTerm(ctx, db, corrosion.LeaseKeyFailover,
					"successor", 10*time.Minute, time.Now().Add(10*time.Minute)); err != nil {
					t.Errorf("successor could not take the failover lease: %v", err)
				}
			},
		}

		c.run(ctx)

		if len(prom.promoted) != 0 {
			t.Fatalf("a coordinator whose tenure ended mid-loop promoted %v; promote "+
				"defines and starts a VM on a new host and must take the same "+
				"stale-tenure abandon reschedule and relocate take", prom.promoted)
		}
	})
}

// TestStillOurTenureFailsClosedOnAnUnknownHolder pins the direction of the
// re-check's failure mode.
//
// leaseSnapshot returns an empty holder on a read error rather than
// fabricating one — reporting self would falsely assert this node held the
// lease. An unknown holder is therefore NOT a held lease: abandoning one VM's
// recovery costs a cycle, while promoting on a tenure that may already belong
// to a successor defines and starts a VM on a new host while that successor
// may be doing the same.
func TestStillOurTenureFailsClosedOnAnUnknownHolder(t *testing.T) {
	db := newTestDB(t)
	c := newTestCoordinator("coordinator", db)

	// No leader_election row at all: leaseSnapshot reports "" (unknown).
	if c.stillOurTenure(context.Background()) {
		t.Fatal("an unknown lease holder was read as 'still ours'; the re-check must fail closed")
	}
}
