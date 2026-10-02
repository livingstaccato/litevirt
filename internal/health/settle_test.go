package health

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// settleFixture: node-a holds a RUNNING copy of vm-a whose row has moved to
// node-b, and a proof for node-b whose certificate the injected verifier
// judges. Each case edits one clause.
type settleFixture struct {
	t       *testing.T
	db      *corrosion.Client
	virt    *libvirtfake.Fake
	r       *Reconciler
	dataDir string
	row     *corrosion.VMRecord
	proof   corrosion.ProofRecord
	cert    corrosion.ClaimCertificate
	certErr error
	// destState is what the destination reports for vm-a in its own libvirt.
	destState string
}

func newSettleFixture(t *testing.T) *settleFixture {
	t.Helper()
	ctx := context.Background()
	f := &settleFixture{t: t, db: corrosion.NewTestClientT(t), virt: libvirtfake.New(), dataDir: t.TempDir()}
	if err := corrosion.InitSchema(ctx, f.db); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"node-a", "node-b", "node-c"} {
		if err := corrosion.InsertHost(ctx, f.db, corrosion.HostRecord{Name: h, Address: "127.0.0.1", GRPCPort: 7443, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: "vm-a", HostName: "node-b",
		Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	row, err := corrosion.GetVM(ctx, f.db, "vm-a")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v", err)
	}
	f.row = row
	inc := corrosion.IncarnationOf(row.CreatedAt)
	f.virt.SetState("vm-a", libvirtfake.StateRunning)
	f.proof = corrosion.ProofRecord{ActionProof: corrosion.ActionProof{ID: "proof-1", Action: corrosion.ActionReschedule,
		TargetKind: corrosion.ClaimKindVM, TargetName: "vm-a", DestHost: "node-b", OwnerEpoch: "3",
		ClaimCertificate: "{}"}, Status: corrosion.ProofCompleted, ExecutorHost: "node-b"}
	f.cert = corrosion.ClaimCertificate{Key: corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-a",
		OwnerEpoch: 3, Incarnation: inc}, ConfigGeneration: 1}
	// The local copy, as this host's pause recorded it.
	if err := newPauseStore(f.dataDir).put(PauseRecord{Kind: PauseKindVM, Name: "vm-a", Host: "node-a",
		OwnerEpoch: 3, Incarnation: inc}); err != nil {
		t.Fatal(err)
	}
	f.r = NewReconciler("node-a", f.dataDir, f.db, f.virt)
	f.r.settleProofs = func(context.Context, *corrosion.Client, string, string) ([]corrosion.ProofRecord, error) {
		return []corrosion.ProofRecord{f.proof}, nil
	}
	f.destState = RuntimeRunning
	f.r.SetPeerRuntimeChecker(func(_ context.Context, host, name string) (string, error) {
		if host != "node-b" || name != "vm-a" {
			return RuntimeAbsent, nil
		}
		return f.destState, nil
	})
	f.r.SetSettleVerifier(func(_ context.Context, p corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
		// A real verifier returns the decoded certificate with its error.
		return f.cert, f.certErr
	})
	return f
}

func (f *settleFixture) run() libvirtfake.State {
	f.t.Helper()
	f.r.selfFence(context.Background())
	st, ok := f.virt.RawState("vm-a")
	if !ok {
		f.t.Fatal("the domain was UNDEFINED by settle; it must only be stopped")
	}
	return st
}

// With a verified certificate for this incarnation at the local copy's epoch,
// the running copy is stopped (destroyed: definition kept), an audit row and
// vm_settled are written, and the pause record is dropped.
//
// Mutations: skip the destroy — this goes red; skip the audit row / the
// condition / the record removal — the matching check goes red.
func TestSettle_StopsACopyACertifiedClaimGaveAway(t *testing.T) {
	f := newSettleFixture(t)
	if st := f.run(); st != libvirtfake.StateShutdown {
		t.Fatalf("vm-a is %s; a verified claim gave it to node-b, so the local copy must stop", st)
	}
	ctx := context.Background()
	rows, err := f.db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'partition.settle' AND target = 'vm-a'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("partition.settle audit rows = %d (%v), want 1", len(rows), err)
	}
	c, ok, err := corrosion.GetHealthCondition(ctx, f.db, corrosion.PartitionPauseEvaluator, corrosion.CondVMSettled, "vm", "vm-a@node-a")
	if err != nil || !ok || c.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("vm_settled = (%+v, %v, %v), want confirmed", c, ok, err)
	}
	if _, ok, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-a"); ok {
		t.Fatal("the pause record outlived the settled copy")
	}
}

// A paused copy (this host's partition pause) settles the same way.
func TestSettle_StopsAPausedCopy(t *testing.T) {
	f := newSettleFixture(t)
	f.virt.SetPaused("vm-a")
	if st := f.run(); st != libvirtfake.StateShutdown {
		t.Fatalf("paused vm-a is %s after a verified claim gave it away", st)
	}
}

// Every clause of the proof is load-bearing; each case removes one and the
// copy must keep running.
//
// Mutations (one per case): skip the proof requirement (settle on host_name
// alone) — "no proof"; ignore the verifier's error — "certificate does not
// verify"; skip the key-incarnation check — "certificate for another
// incarnation"; skip the epoch check — "older epoch"; skip the row-incarnation
// check — "row is another incarnation"; accept an unknown identity — the two
// "unknown" cases; skip the destination check — "proof for a third host".
func TestSettle_NeverWithoutPositiveProof(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(f *settleFixture)
	}{
		{"no proof (host_name alone)", func(f *settleFixture) {
			f.r.settleProofs = func(context.Context, *corrosion.Client, string, string) ([]corrosion.ProofRecord, error) {
				return nil, nil
			}
		}},
		{"certificate does not verify", func(f *settleFixture) { f.certErr = errors.New("too few valid accepts") }},
		{"certificate for another incarnation", func(f *settleFixture) { f.cert.Key.Incarnation = "2001-01-01T00:00:00Z" }},
		{"older epoch than the local copy", func(f *settleFixture) { f.cert.Key.OwnerEpoch = 2 }},
		{"row is another incarnation", func(f *settleFixture) {
			if err := RemovePauseRecord(f.dataDir, PauseKindVM, "vm-a"); err != nil {
				f.t.Fatal(err)
			}
			if err := newPauseStore(f.dataDir).put(PauseRecord{Kind: PauseKindVM, Name: "vm-a", Host: "node-a",
				OwnerEpoch: 3, Incarnation: "1999-01-01T00:00:00Z"}); err != nil {
				f.t.Fatal(err)
			}
			f.cert.Key.Incarnation = "" // a legacy key: only the row binds the incarnation
		}},
		{"unknown incarnation", func(f *settleFixture) {
			if err := RemovePauseRecord(f.dataDir, PauseKindVM, "vm-a"); err != nil {
				f.t.Fatal(err)
			}
			// The epoch is known; only the incarnation is missing.
			if err := f.virt.SetDomainOwnerEpoch("vm-a", 3, true); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"unknown epoch", func(f *settleFixture) {
			if err := RemovePauseRecord(f.dataDir, PauseKindVM, "vm-a"); err != nil {
				f.t.Fatal(err)
			}
			if err := f.virt.SetDomainManagedIncarnation("vm-a", corrosion.IncarnationOf(f.row.CreatedAt), true); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"proof for a third host", func(f *settleFixture) { f.proof.DestHost = "node-c" }},
		// A decided claim is not a running replacement: the proof may still be
		// prepared (the destination has not started it), have failed, or have
		// been executed by someone other than its destination. Settling then
		// would stop the ONLY running copy.
		{"proof prepared, not executed", func(f *settleFixture) { f.proof.Status = corrosion.ProofPrepared; f.proof.ExecutorHost = "" }},
		{"proof failed", func(f *settleFixture) { f.proof.Status = corrosion.ProofFailed }},
		{"proof executed by another host", func(f *settleFixture) { f.proof.ExecutorHost = "node-c" }},
		{"destination does not run it", func(f *settleFixture) { f.destState = RuntimeDefinedStopped }},
		{"destination unreachable", func(f *settleFixture) {
			f.r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) {
				return "", errors.New("unreachable")
			})
		}},
		{"no destination runtime check wired", func(f *settleFixture) { f.r.SetPeerRuntimeChecker(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			tc.edit(f)
			if st := f.run(); st != libvirtfake.StateRunning {
				t.Fatalf("vm-a is %s; without positive proof the non-destruction guard must stand", st)
			}
		})
	}
}

// A host WITHOUT the token never paused, so it has no record: the managed
// stamp's incarnation and the owner-epoch marker are its evidence, and they
// settle the copy exactly as a record would.
//
// Mutation: read the identity from the pause record only — this goes red.
func TestSettle_DomainMetadataIsEvidenceToo(t *testing.T) {
	f := newSettleFixture(t)
	if err := RemovePauseRecord(f.dataDir, PauseKindVM, "vm-a"); err != nil {
		t.Fatal(err)
	}
	if err := f.virt.SetDomainManagedIncarnation("vm-a", corrosion.IncarnationOf(f.row.CreatedAt), true); err != nil {
		t.Fatal(err)
	}
	if err := f.virt.SetDomainOwnerEpoch("vm-a", 3, true); err != nil {
		t.Fatal(err)
	}
	if st := f.run(); st != libvirtfake.StateShutdown {
		t.Fatalf("vm-a is %s; its domain metadata identifies the copy the certificate superseded", st)
	}
}
