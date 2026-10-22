package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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
	// The local copy is one this host's partition pause suspended.
	f.virt.SetState("vm-a", libvirtfake.StateRunning)
	f.virt.SetPaused("vm-a")
	f.virt.SetInactiveXML("vm-a", settleDomainXML)
	f.proof = corrosion.ProofRecord{ActionProof: corrosion.ActionProof{ID: "proof-1", Action: corrosion.ActionReschedule,
		TargetKind: corrosion.ClaimKindVM, TargetName: "vm-a", DestHost: "node-b", OwnerEpoch: "3",
		ClaimCertificate: "{}"}, Status: corrosion.ProofCompleted, ExecutorHost: "node-b"}
	f.cert = corrosion.ClaimCertificate{Key: corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-a",
		OwnerEpoch: 3, Incarnation: inc}, ConfigGeneration: 1}
	// The local copy, as this host's pause recorded it.
	if err := newPauseStore(f.dataDir).put(PauseRecord{Kind: PauseKindVM, Name: "vm-a", Host: "node-a",
		OwnerEpoch: 3, Incarnation: inc, DomainUUID: settleDomainUUID}); err != nil {
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

// runningCopy turns the local copy into a RUNNING one on a host that never
// paused: no pause record, identified by its managed stamp and owner-epoch
// metadata (TestSettle_DomainMetadataIsEvidenceToo).
func (f *settleFixture) runningCopy() {
	f.t.Helper()
	if err := RemovePauseRecord(f.dataDir, PauseKindVM, "vm-a"); err != nil {
		f.t.Fatal(err)
	}
	f.virt.SetState("vm-a", libvirtfake.StateRunning)
	if err := f.virt.SetDomainManagedIncarnation("vm-a", corrosion.IncarnationOf(f.row.CreatedAt), true); err != nil {
		f.t.Fatal(err)
	}
	if err := f.virt.SetDomainOwnerEpoch("vm-a", 3, true); err != nil {
		f.t.Fatal(err)
	}
}

// onRunning is edit applied to a RUNNING local copy (runningCopy).
func onRunning(edit func(f *settleFixture)) func(f *settleFixture) {
	return func(f *settleFixture) {
		f.runningCopy()
		edit(f)
	}
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

// A pause record is evidence only while it still describes the domain: one
// left behind after the domain was resumed by hand says nothing about what
// runs now (and would offer a stale epoch), so without other evidence there is
// no proof.
//
// Mutation: trust the record whatever the domain's state — the copy stops and
// this goes red.
func TestSettle_AStaleRecordIsNotEvidence(t *testing.T) {
	f := newSettleFixture(t)
	f.virt.SetState("vm-a", libvirtfake.StateRunning) // resumed by someone else
	if st := f.run(); st != libvirtfake.StateRunning {
		t.Fatalf("vm-a is %s; a record of a pause that no longer holds was taken as proof", st)
	}
}

// The local copy's domain, by UUID: the pause record names it.
const (
	settleDomainUUID = "6f1c2a3e-0000-4000-8000-00000000000a"
	settleDomainXML  = `<domain type='kvm'><name>vm-a</name><uuid>` + settleDomainUUID +
		`</uuid><memory unit='MiB'>1024</memory><vcpu>1</vcpu><devices></devices></domain>`
)

// A record without a domain UUID — its DumpXML read failed at pause time —
// cannot show it is about THIS domain rather than one defined under the same
// name since, so it is not evidence; nor is one naming another domain.
//
// Mutations: accept a record without a UUID — the first case stops the copy
// and this goes red; skip the UUID comparison — the second does.
func TestSettle_ARecordMustNameTheDomainByUUID(t *testing.T) {
	for _, tc := range []struct{ name, uuid string }{
		{"no uuid", ""},
		{"another domain's uuid", "6f1c2a3e-0000-4000-8000-0000000000ff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			rec, ok, err := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-a")
			if err != nil || !ok {
				t.Fatalf("setup: record %v %v", ok, err)
			}
			rec.DomainUUID = tc.uuid
			if err := newPauseStore(f.dataDir).put(rec); err != nil {
				t.Fatal(err)
			}
			if st := f.run(); st == libvirtfake.StateShutdown {
				t.Fatalf("vm-a is %s; a record that does not name this domain was taken as proof", st)
			}
		})
	}
}

// The local copy's epoch is the HIGHEST any host-local source reports: a pause
// record at 3 beside owner-epoch metadata at 5 is a copy at 5, which a
// certificate for epoch 3 does not supersede.
//
// Mutation: prefer the record's epoch over the others — the copy stops and
// this goes red.
func TestSettle_TheLocalEpochIsTheHighestEvidence(t *testing.T) {
	f := newSettleFixture(t)
	if err := f.virt.SetDomainOwnerEpoch("vm-a", 5, true); err != nil {
		t.Fatal(err)
	}
	if st := f.run(); st != libvirtfake.StatePaused {
		t.Fatalf("vm-a is %s; a certificate for epoch 3 stopped a copy whose metadata says 5", st)
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
//
// The cases wrapped in onRunning hold a RUNNING local copy (a host that never
// paused, identified by its domain metadata): the replacement-runs clauses
// (H2) protect a copy that runs, and a copy this host holds paused yields to
// a live decided claim without them (TestSettle_APausedCopyYieldsToALiveDecidedClaim).
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
				OwnerEpoch: 3, Incarnation: "1999-01-01T00:00:00Z", DomainUUID: settleDomainUUID}); err != nil {
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
		{"proof prepared, not executed", onRunning(func(f *settleFixture) { f.proof.Status = corrosion.ProofPrepared; f.proof.ExecutorHost = "" })},
		{"proof in progress, not executed", onRunning(func(f *settleFixture) { f.proof.Status = corrosion.ProofInProgress })},
		{"proof failed", onRunning(func(f *settleFixture) { f.proof.Status = corrosion.ProofFailed })},
		{"proof executed by another host", onRunning(func(f *settleFixture) { f.proof.ExecutorHost = "node-c" })},
		{"destination does not run it", onRunning(func(f *settleFixture) { f.destState = RuntimeDefinedStopped })},
		{"destination unreachable", onRunning(func(f *settleFixture) {
			f.r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) {
				return "", errors.New("unreachable")
			})
		})},
		{"no destination runtime check wired", onRunning(func(f *settleFixture) { f.r.SetPeerRuntimeChecker(nil) })},
		// A copy this host holds paused does not wait for the replacement to
		// run, but it still yields only to a proof its destination may
		// execute: never to a failed one, nor to one another host took.
		{"paused: proof failed", func(f *settleFixture) {
			f.proof.Status = corrosion.ProofFailed
			f.destState = RuntimeDefinedStopped
		}},
		{"paused: proof completed by another host", func(f *settleFixture) { f.proof.ExecutorHost = "node-c" }},
		{"paused: proof in progress on another host", func(f *settleFixture) {
			f.proof.Status, f.proof.ExecutorHost = corrosion.ProofInProgress, "node-c"
			f.destState = RuntimeDefinedStopped
		}},
		{"paused: proof prepared, claimed by another host", func(f *settleFixture) {
			f.proof.Status, f.proof.ExecutorHost = corrosion.ProofPrepared, "node-c"
			f.destState = RuntimeDefinedStopped
		}},
		// The paused path is taken on the domain being paused NOW, never on a
		// pause record alone: a record left beside a copy that runs again (a
		// resume that landed before the record was dropped, an operator's
		// resume) says nothing about what runs.
		{"running beside a stale pause record: proof prepared", func(f *settleFixture) {
			rec, ok, err := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-a")
			if err != nil || !ok {
				f.t.Fatalf("setup: record %v %v", ok, err)
			}
			f.runningCopy()
			if err := newPauseStore(f.dataDir).put(rec); err != nil {
				f.t.Fatal(err)
			}
			f.proof.Status, f.proof.ExecutorHost = corrosion.ProofPrepared, ""
			f.destState = RuntimeAbsent
		}},
		// On a proof not yet executed the certificate's epoch and incarnation
		// are the last line before the destroy of a paused copy: no
		// destination check follows them.
		{"paused: in progress, certificate at an older epoch", func(f *settleFixture) {
			f.proof.Status = corrosion.ProofInProgress
			f.cert.Key.OwnerEpoch = 2
			f.destState = RuntimeAbsent
		}},
		{"paused: prepared, certificate for another incarnation", func(f *settleFixture) {
			f.proof.Status, f.proof.ExecutorHost = corrosion.ProofPrepared, ""
			f.cert.Key.Incarnation = "2001-01-01T00:00:00Z"
			f.destState = RuntimeAbsent
		}},
		{"paused: in progress, certificate for another incarnation", func(f *settleFixture) {
			f.proof.Status = corrosion.ProofInProgress
			f.cert.Key.Incarnation = "2001-01-01T00:00:00Z"
			f.destState = RuntimeAbsent
		}},
		{"paused: prepared, certificate at an older epoch", func(f *settleFixture) {
			f.proof.Status, f.proof.ExecutorHost = corrosion.ProofPrepared, ""
			f.cert.Key.OwnerEpoch = 2
			f.destState = RuntimeAbsent
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			tc.edit(f)
			if st := f.run(); st == libvirtfake.StateShutdown {
				t.Fatalf("vm-a is %s; without positive proof the non-destruction guard must stand", st)
			}
		})
	}
}

// Lab 2, B4: a copy this host's partition pause holds paused still holds its
// image locks on shared storage, so the replacement the decided claim sent to
// node-b cannot start until it is gone, and waiting for the replacement to run
// first left zero copies running until an operator destroyed it. A paused
// copy runs nothing, and a decided claim moved it, so it yields to the live
// proof: prepared, or in progress on its destination, before the destination
// runs it, and even with the destination unreachable.
//
// Mutations: require an executed proof for a paused copy too — the first
// three cases go red; require the destination to run it — every case goes
// red; take a running copy for a paused one (SelfPaused without the record) —
// TestSettle_NeverWithoutPositiveProof's running cases go red.
func TestSettle_APausedCopyYieldsToALiveDecidedClaim(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(f *settleFixture)
	}{
		{"in progress on the destination, which cannot start it", func(f *settleFixture) {
			f.proof.Status = corrosion.ProofInProgress
			f.destState = RuntimeDefinedStopped
		}},
		{"prepared, not yet claimed", func(f *settleFixture) {
			f.proof.Status, f.proof.ExecutorHost = corrosion.ProofPrepared, ""
			f.destState = RuntimeAbsent
		}},
		{"in progress, destination unreachable", func(f *settleFixture) {
			f.proof.Status = corrosion.ProofInProgress
			f.r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) {
				return "", errors.New("unreachable")
			})
		}},
		{"completed, destination not running it", func(f *settleFixture) { f.destState = RuntimeDefinedStopped }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			tc.edit(f)
			if st := f.run(); st != libvirtfake.StateShutdown {
				t.Fatalf("vm-a is %s; a copy this host holds paused must yield to the decided claim, "+
					"or the replacement waits forever on its image lock", st)
			}
			rows, err := f.db.Query(context.Background(), `SELECT detail FROM audit_log WHERE action = 'partition.settle' AND target = 'vm-a'`)
			if err != nil || len(rows) != 1 {
				t.Fatalf("partition.settle audit rows = %d (%v), want 1", len(rows), err)
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
	f.virt.SetState("vm-a", libvirtfake.StateRunning) // a running copy: the host never paused
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

// A domain an older build defined carries no incarnation stamp. Its UUID
// equalling the row's spec uuid is NOT evidence of the incarnation, so settle
// must still decline: a non-firmware live restore (resolveRestoreSpec in
// restore_live_autostart.go) and a renamed promote (promote.go) both write a
// NEW row — a new created_at, so a new incarnation — carrying the source VM's
// spec uuid, and any later spec-driven define gives the new domain that uuid.
// A stale copy of the old incarnation then matches the new row by UUID, and a
// UUID rule would stop it on a certificate that decided the other one.
//
// The control is the same domain WITH its stamp, which settles (above).
//
// Mutation: accept a domain UUID equal to the row's spec uuid as the row's
// incarnation in settleCertifiedMove — this goes red.
func TestSettle_AMatchingUUIDIsNotIncarnationEvidence(t *testing.T) {
	f := newSettleFixture(t)
	if err := RemovePauseRecord(f.dataDir, PauseKindVM, "vm-a"); err != nil {
		t.Fatal(err)
	}
	f.virt.SetState("vm-a", libvirtfake.StateRunning)
	if err := f.virt.SetDomainOwnerEpoch("vm-a", 3, true); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = ?`,
		`{"on_host_failure":"restart-any","uuid":"`+settleDomainUUID+`"}`, "vm-a"); err != nil {
		t.Fatal(err)
	}
	if st := f.run(); st == libvirtfake.StateShutdown {
		t.Fatalf("vm-a is %s: a matching UUID settled a copy whose incarnation is unknown", st)
	}
	// And it declines for the RIGHT reason: the incarnation is unknown, not some
	// later clause that happened to fail.
	vm, err := corrosion.GetVM(context.Background(), f.db, "vm-a")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	settled, why, local := f.r.settleCertifiedMove(context.Background(), "vm-a", vm)
	if settled || settleReasonClass(why) != "incarnation_unknown" || local.Incarnation != "" {
		t.Fatalf("settle = (%v, %q, incarnation %q), want a decline because the incarnation is unknown",
			settled, why, local.Incarnation)
	}
}

// settledRow reads node-a's vm_settled for vm-a with its raw updated_at.
func settledRow(t *testing.T, f *settleFixture) (corrosion.HealthCondition, string) {
	t.Helper()
	ctx := context.Background()
	c, ok, err := corrosion.GetHealthCondition(ctx, f.db, corrosion.PartitionPauseEvaluator, corrosion.CondVMSettled, "vm", "vm-a@node-a")
	if err != nil || !ok {
		t.Fatalf("vm_settled = (%+v, %v, %v), want a row", c, ok, err)
	}
	rows, err := f.db.Query(ctx, `SELECT updated_at FROM health_conditions WHERE code = ? AND subject_id = ?`,
		corrosion.CondVMSettled, "vm-a@node-a")
	if err != nil || len(rows) != 1 {
		t.Fatalf("vm_settled updated_at: %d rows, %v", len(rows), err)
	}
	return c, rows[0].String("updated_at")
}

// vm_settled says this host holds a stopped copy of a VM a certified claim
// gave to another host. It stays open while that copy is defined here, and
// resolves on the pass that finds it gone (the leftover cleanup, or an
// operator, undefined it). On lab 3 it never resolved: nothing resolved the
// code at all, and `lv health resolve` refuses it.
//
// A host resolves only its own: another host's copy is not in its domain
// list, and that says nothing about whether it is still there.
//
// Mutations: drop the resolution — red at "resolved"; resolve without the
// domain check — red at "still defined"; rewrite a resolved row each pass —
// red at the idempotence check; drop the subject's host check — red at
// node-c's row.
func TestSettle_VMSettledResolvesOnceTheStoppedCopyIsGone(t *testing.T) {
	f := newSettleFixture(t)
	f.run()
	// Another host's vm_settled: node-a's domain list says nothing about a
	// copy on node-c, so a node-a pass leaves it open.
	ctx := context.Background()
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, f.db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondVMSettled,
		SubjectKind: "vm", SubjectID: "vm-z@node-c", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityWarning, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: "node-c",
	}); err != nil {
		t.Fatal(err)
	}
	// The stopped copy stays defined: a reason the leftover cleanup does
	// not take, and not a live state settle would act on again.
	f.virt.SetStateReason("vm-a", "crashed")
	f.r.selfFence(ctx)
	f.r.selfFence(ctx)
	if c, _ := settledRow(t, f); c.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("vm_settled is %s while the stopped copy is still defined here; it still holds", c.Lifecycle)
	}

	if err := f.virt.UndefineDomain("vm-a", false); err != nil {
		t.Fatal(err)
	}
	f.r.selfFence(ctx)
	c, at := settledRow(t, f)
	if c.Lifecycle != corrosion.ConditionResolved || c.ResolvedAt == "" || c.Reporter != "node-a" {
		t.Fatalf("vm_settled = %+v once the stopped copy is gone, want resolved by node-a", c)
	}
	f.r.selfFence(ctx)
	if _, again := settledRow(t, f); again != at {
		t.Fatalf("a pass over a resolved vm_settled rewrote it (updated_at %s → %s)", at, again)
	}
	other, ok, err := corrosion.GetHealthCondition(ctx, f.db, corrosion.PartitionPauseEvaluator, corrosion.CondVMSettled, "vm", "vm-z@node-c")
	if err != nil || !ok || other.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("node-c's vm_settled = (%+v, %v, %v) after node-a's passes, want it left open", other, ok, err)
	}
}

// A copy is superseded only while the VM's row names another host. Once the
// row names this host again (the VM came back), the domain here is the VM's
// own, and vm_settled no longer holds.
//
// Mutation: drop the row clause — red.
func TestSettle_VMSettledResolvesWhenTheRowNamesThisHostAgain(t *testing.T) {
	f := newSettleFixture(t)
	f.run()
	f.virt.SetStateReason("vm-a", "crashed")
	ctx := context.Background()
	if err := corrosion.UpdateVMHost(ctx, f.db, "vm-a", "node-a", "stopped"); err != nil {
		t.Fatal(err)
	}
	f.r.selfFence(ctx)
	if c, _ := settledRow(t, f); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("vm_settled is %s while vm-a's row names node-a again, want resolved", c.Lifecycle)
	}
}

// A settle that drops a VM's pause record drops the pauser's capture
// registry hold with it: a kept hold would refuse every later memory
// snapshot of the name on this host.
//
// Mutation: drop the Release in dropMatchingPause — red.
func TestSettle_DroppingThePauseRecordReleasesTheCaptureHold(t *testing.T) {
	f := newSettleFixture(t)
	reg := lv.NewCaptureRegistry()
	f.r.SetCaptureRegistry(reg)
	reg.Hold("vm-a", time.Second) // the pauser's, taken when it paused vm-a
	if st := f.run(); st != libvirtfake.StateShutdown {
		t.Fatalf("vm-a is %s, want the settled copy stopped", st)
	}
	if _, ok, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-a"); ok {
		t.Fatal("the pause record outlived the settled copy")
	}
	if reg.Holding("vm-a") {
		t.Fatal("the capture hold outlived the pause record")
	}
}
