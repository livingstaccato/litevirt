package grpcapi

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Fix round 5 of fix/iscsi-one-disk-per-lun: re-review 4's I-1, I-2,
// concern 3 and m-1..m-4.

// barVM sets (op != "") or clears vm's mutation barrier, as a journaled
// operation in progress holds it: DeleteVM refuses while it is set.
func barVM(t *testing.T, s *Server, vm, op string) {
	t.Helper()
	if err := s.db.Execute(context.Background(), `UPDATE vms SET active_operation_id = ? WHERE name = ?`, op, vm); err != nil {
		t.Fatal(err)
	}
}

// failResolveOnce makes the first resolution of pool's storage fail, as a
// transient read error would.
func failResolveOnce(t *testing.T, pool string) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	resolveVolumeFault = func(_, vol string) error {
		if vol == pool && n.Add(1) == 1 {
			return errors.New("database is locked")
		}
		return nil
	}
	t.Cleanup(func() { resolveVolumeFault = nil })
	return &n
}

// I-1: a recreate whose delete is refused — the VM intact, no create
// attempted — leaves no hold behind, and does not move the LUN's checkpoint
// to the allocation it decided: once the refusal's cause is gone, the next
// recreate of the VM goes through. The checkpoint moves to the re-created
// VM's allocation only once its create has committed.
//
// Mutation: keep the hold (finish, not abandon) when no create was attempted
// — the second recreate is refused Aborted by the first one's hold, and this
// goes red.
func TestRecreate_ISCSI_ARecreateRefusedAtItsDeleteAbandonsItsHold(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	key := mustLUNKey(t, "10.0.0.1", "0")
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	barVM(t, s, "a", "op-backup")
	err := (&serverOps{s: s}).RecreateVM(ctx, "a", lunVM("a", "lun0").Spec)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "operation is in progress") {
		t.Fatalf("a recreate while an operation holds the VM: got %v, want the delete's FailedPrecondition", err)
	}
	vmExists(t, s, "a", "after the refused recreate")
	if toks, err := s.lunHoldTokens(); err != nil || len(toks) != 0 {
		t.Fatalf("the recreate refused at its delete left holds %v (%v)", toks, err)
	}
	if c, err := corrosion.GetLUNResolved(ctx, s.db, key); err != nil || c != 0 {
		t.Fatalf("checkpoint after a recreate whose create never ran = %d (%v), want 0", c, err)
	}

	barVM(t, s, "a", "")
	if err := (&serverOps{s: s}).RecreateVM(ctx, "a", lunVM("a", "lun0").Spec); err != nil {
		t.Fatalf("the recreate once the operation finished: %v", err)
	}
	vmExists(t, s, "a", "after the second recreate")
	// Allocation 0 is a's create, 1 the refused recreate's, 2 this one's.
	if c, err := corrosion.GetLUNResolved(ctx, s.db, key); err != nil || c != 2 {
		t.Fatalf("checkpoint after the committed recreate = %d (%v), want 2 (its own allocation)", c, err)
	}
}

// I-2 (a): a create whose storage fails to resolve once — a read error, or a
// pool row that arrives between two resolutions — is refused. It never
// attaches a LUN it did not claim.
//
// Mutation: skip a disk whose storage does not resolve (round 4) — b is
// created on a's LUN and this goes red.
func TestCreateVM_ISCSI_AStorageThatFailsToResolveOnceIsRefused(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create a: %v", err)
	}
	failResolveOnce(t, "lun0")
	if _, err := s.CreateVM(ctx, lunVM("b", "lun0")); err == nil {
		t.Fatal("a create whose storage failed to resolve once took a's LUN: two guests on one LUN")
	}
	requireNoVM(t, s, "b")
}

// I-2 (a): the disk a create makes is on the storage its claim resolved —
// one resolution, so the claim and the disk cannot disagree.
//
// Mutation: resolve the storage again in the create's disk loop — this goes
// red.
func TestCreateVM_ISCSI_TheDiskIsTheStorageItsClaimResolved(t *testing.T) {
	s := lunTestServer(t)
	var n atomic.Int32
	resolveVolumeFault = func(_, vol string) error {
		if vol == "lun0" {
			n.Add(1)
		}
		return nil
	}
	t.Cleanup(func() { resolveVolumeFault = nil })
	if _, err := s.CreateVM(adminCtx(), lunVM("a", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("the create resolved its storage %d times, want once", got)
	}
}

// I-2 (b): a recreate whose storage fails to resolve before the teardown is
// refused with the VM intact — never re-created somewhere its moved claim
// does not name, nor torn down to meet the error after.
//
// Mutation: count an unresolvable storage as no LUN in the recreate
// (round 4) — "throughout" tears the VM down and this goes red; "once" is
// then caught by the run host rule (TestPreflightLUNs_NeverDefaultsTheRunHost).
func TestRecreate_ISCSI_AStorageThatFailsToResolveRefusesBeforeTheTeardown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		always bool
	}{{"once", false}, {"throughout", true}} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			ctx := adminCtx()
			if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
				t.Fatalf("create: %v", err)
			}
			before := vmRecord(t, s, "a").CreatedAt
			if tc.always {
				resolveVolumeFault = func(_, vol string) error {
					if vol == "lun0" {
						return errors.New("database is locked")
					}
					return nil
				}
				t.Cleanup(func() { resolveVolumeFault = nil })
			} else {
				failResolveOnce(t, "lun0")
			}
			err := (&serverOps{s: s}).RecreateVM(ctx, "a", lunVM("a", "lun0").Spec)
			if err == nil || !strings.Contains(err.Error(), "nothing was deleted") {
				t.Fatalf("a recreate whose storage failed to resolve: got %v, want a refusal saying nothing was deleted", err)
			}
			if got := vmRecord(t, s, "a").CreatedAt; got != before {
				t.Fatalf("the VM was re-created (%s → %s)", before, got)
			}
		})
	}
}

// I-2 (b): the preflight never takes the host the re-created VM runs on to be
// this one: a caller that names none is refused.
//
// Mutation: default an empty run host to this host (round 4) — this goes
// red.
func TestPreflightLUNs_NeverDefaultsTheRunHost(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := s.preflightLUNs(ctx, lunVM("a", "lun0").Spec, vmRecord(t, s, "a"), ""); err == nil {
		t.Fatal("a preflight that names no run host moved the claim")
	}
	if toks, _ := s.lunHoldTokens(); len(toks) != 0 {
		t.Fatalf("the refused preflight left holds %v", toks)
	}
}

// m-3: a create that takes LUNs over from a replaced VM with no hold token to
// verify is refused, never let through unverified.
//
// Mutation: skip the check without a token (round 4) — a is created and
// this goes red.
func TestCreateVM_ISCSI_ATakeoverWithoutAHoldTokenIsRefused(t *testing.T) {
	s := lunTestServer(t)
	key := mustLUNKey(t, "10.0.0.1", "0")
	cctx := context.WithValue(adminCtx(), replacedVMKey{}, replacedVM{name: "a",
		snap: corrosion.VMDeleteSnapshot{CreatedAt: "x"}, claimed: map[string]string{key: "root"}})
	if _, err := s.CreateVM(cctx, lunVM("a", "lun0")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a takeover with no hold token: got %v, want FailedPrecondition", err)
	}
	requireNoVM(t, s, "a")
}

// writeGuestData stands in for the guest writing its disk.
func writeGuestData(t *testing.T, d *lunDisks, dev string) {
	t.Helper()
	f, err := os.OpenFile(d.files[dev], os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("GUEST-DATA"), 4096); err != nil {
		t.Fatal(err)
	}
}

func guestDataIntact(t *testing.T, d *lunDisks, dev string) bool {
	t.Helper()
	b := make([]byte, 10)
	f, err := os.Open(d.files[dev])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.ReadAt(b, 4096)
	return string(b) == "GUEST-DATA"
}

// tornDownRecreate creates a (an image root on LUN 0, which its guest then
// writes) and runs a recreate of it whose create fails after the teardown.
func tornDownRecreate(t *testing.T) (*Server, *lunDisks, string) {
	t.Helper()
	s := lunImageServer(t)
	d := newLUNDisks(t)
	dev := d.lun("0", 64<<20)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunImageVM("a", "lun0", false)); err != nil {
		t.Fatalf("create: %v", err)
	}
	writeGuestData(t, d, dev)
	fake := s.virt.(*libvirtfake.Fake)
	fake.FailDefineDomain = func(string) error { return errors.New("injected: define refused") }
	err := (&serverOps{s: s}).RecreateVM(ctx, "a", lunImageVM("a", "lun0", false).Spec)
	fake.FailDefineDomain = nil
	if err == nil || !strings.Contains(err.Error(), "torn down") {
		t.Fatalf("the recreate: got %v, want it torn down and failed", err)
	}
	if !strings.Contains(err.Error(), "takes them over as they are") {
		t.Errorf("the torn-down error does not say how to recover the VM's LUNs: %v", err)
	}
	requireNoVM(t, s, "a")
	return s, d, dev
}

// Concern 3: after a recreate torn down and failed, the documented recovery —
// create the VM again, under its name, from its spec — takes its own kept LUN
// over as it is: the guest's disk is not refused for holding data, and
// nothing is written over it, without overwrite.
//
// Mutation: do not take the VM's own kept LUN over on a create (round 4) —
// the recovery is refused "not blank" and this goes red.
func TestRecreate_ISCSI_TheRecoveryAfterATornDownRecreateKeepsTheGuest(t *testing.T) {
	s, d, dev := tornDownRecreate(t)
	if _, err := s.CreateVM(adminCtx(), lunImageVM("a", "lun0", false)); err != nil {
		t.Fatalf("re-creating a after its torn-down recreate: %v", err)
	}
	vmExists(t, s, "a", "after the recovery")
	if len(d.writes) != 1 {
		t.Errorf("writes = %v: the recovery wrote over the VM's own LUN", d.writes)
	}
	if !guestDataIntact(t, d, dev) {
		t.Error("the recovery changed the guest's disk")
	}
}

// Concern 3, the other side: the kept LUN is a's own, and only a's. Another
// VM on it is refused as any non-blank LUN is.
//
// Mutation: take a kept LUN over whatever VM names it — b is created over
// a's guest and this goes red.
func TestRecreate_ISCSI_AKeptLUNIsOnlyItsOwnVMs(t *testing.T) {
	s, d, dev := tornDownRecreate(t)
	_, err := s.CreateVM(adminCtx(), lunImageVM("b", "lun0", false))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not blank") {
		t.Fatalf("another VM on a's kept LUN: got %v, want FailedPrecondition, not blank", err)
	}
	if len(d.writes) != 1 || !guestDataIntact(t, d, dev) {
		t.Errorf("writes = %v: b wrote over a's guest", d.writes)
	}
}

// Concern 3, the other side: a VM DELETED gives its LUN up. Creating one of
// the same name later is a new disk, refused for a LUN that holds data
// unless it says overwrite — as before.
//
// Mutation: take over any LUN whose previous allocation names the VM and
// disk, kept or not — the new a is put on the deleted a's guest and this
// goes red.
func TestCreateVM_ISCSI_ADeletedVMsLUNIsNotTakenOverByItsName(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	dev := d.lun("0", 64<<20)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunImageVM("a", "lun0", false)); err != nil {
		t.Fatalf("create: %v", err)
	}
	writeGuestData(t, d, dev)
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "a"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := s.CreateVM(ctx, lunImageVM("a", "lun0", false))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not blank") {
		t.Fatalf("a new a on the deleted a's LUN: got %v, want FailedPrecondition, not blank", err)
	}
}

// m-1: an I/O error reading the holds is not latched: the next question reads
// them again.
//
// Mutation: latch every load error (round 4) — the second read fails too and
// this goes red.
func TestLUNHold_AnIOErrorIsRetried(t *testing.T) {
	s := lunTestServer(t)
	key := mustLUNKey(t, "10.0.0.1", "0")
	if err := s.putLUNHold(&lunHoldRecord{Token: "tok", VM: "web", ReplacedCreatedAt: "x",
		LUNs: map[string]string{key: "root"}, RunHost: "run-host"}); err != nil {
		t.Fatal(err)
	}
	s2 := restartedLUNServer(s)
	var n atomic.Int32
	prev := lunHoldReadDir
	lunHoldReadDir = func(dir string) ([]os.DirEntry, error) {
		if n.Add(1) == 1 {
			return nil, &os.PathError{Op: "readdirent", Path: dir, Err: syscall.EIO}
		}
		return prev(dir)
	}
	t.Cleanup(func() { lunHoldReadDir = prev })
	if _, err := s2.lunHoldPresent("tok", []string{key}); err == nil {
		t.Fatal("the injected read error was not reported")
	}
	if ok, err := s2.lunHoldPresent("tok", []string{key}); err != nil || !ok {
		t.Fatalf("after one I/O error the holds are still unreadable: present=%v err=%v", ok, err)
	}
}

// lunHoldCond is this host's row of one hold condition.
func lunHoldCond(t *testing.T, s *Server, code string) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, lunHoldEvaluator, code, "host", s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	return row, ok
}

// m-1: a hold record that does not parse stops this host answering LUN
// questions — fail closed — and raises a critical condition naming the file.
// `lv host lun-hold discard` (admin only, audited) moves it aside and the
// holds are read again at once, with no restart; the condition resolves.
//
// Mutation: do not reload after the discard — the host still answers
// nothing and this goes red.
func TestLUNHold_AnUnparsableRecordIsReportedAndDiscardedWithoutARestart(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	key := mustLUNKey(t, "10.0.0.1", "0")
	if err := os.MkdirAll(s.lunHoldDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.lunHoldDir()+"/torn.json", []byte(`{"token":"torn","vm":"we`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.lunHoldPresent("x", []string{key}); err == nil {
		t.Fatal("an unparsable record did not fail the answer closed")
	}
	if _, err := s.CreateVM(ctx, lunVM("b", "lun0")); err == nil {
		t.Fatal("an iSCSI create went on while this host's holds cannot be read")
	}
	s.lunHoldHealthPass(ctx, time.Now())
	row, ok := lunHoldCond(t, s, condLUNHoldUnreadable)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed || row.Severity != corrosion.SeverityCritical ||
		!strings.Contains(row.Evidence, "torn.json") {
		t.Fatalf("condition = %+v (found %v), want a critical %s naming torn.json", row, ok, condLUNHoldUnreadable)
	}
	resp, err := s.ISCSILUNHolds(viewerCtx(), &pb.ISCSILUNHoldsRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.LoadError == "" || len(resp.Holds) != 1 || resp.Holds[0].File != "torn.json" || resp.Holds[0].Error == "" {
		t.Fatalf("list = %+v, want the unreadable torn.json and the load error", resp)
	}
	if _, err := s.ISCSILUNHolds(viewerCtx(), &pb.ISCSILUNHoldsRequest{Discard: "torn.json"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a viewer's discard: got %v, want PermissionDenied", err)
	}
	resp, err = s.ISCSILUNHolds(ctx, &pb.ISCSILUNHoldsRequest{Discard: "torn.json"})
	if err != nil || len(resp.Discarded) != 1 || resp.LoadError != "" {
		t.Fatalf("discard: %+v %v", resp, err)
	}
	if ents, _ := os.ReadDir(s.lunHoldDir() + "/" + lunHoldDiscardedDir); len(ents) != 1 {
		t.Fatalf("the discarded record was not kept aside: %v", ents)
	}
	if _, err := s.lunHoldPresent("x", []string{key}); err != nil {
		t.Fatalf("after the discard the holds still cannot be read: %v", err)
	}
	if _, err := s.CreateVM(ctx, lunVM("b", "lun0")); err != nil {
		t.Fatalf("a create once the record was discarded: %v", err)
	}
	rows, err := s.db.Query(context.Background(), `SELECT detail FROM audit_log WHERE action = 'host.lun_hold.discard'`)
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "torn.json") {
		t.Fatalf("audit rows %v (%v), want one naming torn.json", rows, err)
	}
	s.lunHoldHealthPass(ctx, time.Now())
	if row, _ := lunHoldCond(t, s, condLUNHoldUnreadable); row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition after the discard = %s, want resolved", row.Lifecycle)
	}
}

// m-1, m-4: a hold standing longer than lunHoldStandingAfter is reported,
// naming its VM, LUN and run host; a discard by LUN moves it aside — never
// one whose re-create still runs here.
//
// Mutation: report no standing hold — this goes red.
func TestLUNHold_AStandingHoldIsReportedAndDiscardedByItsLUN(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	key := mustLUNKey(t, "10.0.0.1", "0")
	since := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano)
	if err := s.putLUNHold(&lunHoldRecord{Token: "tok", VM: "web", ReplacedCreatedAt: "x",
		LUNs: map[string]string{key: "root"}, RunHost: "run-host", Since: since}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ISCSILUNHolds(ctx, &pb.ISCSILUNHoldsRequest{Discard: key}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("discard of a hold whose re-create runs: got %v, want FailedPrecondition", err)
	}
	s.lunHoldHealthPass(ctx, time.Now())
	if _, ok := lunHoldCond(t, s, condLUNHoldStanding); ok {
		t.Fatal("a hold whose re-create still runs was reported standing")
	}
	s.finishLUNHold("tok")
	s.lunHoldHealthPass(ctx, time.Now())
	row, ok := lunHoldCond(t, s, condLUNHoldStanding)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed || row.Severity != corrosion.SeverityWarning ||
		!strings.Contains(row.Evidence, "web") || !strings.Contains(row.Evidence, "run-host") ||
		!strings.Contains(row.Evidence, key) {
		t.Fatalf("condition = %+v (found %v), want a warning naming web, its LUN and run-host", row, ok)
	}
	if _, err := s.ISCSILUNHolds(ctx, &pb.ISCSILUNHoldsRequest{Discard: "nothing-by-that-name"}); status.Code(err) != codes.NotFound {
		t.Fatalf("discard of nothing: got %v, want NotFound", err)
	}
	resp, err := s.ISCSILUNHolds(ctx, &pb.ISCSILUNHoldsRequest{Discard: key})
	if err != nil || len(resp.Discarded) != 1 || len(resp.Holds) != 0 {
		t.Fatalf("discard by LUN: %+v %v", resp, err)
	}
	if ok, err := s.lunHoldPresent("tok", []string{key}); err != nil || ok {
		t.Fatalf("the discarded hold still stands: %v %v", ok, err)
	}
	s.lunHoldHealthPass(ctx, time.Now())
	if row, _ := lunHoldCond(t, s, condLUNHoldStanding); row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition after the discard = %s, want resolved", row.Lifecycle)
	}
}

// I-1: a rebuild whose create committed moves the LUN's checkpoint to its
// moved allocation — and only then (a refused one does not; see
// TestRecreate_ISCSI_ARecreateRefusedAtItsDeleteAbandonsItsHold).
//
// Mutation: report the rebuild's create as not attempted — the checkpoint
// stays behind and this goes red.
func TestRebuildVM_ISCSI_ACommittedRebuildMovesTheCheckpoint(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	key := mustLUNKey(t, "10.0.0.1", "0")
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "a"}); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if c, err := corrosion.GetLUNResolved(ctx, s.db, key); err != nil || c != 1 {
		t.Fatalf("checkpoint after the committed rebuild = %d (%v), want 1 (its moved allocation)", c, err)
	}
	if toks, _ := s.lunHoldTokens(); len(toks) != 0 {
		t.Fatalf("the rebuild's hold on its own host stands after its rows are here: %v", toks)
	}
}
