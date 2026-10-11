package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ioGate is a release-feature gate for the disk/NIC feature: open it mints the
// feature's grant, closed it refuses as the real gate does. Writes records the
// order the grant was handed out in (see TestIOGrant_*).
type ioGate struct {
	t      testing.TB
	on     bool
	grants *int
	// latchedButRefuses models a latched token whose first use cannot be
	// acknowledged: FeatureAvailable is true, WithFeature refuses.
	latchedButRefuses bool
}

func (g ioGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	if g.grants != nil {
		*g.grants++ // every run of the gate, granted or refused
	}
	if g.latchedButRefuses {
		return status.Errorf(codes.Unavailable, "could not confirm %s with every host", f)
	}
	if !g.on {
		return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s)", f, capabilities.ReleaseToken)
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g ioGate) FeatureAvailable(capabilities.Feature) bool { return g.on || g.latchedButRefuses }

// Until the disk/NIC feature gate latches, every way of setting discard, detect_zeroes,
// a throttle or NIC queues is refused with FailedPrecondition naming the cluster
// upgrade: an older owner would drop them from the spec it rewrites.
//
// Mutations: make specSetsDiskNICIO ignore one field kind — that case goes red;
// make the refusal never fire — every case goes red.
func TestDiskNICIOGate_UnlatchedRefusesEveryWayOfSettingTuning(t *testing.T) {
	ctx := context.Background()
	s := &Server{releaseFeatures: ioGate{t: t, on: false}}
	for name, spec := range map[string]*pb.VMSpec{
		"discard":       {Disks: []*pb.DiskSpec{{Name: "root", Discard: "unmap"}}},
		"discard off":   {Disks: []*pb.DiskSpec{{Name: "root", Discard: "ignore"}}},
		"detect_zeroes": {Disks: []*pb.DiskSpec{{Name: "root", DetectZeroes: "on"}}},
		"iotune":        {Disks: []*pb.DiskSpec{{Name: "root"}, {Name: "d", Io: &pb.DiskIOLimits{ReadIopsSec: 1}}}},
		"queues":        {Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}}},
	} {
		err := s.refuseUnlatchedDiskNICIO(ctx, spec)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
			t.Errorf("create with %s: err = %v, want FailedPrecondition naming the cluster upgrade", name, err)
		}
	}
	// A compose clear (`iotune: {}`) sets nothing: it is not refused.
	if err := s.refuseUnlatchedDiskNICIO(ctx, &pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root", Io: &pb.DiskIOLimits{}}}}); err != nil {
		t.Errorf("an empty iotune was refused before the latch: %v", err)
	}
	// A spec with none of them is not refused.
	if err := s.refuseUnlatchedDiskNICIO(ctx, &pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root"}}, Network: []*pb.NetworkAttachment{{Name: "n"}}}); err != nil {
		t.Errorf("an untuned spec was refused: %v", err)
	}
	// A latched cluster accepts them; a server with no gate is unlatched.
	latched := &Server{releaseFeatures: ioGate{t: t, on: true}}
	if err := latched.refuseUnlatchedDiskNICIO(ctx, &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}}}); err != nil {
		t.Errorf("latched: %v", err)
	}
	if err := (&Server{}).refuseUnlatchedDiskNICIO(ctx, &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}}}); err == nil {
		t.Error("a server with no gate accepted queues")
	}
}

// The recreate preflight judges a spec before a teardown, so it must refuse an
// unlatched tuning before anything is touched.
func TestDiskNICIOGate_RecreatePreflightRefusesUnlatched(t *testing.T) {
	s := &Server{releaseFeatures: ioGate{t: t, on: false}}
	_, err := s.recreatePreflightSpec(context.Background(),
		&pb.VMSpec{Cpu: 2, Disks: []*pb.DiskSpec{{Name: "root", Io: &pb.DiskIOLimits{TotalIopsSec: 5}}}}, "host")
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition", err)
	}
}

// lv disk-io is refused before the latch when it sets a limit, and clearing is
// not (there is nothing set to protect).
//
// Mutation: drop the refusal from SetDiskIO — the set case goes red.
func TestDiskNICIOGate_SetDiskIO(t *testing.T) {
	s, _, ctx := ioVM(t, "running")
	s.SetReleaseFeatureGate(ioGate{t: t, on: false})
	_, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
		t.Fatalf("set before the latch: %v", err)
	}
	if got := loadStoredSpec(t, s, "io").Disks[0].Io; got != nil {
		t.Errorf("a refused call recorded limits: %+v", got)
	}
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root"}); err != nil {
		t.Errorf("clearing before the latch: %v", err)
	}
	s.SetReleaseFeatureGate(ioGate{t: t, on: true})
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}); err != nil {
		t.Errorf("set after the latch: %v", err)
	}
}

// UpdateVM's explicit hardware redefine is refused before the latch, as is a
// request carrying tuning (below).
func TestDiskNICIOGate_HardwareRedefine(t *testing.T) {
	s, _, ctx := ioVM(t, "stopped")
	s.SetReleaseFeatureGate(ioGate{t: t, on: false})
	// A VM whose spec carries tuning: the redefine renders it, so it waits (m5).
	tuned := &pb.VMSpec{Name: "io", Cpu: 2, MemoryMib: 512, Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio", Discard: "unmap"}}}
	if _, _, err := corrosion.MutateDesiredSpec(ctx, s.db, "io", func(string) (string, error) { return seedSpecJSON(t, tuned), nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "io", RedefineHardware: true}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("UpdateVM redefine_hardware of a tuned VM before the latch: %v", err)
	}
}

// CreateVM itself refuses (not only the compose entry): a direct create, a
// forwarded leg and a recreate all reach it.
//
// Mutation: drop the refusal from CreateVM — red.
func TestDiskNICIOGate_CreateVMRefusesUnlatched(t *testing.T) {
	s := testServer(t) // no gate: not latched
	_, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "gated", Cpu: 1, MemoryMib: 256, Image: "img",
		Disks: []*pb.DiskSpec{{Name: "root", Discard: "unmap"}},
	}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
		t.Errorf("CreateVM with discard before the latch: %v", err)
	}
}

// UpdateVM carries the tuning itself (the owner applies it): before the latch a
// request naming any is refused at the entry node, and a refusal changes nothing.
func TestDiskNICIOGate_UpdateVMTuningRequestUnlatched(t *testing.T) {
	s, _, ctx := ioVM(t, "stopped")
	s.SetReleaseFeatureGate(ioGate{t: t, on: false})
	for name, req := range map[string]*pb.UpdateVMRequest{
		"disk": {Name: "io", DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", Discard: "ignore"}}},
		"nic":  {Name: "io", NicQueues: []*pb.NICQueuesUpdate{{Ordinal: 0, Queues: 4}}},
	} {
		if _, err := s.UpdateVM(ctx, req); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Restore-live and promote take their spec from a backup manifest or a caller:
// before the gate opens the tuning is stripped (a restore main allows must still
// work), and after it the values are validated.
//
// Mutations: skip the strip — the unlatched case goes red; skip validation — the
// latched invalid cases go red; refuse an invalid value (as before) — red.
func TestRestrictRestoredTuning(t *testing.T) {
	mk := func() *pb.VMSpec {
		return &pb.VMSpec{Name: "r",
			Disks:   []*pb.DiskSpec{{Name: "root", Discard: "unmap", DetectZeroes: "on", Io: &pb.DiskIOLimits{ReadIopsSec: 5}}},
			Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}}}
	}
	ctx := context.Background()
	un := &Server{releaseFeatures: ioGate{t: t, on: false}}
	spec := mk()
	rr, err := un.restrictRestoredTuning(ctx, spec)
	stripped := rr.stripped
	if err != nil || !stripped || rr.refused != nil || specSetsDiskNICIO(spec) {
		t.Errorf("unlatched: stripped=%v err=%v spec=%+v", stripped, err, spec)
	}
	if untouched := (&pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root"}}}); true {
		if rr, err := un.restrictRestoredTuning(ctx, untouched); rr.stripped || err != nil {
			t.Errorf("a spec with no tuning reported stripped=%v err=%v", rr.stripped, err)
		}
	}
	la := &Server{releaseFeatures: ioGate{t: t, on: true}}
	spec = mk()
	lr, err := la.restrictRestoredTuning(ctx, spec)
	st, g := lr.stripped, lr.grant
	if err != nil || st || !specSetsDiskNICIO(spec) || g.Check(capabilities.FeatureVMDiskNICIO) != nil {
		t.Errorf("latched valid: stripped=%v err=%v grant=%v", st, err, g)
	}
	// Invalid values after the latch: dropped, not refused (a recovery path),
	// each named; the valid rest is kept under the grant.
	bad := mk()
	bad.Network[0].Queues = 4096
	br, err := la.restrictRestoredTuning(ctx, bad)
	if err != nil || bad.Network[0].Queues != 0 || bad.Disks[0].Discard != "unmap" || bad.Disks[0].Io == nil ||
		br.grant.Check(capabilities.FeatureVMDiskNICIO) != nil || !strings.Contains(strings.Join(br.invalid, ";"), "network 0 queues") {
		t.Errorf("latched, queues 4096: %+v err=%v spec=%+v; want the queues dropped and named, the disk kept", br, err, bad)
	}
	bad = mk()
	bad.Disks[0].Io = &pb.DiskIOLimits{TotalBytesSec: 1, ReadBytesSec: 1}
	br, err = la.restrictRestoredTuning(ctx, bad)
	joined := strings.Join(br.invalid, ";")
	if err != nil || bad.Disks[0].Io != nil || bad.Disks[0].Discard != "" || bad.Disks[0].DetectZeroes != "" || bad.Network[0].Queues != 4 ||
		!strings.Contains(joined, `disk "root" io`) || !strings.Contains(joined, `disk "root" discard`) {
		t.Errorf("latched, total with read: %+v err=%v spec=%+v; want the disk's tuning dropped and named, the NIC kept", br, err, bad)
	}
}

// The corrosion writers of the feature refuse a call without the feature's
// grant, so a write that skips the gate cannot land.
//
// Mutation: drop g.Check from either writer — the matching case goes red.
func TestDiskNICIOWriters_RefuseWithoutAGrant(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "w", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{Name: "w"}))
	var none capabilities.FeatureGrant
	if _, _, err := corrosion.MutateDesiredSpecTuning(ctx, s.db, none, "w", func(old string) (string, error) { return old + " ", nil }); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("MutateDesiredSpecTuning without a grant: %v", err)
	}
	other := capabilities.GrantForTest(t, capabilities.FeatureVMLimits)
	if _, _, err := corrosion.MutateDesiredSpecTuning(ctx, s.db, other, "w", func(old string) (string, error) { return old + " ", nil }); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("MutateDesiredSpecTuning with another feature's grant: %v", err)
	}
	if err := corrosion.InsertVMWithTuning(ctx, s.db, none, corrosion.VMRecord{Name: "x", HostName: "test-host", State: "stopped"}, nil, nil, nil, nil, false); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("InsertVMWithTuning without a grant: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "x"); vm != nil {
		t.Error("a refused insert wrote a row")
	}
	ok := capabilities.GrantForTest(t, capabilities.FeatureVMDiskNICIO)
	if _, _, err := corrosion.MutateDesiredSpecTuning(ctx, s.db, ok, "w", func(old string) (string, error) { return old, nil }); err != nil {
		t.Errorf("MutateDesiredSpecTuning with the grant: %v", err)
	}
}

// I1: the default discard of a plain create is applied only when the feature
// is ALREADY recorded used and acknowledged here. Before the first use the
// create never reaches the gate, however degraded the cluster is: no first-use
// wait, no unacknowledged row.
//
// Mutation: have ioGrantIfUsed skip the recorded-used read — the first-use case
// goes red.
func TestIOGrant_DefaultDiscardNeverPerformsTheFirstUse(t *testing.T) {
	ctx := context.Background()
	var n int
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(ioGate{t: t, on: true, grants: &n})
	if _, ok := s.ioGrantIfUsed(ctx); ok || n != 0 {
		t.Fatalf("before the first use: ok=%v, gate runs=%d; a plain create must not touch the gate", ok, n)
	}
	// Recorded but not yet acknowledged (a first use in flight): still nothing.
	tok := featureToken(capabilities.FeatureVMDiskNICIO)
	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, tok, string(capabilities.FeatureVMDiskNICIO), "h", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ioGrantIfUsed(ctx); ok || n != 0 {
		t.Fatalf("unacknowledged use: ok=%v runs=%d", ok, n)
	}
	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, tok, string(capabilities.FeatureVMDiskNICIO), "h", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ioGrantIfUsed(ctx); !ok || n != 1 {
		t.Fatalf("acknowledged use: ok=%v runs=%d, want a grant", ok, n)
	}
	closed := testServer(t)
	closed.SetReleaseFeatureGate(ioGate{t: t, on: false})
	if _, ok := closed.ioGrantIfUsed(ctx); ok {
		t.Error("closed gate handed out a grant")
	}
	if _, err := closed.ioGrant(ctx); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (vm_disk_nic_io needs release_2026_11_v1)") {
		t.Errorf("closed ioGrant: %v", err)
	}
}

// m4: the entry-node check records and grants nothing, even when it passes.
func TestIOFeatureGate_EntryCheckTakesNoGrant(t *testing.T) {
	var n int
	s := testServer(t)
	s.SetReleaseFeatureGate(ioGate{t: t, on: true, grants: &n})
	if err := s.ioFeatureGate(context.Background()); err != nil || n != 0 {
		t.Errorf("open: err=%v runs=%d", err, n)
	}
	s.SetReleaseFeatureGate(ioGate{t: t, on: false, grants: &n})
	err := s.ioFeatureGate(context.Background())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "vm_disk_nic_io needs release_2026_11_v1") || n != 0 {
		t.Errorf("closed: err=%v runs=%d", err, n)
	}
	// A gate with a refusal entry point (health.Checker) is asked for it.
	r := &refuserGate{ioGate: ioGate{t: t, on: false, grants: &n}}
	s.SetReleaseFeatureGate(r)
	if err := s.ioFeatureGate(context.Background()); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "lv cluster upgrade-status") || r.refusals != 1 || n != 0 {
		t.Errorf("refuser: err=%v refusals=%d runs=%d", err, r.refusals, n)
	}
}

type refuserGate struct {
	ioGate
	refusals int
}

func (g *refuserGate) FeatureRefusal(context.Context, capabilities.Feature) error {
	g.refusals++
	return status.Error(codes.FailedPrecondition,
		"the cluster upgrade must finish first (vm_disk_nic_io needs release_2026_11_v1): not on this release yet: h2 (v0) — see `lv cluster upgrade-status`")
}

// m5: a hardware redefine of a VM with no tuning writes none, so it is not
// gated and takes no grant.
func TestIOGrant_RedefineOfAnUntunedVMTakesNone(t *testing.T) {
	var n int
	s, _, ctx := ioVM(t, "stopped")
	s.SetReleaseFeatureGate(ioGate{t: t, on: false, grants: &n})
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "io", RedefineHardware: true}); err != nil {
		t.Errorf("redefine_hardware of an untuned VM on a closed gate: %v", err)
	}
	if n != 0 {
		t.Errorf("took %d grants", n)
	}
}

// m1/N2: a restore whose tuning the gate refuses AFTER the latch is never
// refused: the tuning is stripped and the result says the gate refused (not "the
// upgrade has not finished"). The audit row is written by the caller once the
// restore cannot be refused any more, against the VM's ACTUAL name, under an
// action that fits promote and failover too; a strip before the latch writes none.
//
// Mutations: return the gate's error instead of stripping — red; audit inside
// restrictRestoredTuning (before the caller's commit point) — the no-row-yet check
// goes red; audit the spec's original name — the target check goes red.
func TestRestrictRestoredTuning_RefusalAfterTheLatchStripsAndAudits(t *testing.T) {
	ctx := adminCtx()
	s := testServer(t)
	s.SetReleaseFeatureGate(ioGate{t: t, latchedButRefuses: true})
	spec := &pb.VMSpec{Name: "orig", Disks: []*pb.DiskSpec{{Name: "root", Discard: "unmap"}}}
	rr, err := s.restrictRestoredTuning(ctx, spec)
	if err != nil || !rr.stripped || rr.refused == nil || specSetsDiskNICIO(spec) {
		t.Fatalf("restricted = %+v err=%v spec=%+v", rr, err, spec)
	}
	if !strings.Contains(rr.why(), "refused after the latch") || strings.Contains(rr.why(), "has not finished") {
		t.Errorf("why = %q, want the post-latch wording", rr.why())
	}
	count := func(target string) int {
		rows, qerr := s.db.Query(context.Background(), `SELECT action FROM audit_log WHERE action = ? AND target = ?`, "vm.tuning_dropped", target)
		if qerr != nil {
			t.Fatal(qerr)
		}
		return len(rows)
	}
	if count("orig") != 0 || count("renamed") != 0 {
		t.Fatal("restrictRestoredTuning wrote the audit row itself; the restore may still be refused")
	}
	s.auditTuningDropped(ctx, rr, "renamed", "restore")
	if count("renamed") != 1 || count("orig") != 0 {
		t.Errorf("audit rows: renamed=%d orig=%d, want 1 and 0", count("renamed"), count("orig"))
	}
	// A strip before the latch is not an audit event.
	pre := testServer(t)
	pre.SetReleaseFeatureGate(ioGate{t: t, on: false})
	spec2 := &pb.VMSpec{Name: "p", Disks: []*pb.DiskSpec{{Name: "root", Discard: "unmap"}}}
	pr, _ := pre.restrictRestoredTuning(ctx, spec2)
	pre.auditTuningDropped(ctx, pr, "p", "restore")
	rows, _ := pre.db.Query(context.Background(), `SELECT action FROM audit_log WHERE action = ?`, "vm.tuning_dropped")
	if !pr.stripped || pr.refused != nil || len(rows) != 0 || !strings.Contains(pr.why(), "has not finished") {
		t.Errorf("pre-latch: %+v rows=%d", pr, len(rows))
	}
}

// The node that WRITES tuning takes the feature's grant: an UpdateVM carrying
// tuning and a SetDiskIO that sets a limit each take one; a SetDiskIO that
// clears takes none (it adds nothing). The entry check is the local hint and
// takes none.
//
// Mutations: write UpdateVM's spec with plain MutateDesiredSpec and no grant —
// the UpdateVM case goes red; skip the grant in SetDiskIO — the set case does.
func TestIOGrant_TakenByTheNodeThatWritesTuning(t *testing.T) {
	var n int
	s, _, ctx := ioVM(t, "stopped")
	s.SetReleaseFeatureGate(ioGate{t: t, on: true, grants: &n})
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "io", DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", Discard: "unmap"}}}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	if n != 1 {
		t.Errorf("UpdateVM with tuning took %d grants, want 1", n)
	}
	n = 0
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}); err != nil {
		t.Fatalf("SetDiskIO set: %v", err)
	}
	if n != 1 {
		t.Errorf("SetDiskIO set took %d grants, want 1", n)
	}
	n = 0
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root"}); err != nil {
		t.Fatalf("SetDiskIO clear: %v", err)
	}
	if n != 0 {
		t.Errorf("SetDiskIO clear took %d grants, want 0", n)
	}
}

// m2: a compose file that sets no tuning never asks the gate (a plain deploy
// mid-roll pings nobody); one that does asks it once and is refused with the
// VM's name. CreateVM runs the entry check only after the permission check.
//
// Mutations: call the gate before the scan — the plain-file case goes red; run
// the entry check before RequirePerm in CreateVM — the permission case goes red.
func TestRefuseUnlatchedStack_PlainFileNeverAsksTheGate(t *testing.T) {
	var n int
	r := &refuserGate{ioGate: ioGate{t: t, on: false, grants: &n}}
	s := testServer(t)
	s.SetReleaseFeatureGate(r)
	plain := &compose.File{VMs: map[string]compose.VMDef{"a": {Disks: map[string]compose.DiskDef{"root": {}}}}}
	if err := s.refuseUnlatchedStackDiskNICIO(context.Background(), plain); err != nil || r.refusals != 0 {
		t.Fatalf("plain file: err=%v gate asked %d times", err, r.refusals)
	}
	tuned := &compose.File{VMs: map[string]compose.VMDef{"a": {Disks: map[string]compose.DiskDef{"root": {Discard: "on"}}}}}
	err := s.refuseUnlatchedStackDiskNICIO(context.Background(), tuned)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `vm "a"`) || r.refusals != 1 {
		t.Fatalf("tuned file: err=%v asks=%d, want one refusal naming vm a", err, r.refusals)
	}
}

func TestCreateVM_EntryCheckRunsAfterThePermissionCheck(t *testing.T) {
	r := &refuserGate{ioGate: ioGate{t: t, on: false}}
	s := testServer(t)
	s.SetReleaseFeatureGate(r)
	viewer := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "v"), ctxKeyRole, "viewer")
	_, err := s.CreateVM(viewer, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "x", Cpu: 1, MemoryMib: 256,
		Disks: []*pb.DiskSpec{{Name: "root", Discard: "unmap"}}}})
	if status.Code(err) != codes.PermissionDenied || r.refusals != 0 {
		t.Fatalf("err=%v gate asked %d times, want PermissionDenied before any gate work", err, r.refusals)
	}
}
