package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// Round 5 of the colonelpanik/litevirt#256 review (re-review 4).

// mergedAndWrittenSince is a VM off whose overlay is already in its disk (a
// recorded live pivot), with the guest's writes on the disk since.
func mergedAndWrittenSince(t *testing.T) (*Server, string) {
	t.Helper()
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	for _, f := range []func(string) error{pitoverlay.MarkCommitting, pitoverlay.MarkPivoting, pitoverlay.MarkCommitted} {
		if err := f(live); err != nil {
			t.Fatal(err)
		}
	}
	writeBase(t, live, "write -P 0x33 65536 65536")
	return s, live
}

// I2: --force-commit never overrides a merged overlay on its own. That
// commit would write the window's old blocks over everything the guest wrote
// since, so it needs its own flag, which the refusal names with the
// consequence; the dry run says the flag is needed.
//
// Mutation "force overrides pivoted" — red.
func TestResolvePITOverlay_ForcingAMergedOverlayNeedsItsOwnFlag(t *testing.T) {
	s, live := mergedAndWrittenSince(t)
	dry, err := s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root"})
	if err != nil || !dry.GetNeedsOverwriteNewerWrites() {
		t.Fatalf("dry run = %+v, %v; want it to say --overwrite-newer-writes is needed", dry, err)
	}
	req := &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "commit", Confirm: true, ForceCommit: true}
	_, err = s.ResolvePITOverlay(adminCtx(), req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--overwrite-newer-writes") {
		t.Fatalf("forced commit of a merged overlay = %v, want refused naming --overwrite-newer-writes", err)
	}
	if !regionHolds(t, live, 0x33) || !pitoverlay.Present(live) {
		t.Fatal("the refused commit touched the disk or the overlay")
	}
	req.OverwriteNewerWrites = true
	if resp, err := s.ResolvePITOverlay(adminCtx(), req); err != nil || !resp.GetDone() || !holdsTheWindowsWrite(t, live) {
		t.Fatalf("with --overwrite-newer-writes = %+v, %v", resp, err)
	}
}

// m1: when the diverged mark cannot be written, the VM is still held as
// unknown — never advised (or later settled) as half-written.
//
// Mutation "fall back to the binding as it stands" — red.
func TestHeal_AFailedDivergedMarkStillHoldsAsUnknown(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{}) // the domain runs on its disk
	windowOverlay(t, live)
	if err := pitoverlay.MarkCommitting(live); err != nil {
		t.Fatal(err)
	}
	prev := pitMarkDiverged
	pitMarkDiverged = func(string, string) error { return errors.New("ENOSPC") }
	defer func() { pitMarkDiverged = prev }()
	err := healWeb(t, s)
	msg := status.Convert(err).Message()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(msg, "verdict unknown") || strings.Contains(msg, "--commit --confirm") {
		t.Fatalf("heal = %v; want held as unknown, never advised to commit", err)
	}
}

// I3: layer 2 is tried only once the pit_overlay release feature is open on
// this host; before that the copy takes the existing path (here the last
// layer, marked), and no overlay is ever made.
//
// Mutation "layer 2 ungated" — red.
func TestCopy_LayerTwoWaitsForThePITOverlayFeature(t *testing.T) {
	recordQemuImg(t)
	s, dir, live := pitServer(t)
	gate := &pitFeatureGate{available: false}
	s.SetReleaseFeatureGate(gate)
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)
	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if slices.Contains(snap.calls, "snapshot") || pitoverlay.Present(live) {
		t.Fatal("layer 2 ran before the pit_overlay feature was open")
	}
	if recs := replicaRecordsOf(t, dir, "web"); len(recs) != 1 || !recs[0].NotPointInTime {
		t.Fatalf("records %+v: want the existing last layer's marked copy", recs)
	}
	// The local read alone decided: the gate was never asked (its refusal
	// pings every lagging host), so nothing was recorded either, and the
	// copy says why with the release refusal's own text.
	if gate.calls != 0 {
		t.Fatalf("the release gate was asked %d time(s) below the latch", gate.calls)
	}
	if !slices.ContainsFunc(pitEventDetails(t, s, "web", "disk.replica_not_point_in_time"), func(d string) bool {
		return strings.Contains(d, "external snapshot: the cluster upgrade must finish first (pit_overlay needs "+capabilities.ReleaseToken+")")
	}) {
		t.Fatalf("no not-point-in-time event naming the release refusal: %v", pitEventDetails(t, s, "web", "disk.replica_not_point_in_time"))
	}
}

// m2: the dry run answers while the VM runs (the heal's hold points the
// admin at it), and shows the overlay's own time; only --confirm needs the
// VM stopped.
//
// Mutation "dry run refused while the VM runs" — red.
func TestResolvePITOverlay_TheDryRunAnswersWhileTheVMRuns(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t) // the domain is running
	windowOverlay(t, live)
	resp, err := s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root"})
	if err != nil || resp.GetVerdict() == "" || resp.GetOverlayCurrent() == "" {
		t.Fatalf("dry run while the VM runs = %+v, %v", resp, err)
	}
	_, err = s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "discard", Confirm: true})
	if status.Code(err) != codes.FailedPrecondition || !pitoverlay.Present(live) {
		t.Fatalf("a confirmed action while the VM runs = %v; want refused", err)
	}
}

// I3: a pivot recorded long before the disk's last write, with the VM on its
// disk, is not taken as landed: the VM is held and the binding marked
// diverged, the overlay kept.
//
// Mutation "pivoting uncapped" (in Assess) — red.
func TestHeal_APivotRecordedLongAgoIsHeldAndMarkedDiverged(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{}) // the domain runs on its disk
	windowOverlay(t, live)
	_ = pitoverlay.MarkCommitting(live)
	_ = pitoverlay.MarkPivoting(live)
	long := time.Now().Add(-time.Hour)
	if err := os.Chtimes(pitoverlay.SidecarPath(live), long, long); err != nil {
		t.Fatal(err)
	}
	writeBase(t, live, "write -P 0x33 0 512")
	if err := healWeb(t, s); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("heal = %v, want held", err)
	}
	if b, err := pitoverlay.BindingOf(live); err != nil || b.State != pitoverlay.StateDiverged || !pitoverlay.Present(live) {
		t.Fatalf("binding %+v (%v), present %v; want diverged and kept", b, err, pitoverlay.Present(live))
	}
}

// I1: the in-place restore is the way to restore a disk held on an overlay
// that cannot be trusted: it sets the overlay aside (kept, never deleted),
// clears the hold, and restores over the disk — where a hand restore that
// left the overlay in place would meet it.
//
// Mutation "in-place restore refuses a held overlay" — red.
func TestInPlaceRestore_SetsAHeldOverlayAsideThenRestores(t *testing.T) {
	s, live := stoppedWithStaleOverlay(t)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	_ = healWeb(t, s) // held
	dest, err := s.inPlaceRestoreLocked(context.Background(), "web", "root")
	if err != nil {
		t.Fatalf("in-place restore over a held overlay: %v", err)
	}
	if err := dest.place(stagedImage(t, live)); err != nil {
		t.Fatalf("place the restored image: %v", err)
	}
	if pitoverlay.Present(live) {
		t.Fatal("the overlay is still where the restore writes")
	}
	if aside, _ := filepath.Glob(pitoverlay.Path(live) + ".orphan-*"); len(aside) == 0 {
		t.Fatal("the overlay was not kept")
	}
	if row, _ := heldCondition(t, s, "web", "root"); row.Lifecycle != "resolved" {
		t.Errorf("the hold did not clear: %+v", row)
	}
}

// I3, rollback: below the pit_overlay feature a host settles no overlay — a
// running VM on one is not even committed live; it is held, with the reason.
//
// Mutation "the heal ignores the gate" — red.
func TestHeal_BelowThePITOverlayFeatureNothingIsCommittedLive(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)
	windowOverlay(t, live)
	onOverlay(s, snap, live)
	s.SetReleaseFeatureGate(&pitFeatureGate{available: false})
	err := healWeb(t, s)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "pit_overlay") {
		t.Fatalf("heal below the feature = %v; want held, naming pit_overlay", err)
	}
	if slices.Contains(snap.calls, "commit") || !pitoverlay.Present(live) {
		t.Fatal("an overlay was committed below the feature")
	}
}
