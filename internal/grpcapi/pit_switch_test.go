package grpcapi

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// The pit_overlay release-token switch (layer 2 through
// WithReleaseFeature), and the residuals of the #256 re-review 5 that block
// opening it (P1, P3, P7, P8, P9).

// pitFeatureGate is a release gate that counts the pit_overlay writes it
// is asked to gate. available is FeatureAvailable (the local latch read);
// refuse, when set, is WithFeature's refusal.
type pitFeatureGate struct {
	mu        sync.Mutex
	available bool
	refuse    error
	calls     int
	// during, if set, runs inside the gate before the write (the moment the
	// used record exists and every recipient holds it).
	during func()
	t      testing.TB
}

func (g *pitFeatureGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	if f == capabilities.FeaturePITOverlay {
		g.mu.Lock()
		g.calls++
		g.mu.Unlock()
	}
	if g.refuse != nil {
		return g.refuse
	}
	if g.during != nil {
		g.during()
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *pitFeatureGate) FeatureAvailable(capabilities.Feature) bool { return g.available }

func (g *pitFeatureGate) pitCalls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

func pitEventDetails(t *testing.T, s *Server, vm, evType string) []string {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, vm, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		if e.Type == evType {
			out = append(out, e.Detail)
		}
	}
	return out
}

// stagedImage is a restored image ready to be placed over disk: a fresh qcow2
// beside it.
func stagedImage(t *testing.T, disk string) string {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(disk), "restore-test.tmp")
	if err := qcow2.Create(tmp, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	return tmp
}

// The window is opened only under the gate's grant, and only after the
// copy's cheap local refusals: a copy that cannot make an overlay here (no
// snapshotter, a domain that is not running, a disk on tmpfs) never asks the
// gate, so it never marks the feature used — which would block a rollback
// below the release with no overlay ever made.
//
// Mutation "grant before the local refusals" — red.
func TestCopy_TheGrantIsTakenOnlyAfterTheLocalRefusals(t *testing.T) {
	recordQemuImg(t)
	cases := []struct {
		name  string
		setup func(t *testing.T, s *Server)
	}{
		{"no snapshotter", func(t *testing.T, s *Server) { s.SetPointInTimeSnapshotter(nil) }},
		{"domain not running", func(t *testing.T, s *Server) {
			s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
		}},
		{"overlay would sit on tmpfs", func(t *testing.T, s *Server) {
			t.Cleanup(pitoverlay.SetVolatileOKForTest(false))
			t.Cleanup(pitoverlay.SetDirFSTypeForTest(pitoverlay.FSTmpfs))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, live := pitServer(t)
			gate := &pitFeatureGate{available: true, t: t}
			s.SetReleaseFeatureGate(gate)
			snap := &fakePITSnapshotter{}
			s.SetPointInTimeSnapshotter(snap)
			tc.setup(t, s)
			vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
			disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
			if _, err := s.copyViaExternalSnapshot(context.Background(), vm, &disks[0], filepath.Join(t.TempDir(), "dst.qcow2"), nil); err == nil {
				t.Fatal("layer 2 succeeded where it must refuse locally")
			}
			if n := gate.pitCalls(); n != 0 {
				t.Fatalf("the release gate was asked %d time(s) for a copy that refused locally", n)
			}
			if pitoverlay.Present(live) || slices.Contains(snap.calls, "snapshot") {
				t.Fatal("an overlay was made")
			}
		})
	}
}

// After the latch, a gate that refuses (a host rolled back after it, a first
// use not yet acknowledged) means no window: the copy takes the existing
// path, marked, and no overlay or window token exists.
//
// Mutation "gate removed" (the window opened without WithReleaseFeature) —
// red.
func TestCopy_ARefusingGateOpensNoWindow(t *testing.T) {
	recordQemuImg(t)
	s, dir, live := pitServer(t)
	refusal := status.Error(codes.Unavailable, "not yet acknowledged by host-c")
	gate := &pitFeatureGate{available: true, refuse: refusal, t: t}
	s.SetReleaseFeatureGate(gate)
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)
	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if gate.pitCalls() != 1 {
		t.Fatalf("gate asked %d times, want once", gate.pitCalls())
	}
	if slices.Contains(snap.calls, "snapshot") || pitoverlay.Present(live) {
		t.Fatal("a window was opened through a gate that refused")
	}
	if recs := replicaRecordsOf(t, dir, "web"); len(recs) != 1 || !recs[0].NotPointInTime {
		t.Fatalf("records %+v: want the existing last layer's marked copy", recs)
	}
}

// With the gate open, the window token and the overlay are written inside it,
// after the gate passed (the used record exists): the snapshot never runs
// before the gate does.
//
// Mutation "snapshot outside the grant" — red.
func TestCopy_TheWindowIsWrittenInsideTheGate(t *testing.T) {
	recordQemuImg(t)
	s, _, _ := pitServer(t)
	snap := &fakePITSnapshotter{}
	passed := false
	gate := &pitFeatureGate{available: true, t: t, during: func() { passed = true }}
	snap.atSnapshot = func(string) {
		if !passed {
			t.Error("the snapshot opened the window before the release gate passed")
		}
	}
	s.SetReleaseFeatureGate(gate)
	s.SetBackupSource(failingBackupSource{})
	s.SetPointInTimeSnapshotter(snap)
	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if !slices.Contains(snap.calls, "snapshot") || gate.pitCalls() != 1 {
		t.Fatalf("calls %v, gate %d: want one gated snapshot", snap.calls, gate.pitCalls())
	}
}

// P1: the in-place restore sets a held overlay aside only after it has placed
// the restored image. A restore that fails before (a missing chunk, a cancel)
// or a placement that fails leaves the overlay under its own name and the VM
// held.
//
// Mutations "set aside when the target is resolved" and "set aside before
// placing" — red.
func TestInPlaceRestore_AFailedRestoreLeavesTheOverlayAndTheHold(t *testing.T) {
	s, live := stoppedWithStaleOverlay(t)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	_ = healWeb(t, s) // held
	held := func() bool {
		row, found := heldCondition(t, s, "web", "root")
		return found && row.Lifecycle != "resolved"
	}
	if !held() {
		t.Fatal("setup: the VM is not held")
	}
	dest, err := s.inPlaceRestoreLocked(context.Background(), "web", "root")
	if err != nil {
		t.Fatalf("in-place restore target: %v", err)
	}
	// The restore's chunks are being written now: nothing has moved yet.
	if !pitoverlay.Present(live) || !held() {
		t.Fatal("the overlay was set aside (or the hold cleared) before the restored image was ready")
	}
	// A placement that fails (the staged file vanished) moves nothing.
	if err := dest.place(filepath.Join(filepath.Dir(live), "restore-gone.tmp")); err == nil {
		t.Fatal("placing a missing image succeeded")
	}
	if !pitoverlay.Present(live) || !pitoverlay.Bound(live) || !held() {
		t.Fatalf("after a failed placement: present %v bound %v held %v; want all three", pitoverlay.Present(live), pitoverlay.Bound(live), held())
	}
	if aside, _ := filepath.Glob(pitoverlay.Path(live) + ".orphan-*"); len(aside) != 0 {
		t.Fatalf("a set-aside copy is left: %v", aside)
	}
	// And the restore that succeeds sets it aside and clears the hold.
	if err := dest.place(stagedImage(t, live)); err != nil {
		t.Fatalf("place: %v", err)
	}
	if pitoverlay.Present(live) || held() {
		t.Fatal("after the placement the overlay is still there or the VM still held")
	}
}

// P7: a heal on a host that cannot see the disk (a shared pool not mounted
// here) does not clear a hold another host raised.
//
// Mutation "clear on any absent overlay" — red.
func TestHeal_AnUnseenDiskKeepsItsHold(t *testing.T) {
	s, _, live := pitServer(t)
	s.ReportPITOverlayHeld(context.Background(), "web", "root", "held elsewhere")
	if err := os.Remove(live); err != nil {
		t.Fatal(err)
	}
	if err := healWeb(t, s); err != nil {
		t.Fatalf("heal of an unseen disk: %v", err)
	}
	if row, found := heldCondition(t, s, "web", "root"); !found || row.Lifecycle == "resolved" {
		t.Fatalf("the hold was cleared by a host that cannot see the disk: %+v", row)
	}
}

// P8: a committed binding whose overlay was written since is not "already in
// the disk": the forced-commit refusal says both files hold writes, and that
// a discard needs --accept-torn-disk.
//
// Mutation "one refusal text for both" — red.
func TestResolvePITOverlay_ACommittedOverlayWrittenSinceIsNotCalledMerged(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	for _, f := range []func(string) error{pitoverlay.MarkCommitting, pitoverlay.MarkPivoting, pitoverlay.MarkCommitted} {
		if err := f(live); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(10 * time.Millisecond)
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x44 0 512", pitoverlay.Path(live)).CombinedOutput(); err != nil {
		t.Fatalf("write the overlay: %v %s", err, out)
	}
	_, err := s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "commit", Confirm: true, ForceCommit: true})
	msg := status.Convert(err).Message()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(msg, "--accept-torn-disk") || strings.Contains(msg, "already in the disk") {
		t.Fatalf("forced commit = %v; want refused, naming --accept-torn-disk, not calling it merged", err)
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the refused commit touched the overlay")
	}
}

// P3 through the RPC: below the feature the dry run gives the full verdict,
// and an admin's commit on a safe verdict goes through.
//
// Mutation "verdict withheld below the feature" — red.
func TestResolvePITOverlay_BelowTheFeatureTheAdminStillDecides(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetReleaseFeatureGate(&pitFeatureGate{available: false})
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	dry, err := s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root"})
	if err != nil || dry.GetVerdict() != string(pitoverlay.Matches) || !strings.Contains(dry.GetRecommendation(), "pit_overlay needs "+capabilities.ReleaseToken) {
		t.Fatalf("dry run below the feature = %+v, %v; want verdict matches and why nothing was settled", dry, err)
	}
	resp, err := s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "commit", Confirm: true})
	if err != nil || !resp.GetDone() || !holdsTheWindowsWrite(t, live) || pitoverlay.Present(live) {
		t.Fatalf("admin commit below the feature = %+v, %v", resp, err)
	}
}

// P9: a schedule whose copies stay not point-in-time notifies once, not on
// every run; each run still records its event.
//
// Mutation "notify every run" — red.
func TestNotPointInTime_NotifiesOncePerDisk(t *testing.T) {
	recordQemuImg(t)
	s, _, _ := pitServer(t)
	s.SetBackupSource(failingBackupSource{})
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{snapErr: errors.New("snapshot refused")})
	got := seenNotifications(s)
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		if err := runRepl(t, s, t0.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	n := 0
	for _, x := range *got {
		if x.Kind == "replication.not_point_in_time" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("not-point-in-time notifications = %d over three runs, want 1", n)
	}
	if evs := pitEventDetails(t, s, "web", "disk.replica_not_point_in_time"); len(evs) != 3 {
		t.Fatalf("events = %d, want one per run", len(evs))
	}
}

// m1 of the switch review: a crash between the restored image's placement and
// the overlay's set-aside leaves the VM held — the overlay is still beside
// the disk, bound to the file the restore replaced, so it is never committed
// into the restored disk and a start does not clear the hold.
//
// Mutation "set aside before placing" — red.
func TestInPlaceRestore_ACrashMidPlacementLeavesTheVMHeld(t *testing.T) {
	s, live := stoppedWithStaleOverlay(t)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	_ = healWeb(t, s) // held
	dest, err := s.inPlaceRestoreLocked(context.Background(), "web", "root")
	if err != nil {
		t.Fatalf("in-place restore target: %v", err)
	}
	type crash struct{}
	prev := restorePlaceStep
	restorePlaceStep = func(step string) {
		if step == "placed" {
			panic(crash{})
		}
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(crash); !ok {
					panic(r)
				}
			}
		}()
		_ = dest.place(stagedImage(t, live))
	}()
	restorePlaceStep = prev

	// After the restart: the restored file is in place, and the VM is held.
	if err := healWeb(t, s); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("heal after a crash mid-placement = %v; want the VM held", err)
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the overlay is gone from beside the disk")
	}
	if row, found := heldCondition(t, s, "web", "root"); !found || row.Lifecycle == "resolved" {
		t.Fatalf("the hold cleared after a crash mid-placement: %+v", row)
	}
}

// N5 of the switch re-review: a restore whose old overlay cannot be set aside
// after the placement says the VM stays held and why, not "restore complete".
//
// Mutation "a failed set-aside reports success" — red.
func TestInPlaceRestore_AFailedSetAsideSaysTheVMStaysHeld(t *testing.T) {
	s, live := stoppedWithStaleOverlay(t)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	_ = healWeb(t, s) // held
	dest, err := s.inPlaceRestoreLocked(context.Background(), "web", "root")
	if err != nil {
		t.Fatal(err)
	}
	prev := pitSetAside
	pitSetAside = func(string, string) (string, error) { return "", errors.New("EXDEV") }
	defer func() { pitSetAside = prev }()
	err = dest.place(stagedImage(t, live))
	var held *placedButHeldError
	if !errors.As(err, &held) || !strings.Contains(err.Error(), "stays held") || !strings.Contains(err.Error(), "EXDEV") {
		t.Fatalf("place with a failing set-aside = %v; want it to say the VM stays held, and why", err)
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the overlay moved")
	}
	if row, found := heldCondition(t, s, "web", "root"); !found || row.Lifecycle == "resolved" {
		t.Fatalf("the hold cleared: %+v", row)
	}
}
