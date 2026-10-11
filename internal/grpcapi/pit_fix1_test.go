package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// windowOverlay puts a real overlay beside disk holding a write (0x5a over
// 64 KiB at 64 KiB) the disk lacks: what a layer-2 window leaves when its
// commit fails or its daemon dies.
func windowOverlay(t *testing.T, disk string) {
	t.Helper()
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not on PATH")
	}
	if err := qcow2.CreateWithBackingFormat(pitoverlay.Path(disk), disk, "qcow2", 0, nil); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x5a 65536 65536", pitoverlay.Path(disk)).CombinedOutput(); err != nil {
		t.Fatalf("write into the overlay: %v %s", err, out)
	}
	if err := pitoverlay.Bind(disk, pitoverlay.Owner{VM: "web", Disk: "root"}); err != nil {
		t.Fatal(err)
	}
}

func holdsTheWindowsWrite(t *testing.T, qcow string) bool {
	t.Helper()
	got := rawContent(t, qcow)
	return len(got) >= 131072 && bytes.Equal(got[65536:131072], bytes.Repeat([]byte{0x5a}, 65536))
}

// C1: an overlay on a domain that is not running is committed into the disk
// — offline, no -U — before the disk is copied, and only then removed. The
// window's write is in the disk and in the replica.
//
// Mutation "heal deletes": the inactive branch removes the overlay without
// CommitOffline — red.
func TestHeal_InactiveDomainCommitsTheOverlayNeverDeletesIt(t *testing.T) {
	recordQemuImg(t)
	s, dir, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)

	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if pitoverlay.Present(live) {
		t.Error("the committed overlay is still there")
	}
	if !holdsTheWindowsWrite(t, live) {
		t.Fatal("the window's write is not in the disk: the overlay was dropped, not committed")
	}
	recs := replicaRecordsOf(t, dir, "web")
	if len(recs) != 1 || !holdsTheWindowsWrite(t, filepath.Join(replicaOwnerDir(dir, "", "web"), recs[0].File)) {
		t.Errorf("the replica %+v misses the window's write", recs)
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), "disk.pit_overlay_committed") {
		t.Errorf("no commit event: %v", pitEventTypes(t, s, "web"))
	}
}

// C1, round 3: an overlay found while the running VM uses its disk directly
// (it moved on without it) cannot be verified: it is neither committed (that
// could overwrite newer data) nor dropped (it may hold writes). The VM is
// held — the copy refused with the admin command — and the overlay is left
// exactly as it is.
//
// Mutation "unverified overlay dropped": the hold becomes a removal of the
// overlay — red.
func TestHeal_ActiveDomainOnItsDiskIsHeld(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{})
	s.SetBackupSource(sessionSource())
	windowOverlay(t, live)
	before, _ := os.ReadFile(pitoverlay.Path(live))

	err := runRepl(t, s, time.Now())
	if err == nil || !strings.Contains(err.Error(), "lv resolve-pit-overlay web root") {
		t.Fatalf("RunReplication = %v, want refused naming the admin command", err)
	}
	if after, _ := os.ReadFile(pitoverlay.Path(live)); !bytes.Equal(after, before) {
		t.Error("the held overlay changed or went")
	}
	if holdsTheWindowsWrite(t, live) {
		t.Error("an unverified overlay was committed over the disk the VM runs on")
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), vmEventPITOverlayHeld) {
		t.Errorf("no hold event: %v", pitEventTypes(t, s, "web"))
	}
}

// I1: libvirt decides "definitely shut off". A VM the store has in "error"
// whose domain is shut off is copied plainly, as main did — no session, no
// snapshot, no mark.
//
// Mutation "the store decides": sourceClosedForPlainCopy tests vm.State ==
// "stopped" with libvirt present — red.
func TestCopy_AShutOffDomainInAnErrorStateIsCopiedPlainly(t *testing.T) {
	rec := recordQemuImg(t)
	s, dir, _ := pitServer(t)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'error' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	src := sessionSource()
	s.SetBackupSource(src)
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)

	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if src.opened != 0 || len(snap.calls) != 0 || rec.forceShared() {
		t.Errorf("sessions %d, snapshot calls %v, -U %v: a shut-off disk was not copied plainly", src.opened, snap.calls, rec.forceShared())
	}
	if recs := replicaRecordsOf(t, dir, "web"); len(recs) != 1 || recs[0].NotPointInTime {
		t.Errorf("records %+v, want one plain point-in-time replica", recs)
	}
}

// I1: layer 2 never snapshots a domain that is not running or paused —
// libvirt would snapshot it offline and strand the disk.
//
// Mutation "snapshot any domain": copyViaExternalSnapshot skips domainActive —
// red.
func TestCopy_NoLiveSnapshotOfADomainThatIsNotActive(t *testing.T) {
	recordQemuImg(t)
	s, _, _ := pitServer(t)
	s.virt = libvirtfake.New() // the store says running; libvirt has no such domain
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)

	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if len(snap.calls) != 0 {
		t.Errorf("snapshotter calls %v on a domain that is not active", snap.calls)
	}
}

// I2: MoveVolume of a VM in "error" whose domain is shut off takes the offline
// copy, as main did, not the live mover (which cannot copy an inactive
// domain).
//
// Mutation "the store decides" (as above) — red.
func TestMoveVolume_AnErrorStateShutOffVMMovesOffline(t *testing.T) {
	s, _, _ := liveMoveTestServer(t, 4096)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'error' WHERE name = 'vm-live'`); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm-live", libvirtfake.StateShutdown)
	s.virt = fake
	mover := &fakeLiveMover{jobEnd: 4096}
	s.SetLiveMover(mover)
	_ = s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
	if mover.startCalls != 0 {
		t.Error("a shut-off VM went to the live mover")
	}
}

// I4: at start-up the daemon settles a window a dead daemon left: the
// overlay's writes reach the disk, with an event, before anything else runs.
//
// Mutation "no sweep": SweepPITOverlays returns at once — red.
func TestSweepPITOverlays_SettlesAWindowADeadDaemonLeft(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)

	s.SweepPITOverlays(context.Background(), func() (bool, string) { return true, "" })
	if pitoverlay.Present(live) || !holdsTheWindowsWrite(t, live) {
		t.Fatal("the sweep did not commit the overlay into the disk")
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), "disk.pit_overlay_committed") {
		t.Errorf("no event: %v", pitEventTypes(t, s, "web"))
	}
}

// I8: an automated promotion relayed here by a coordinator that does not know
// the mark (a main build, mid-upgrade) is refused AND held loudly — event and
// notification — not refused silently.
//
// Mutation "silent relayed refusal": the req.Proof branch is removed — red.
func TestPromote_ARelayedAutomatedPromotionOfAMarkedReplicaIsHeldLoudly(t *testing.T) {
	s := testServer(t)
	seen := seenNotifications(s)
	dir := pitPromoteVM(t, s, "db-8", `{}`)
	file := seedMarkedReplica(t, dir, "db-8", "root", stamp(10*time.Minute))
	vm, _ := corrosion.GetVM(context.Background(), s.db, "db-8")

	err := s.promoteResolved(context.Background(), &pb.PromoteReplicaRequest{
		VmName: "db-8", Force: true, TargetPool: "dr", TargetHost: s.hostName, Replica: file,
		Proof: &pb.RuntimeActionProof{Id: "p1"},
	}, vm, false, func(*pb.PromoteReplicaProgress) error { return nil })
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("relayed promotion = %v, want FailedPrecondition", err)
	}
	if !slices.Contains(pitEventTypes(t, s, "db-8"), vmEventFailoverHeld) || !hasNotification(seen, "replication.promote_held") {
		t.Errorf("the relayed refusal was silent: events %v", pitEventTypes(t, s, "db-8"))
	}
}

// I9: a replicate-volume copy made with -U is recorded as not point-in-time,
// and promoting it by name needs the accept flag.
//
// Mutation "copy unmarked": ReplicateVolume records the copy with
// notPointInTime false — red.
func TestReplicateVolume_ANotPointInTimeCopyNeedsTheFlagByName(t *testing.T) {
	recordQemuImg(t)
	s, _, _ := pitServer(t)
	s.SetBackupSource(failingBackupSource{})
	copies := replicaPoolDir(t, s, "copies")

	stream := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "web", DiskName: "root", TargetPool: "copies"}, stream); err != nil {
		t.Fatalf("ReplicateVolume: %v", err)
	}
	done := stream.Sent[len(stream.Sent)-1]
	if !strings.Contains(done.Status, "NOT point-in-time") {
		t.Fatalf("the -U copy was not reported: %q", done.Status)
	}
	name := filepath.Base(done.TargetPath)
	if filepath.Dir(done.TargetPath) != copies || !s.poolCopyNotPIT(context.Background(), "copies", name) {
		t.Fatalf("the copy %s is not recorded as not point-in-time", done.TargetPath)
	}
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	err := s.promoteResolved(adminCtx(), &pb.PromoteReplicaRequest{
		VmName: "web", NewName: "web-dr", Force: true, TargetPool: "copies", TargetHost: s.hostName, Replica: name,
	}, vm, false, func(*pb.PromoteReplicaProgress) error { return nil })
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--accept-not-point-in-time") {
		t.Errorf("promote by name without the flag = %v, want refused naming the flag", err)
	}
}

// M1: a run that fails before its copy keeps the point-in-time retry owed.
//
// Mutation "early failure drops the retry": RunReplication's deferred
// re-set is removed — red.
func TestRunReplication_AnEarlyFailureKeepsTheRetryOwed(t *testing.T) {
	s, _, _ := pitServer(t)
	// A pool the run resolves (so it gets as far as the copy) whose
	// directory cannot exist: its parent is a regular file.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "broken", Driver: "dir", Target: filepath.Join(blocker, "pool"), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	sched := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr", Type: "replication", TargetPool: "broken", KeepReplicas: 1}
	s.pitRetry.set(pitRetryKey(sched))
	if err := s.RunReplication(context.Background(), sched, time.Now()); err == nil {
		t.Fatal("a run into a pool that cannot exist succeeded")
	}
	if !s.PointInTimeRetryDue(sched) {
		t.Error("the owed retry was dropped by a run that never copied")
	}
}

// M7: when every point-in-time replica is too old and a newer one is not
// point-in-time, automatic promotion says the VM is held (not merely that a
// replica is stale), so the coordinator holds it instead of rescheduling.
//
// Mutation "stale hides the hold": the age-refusal branch's hold is
// removed — red.
func TestAutoPromote_StalePointInTimeReplicasAndANewerMarkedOneHold(t *testing.T) {
	s := testServer(t)
	dir := pitPromoteVM(t, s, "db-9", `{}`)
	seedReplica(t, dir, "", "db-9", "root", stamp(5*24*time.Hour), "qcow2", 7)
	seedMarkedReplica(t, dir, "db-9", "root", stamp(10*time.Minute))

	err := s.AutoPromoteReplica(context.Background(), "db-9", "", 0)
	if !errors.Is(err, errReplicaTooOld) || !errors.Is(err, corrosion.ErrPromoteHeld) {
		t.Fatalf("AutoPromoteReplica = %v, want too-old AND held", err)
	}
	if !slices.Contains(pitEventTypes(t, s, "db-9"), vmEventFailoverHeld) {
		t.Errorf("no held event: %v", pitEventTypes(t, s, "db-9"))
	}
}
