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
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// qemuArgvRecorder swaps qemuImgCommand for one that records each argv and
// then runs the real qemu-img.
type qemuArgvRecorder struct {
	mu   sync.Mutex
	argv [][]string
	cmds []*exec.Cmd
}

func recordQemuImg(t *testing.T) *qemuArgvRecorder {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not on PATH")
	}
	r := &qemuArgvRecorder{}
	prev := qemuImgCommand
	qemuImgCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, name, args...)
		r.mu.Lock()
		r.argv = append(r.argv, append([]string{name}, args...))
		r.cmds = append(r.cmds, cmd)
		r.mu.Unlock()
		return cmd
	}
	t.Cleanup(func() { qemuImgCommand = prev })
	return r
}

func (r *qemuArgvRecorder) forceShared() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.argv {
		if slices.Contains(a, "-U") {
			return true
		}
	}
	return false
}

// read reports whether any qemu-img run read path: named as its source in
// the argv, or handed to it as a source descriptor (convertImageWith passes
// the source chain, then the destination, as ExtraFiles; a file's Name is
// the path it was opened by).
func (r *qemuArgvRecorder) read(path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, a := range r.argv {
		if len(a) >= 2 && a[len(a)-2] == path {
			return true
		}
		if files := r.cmds[i].ExtraFiles; len(files) > 1 {
			for _, f := range files[:len(files)-1] {
				if f.Name() == path {
					return true
				}
			}
		}
	}
	return false
}

// countingBackupSource is fakeBackupSource counting the sessions it opens.
type countingBackupSource struct {
	fakeBackupSource
	opened int
}

func (c *countingBackupSource) BeginBackup(domain, diskPath, parentCP, newCP string) (BackupReader, error) {
	c.opened++
	return c.fakeBackupSource.BeginBackup(domain, diskPath, parentCP, newCP)
}

// guestBytes is the guest-visible content a backup session serves.
func guestBytes() []byte {
	b := make([]byte, 1<<20)
	copy(b, "point-in-time guest content")
	copy(b[600<<10:], "a later block")
	return b
}

func sessionSource() *countingBackupSource {
	data := guestBytes()
	return &countingBackupSource{fakeBackupSource: fakeBackupSource{
		full: &fakeBackupReader{data: data, extents: [][2]int64{{0, 4096}, {600 << 10, 4096}}},
	}}
}

// rawContent converts a qcow2 to raw and returns its bytes.
func rawContent(t *testing.T, qcow string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.raw")
	if b, err := exec.Command("qemu-img", "convert", "-f", "qcow2", "-O", "raw", qcow, out).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img convert %s: %v: %s", qcow, err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakePITSnapshotter models layer 2's libvirt: a snapshot creates the overlay
// file and puts the domain on it; a commit takes it off.
type fakePITSnapshotter struct {
	mu        sync.Mutex
	onOverlay map[string]bool
	snapErr   error
	// snapLeavesFile makes a failed snapshot leave the overlay file behind.
	snapLeavesFile bool
	commitErr      error
	quiesce        bool
	calls          []string
	// atSnapshot sees the disk at the instant the window opens.
	atSnapshot func(diskPath string)
	// pivotsRecorded counts the pivots recorded (beforePivot) before landing.
	pivotsRecorded int
	// commitTakes is how long a live commit runs before it is ready to pivot.
	commitTakes time.Duration
}

func (f *fakePITSnapshotter) SnapshotDiskExternal(domain, diskPath, overlay string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "snapshot")
	if f.atSnapshot != nil {
		f.atSnapshot(diskPath)
	}
	if f.snapErr != nil {
		if f.snapLeavesFile {
			_ = os.WriteFile(overlay, []byte("overlay"), 0o600)
		}
		return false, f.snapErr
	}
	if err := os.WriteFile(overlay, []byte("overlay"), 0o600); err != nil {
		return false, err
	}
	if f.onOverlay == nil {
		f.onOverlay = map[string]bool{}
	}
	f.onOverlay[overlay] = true
	return f.quiesce, nil
}

func (f *fakePITSnapshotter) CommitDiskOverlay(domain, diskPath, overlay, _ string, beforePivot func() error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "commit")
	if f.commitErr != nil {
		return f.commitErr
	}
	if f.commitTakes > 0 {
		time.Sleep(f.commitTakes)
	}
	if f.onOverlay[overlay] && beforePivot != nil {
		if err := beforePivot(); err != nil {
			return err
		}
		f.pivotsRecorded++
	}
	delete(f.onOverlay, overlay)
	return nil
}

func (f *fakePITSnapshotter) DomainRunsOnFile(domain, path string) (bool, error) {
	return f.DomainUsesFile(domain, path)
}

func (f *fakePITSnapshotter) DomainUsesFile(domain, path string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.onOverlay[path], nil
}

var _ PointInTimeSnapshotter = (*fakePITSnapshotter)(nil)

// seenNotifications records what notify was asked to send.
func seenNotifications(s *Server) *[]notify.Notification {
	var mu sync.Mutex
	var got []notify.Notification
	s.notifySeen = func(n notify.Notification) {
		mu.Lock()
		got = append(got, n)
		mu.Unlock()
	}
	return &got
}

func hasNotification(got *[]notify.Notification, kind string) bool {
	for _, n := range *got {
		if n.Kind == kind {
			return true
		}
	}
	return false
}

func pitEventTypes(t *testing.T, s *Server, vm string) []string {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, vm, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		out = append(out, e.Type)
	}
	return out
}

func replicaRecordsOf(t *testing.T, dir, vm string) []replicaRecord {
	t.Helper()
	recs, err := listReplicaRecords(dir, "", vm)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// pitServer is a server with a running VM "web" whose root disk is a real
// qcow2, and a replica pool "dr", on a host that holds the pit_overlay
// release feature.
func pitServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	// The pit_overlay release feature is open here (the release token has
	// latched); the tests of the closed gate wire their own.
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	dir := seedReplicationVM(t, s, "web", "running")
	fake := libvirtfake.New()
	fake.SetState("web", libvirtfake.StateRunning)
	s.virt = fake
	disks, err := corrosion.GetVMDisks(context.Background(), s.db, "web")
	if err != nil || len(disks) != 1 {
		t.Fatalf("disks: %v %v", disks, err)
	}
	return s, dir, disks[0].Path
}

func runRepl(t *testing.T, s *Server, at time.Time) error {
	t.Helper()
	return s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
		VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 10,
	}, at)
}

// The plain copy never forces the share. Without -U, qemu-img fails on the
// lock a running qemu holds, so a disk wrongly thought closed is refused, not
// read smeared.
//
// Mutation "convertImage forces the share": convertImage passes forceShare
// true — red.
func TestConvertImage_NeverForceShares(t *testing.T) {
	rec := recordQemuImg(t)
	src := filepath.Join(t.TempDir(), "d.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "o.qcow2")
	if err := convertImage(context.Background(), src, "qcow2", nil, dst, func(*pb.MoveVolumeProgress) error { return nil }); err != nil {
		t.Fatalf("convertImage: %v", err)
	}
	if len(rec.argv) == 0 {
		t.Fatal("qemu-img never ran")
	}
	if rec.forceShared() {
		t.Errorf("convertImage passed -U: %v", rec.argv)
	}
}

// The one -U copy left is the named last layer.
func TestConvertImageForceShare_ForcesTheShare(t *testing.T) {
	rec := recordQemuImg(t)
	src := filepath.Join(t.TempDir(), "d.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "o.qcow2")
	if err := convertImageForceShare(context.Background(), src, "qcow2", nil, dst, func(*pb.MoveVolumeProgress) error { return nil }); err != nil {
		t.Fatalf("convertImageForceShare: %v", err)
	}
	if !rec.forceShared() {
		t.Errorf("convertImageForceShare did not pass -U: %v", rec.argv)
	}
}

// Layer 1. A running VM's full replica is read through a full backup session
// (no parent, no new checkpoint), never through qemu-img on the live image,
// and the replica holds what the session served.
//
// Mutation "skip the backup session": copyVMDiskConsistent does not try
// copyViaBackupSession — red.
func TestRunReplication_RunningSourceReadsABackupSession(t *testing.T) {
	rec := recordQemuImg(t)
	s, dir, live := pitServer(t)
	src := sessionSource()
	s.SetBackupSource(src)

	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if src.opened != 1 || src.lastParentCP != "" || src.lastNewCP != "" {
		t.Errorf("sessions opened %d (parent %q, new %q), want one full session with no checkpoints", src.opened, src.lastParentCP, src.lastNewCP)
	}
	if rec.read(live) || rec.forceShared() {
		t.Errorf("qemu-img read the live image: %v", rec.argv)
	}
	recs := replicaRecordsOf(t, dir, "web")
	if len(recs) != 1 || recs[0].NotPointInTime {
		t.Fatalf("records %+v, want one point-in-time replica", recs)
	}
	got := rawContent(t, filepath.Join(replicaOwnerDir(dir, "", "web"), recs[0].File))
	if !bytes.Equal(got, guestBytes()) {
		t.Error("the replica does not hold the content the backup session served")
	}
}

// Layer 1 for ReplicateVolume on a file pool.
//
// Mutation "ReplicateVolume copies the live image": ReplicateVolume calls
// copyNoClobber (convertVMDisk) for a running VM — red.
func TestReplicateVolume_RunningSourceReadsABackupSession(t *testing.T) {
	rec := recordQemuImg(t)
	s, _, live := pitServer(t)
	src := sessionSource()
	s.SetBackupSource(src)
	copies := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"copies": {Driver: "local", Target: copies}})

	stream := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "web", DiskName: "root", TargetPool: "copies"}, stream); err != nil {
		t.Fatalf("ReplicateVolume: %v", err)
	}
	if src.opened != 1 {
		t.Errorf("backup sessions opened: %d, want 1", src.opened)
	}
	if rec.read(live) || rec.forceShared() {
		t.Errorf("qemu-img read the live image: %v", rec.argv)
	}
	done := stream.Sent[len(stream.Sent)-1]
	if !bytes.Equal(rawContent(t, done.TargetPath), guestBytes()) {
		t.Error("the copy does not hold the content the backup session served")
	}
	if strings.Contains(done.Status, "NOT point-in-time") {
		t.Errorf("a session copy reported as not point-in-time: %q", done.Status)
	}
}

// Layer 2. With no session, the disk is snapshotted, its frozen file copied
// plainly, and the overlay committed back and removed. Still point-in-time.
//
// Mutation "skip the external snapshot": copyVMDiskConsistent does not try
// copyViaExternalSnapshot — red.
func TestRunReplication_ExternalSnapshotWhenNoSession(t *testing.T) {
	rec := recordQemuImg(t)
	s, dir, live := pitServer(t)
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{quiesce: true}
	s.SetPointInTimeSnapshotter(snap)

	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if !slices.Equal(snap.calls, []string{"snapshot", "commit"}) {
		t.Errorf("snapshotter calls %v, want snapshot then commit", snap.calls)
	}
	if rec.forceShared() {
		t.Errorf("the frozen disk was read with -U: %v", rec.argv)
	}
	if !rec.read(live) {
		t.Errorf("the frozen disk file was not the copy's source: %v", rec.argv)
	}
	if _, err := os.Stat(pitOverlayPath(live)); !os.IsNotExist(err) {
		t.Errorf("the committed overlay is still there (%v)", err)
	}
	recs := replicaRecordsOf(t, dir, "web")
	if len(recs) != 1 || recs[0].NotPointInTime {
		t.Fatalf("records %+v, want one point-in-time replica", recs)
	}
}

// A snapshot that fails and leaves a file at the overlay's name (libvirt's
// atomic snapshot should not) never has that file committed or dropped: it
// cannot be verified, so the VM is held on it — loudly — and the copy itself
// still gets made by the next layer.
//
// Mutation "no settle after a failed snapshot": copyViaExternalSnapshot
// returns without healPITOverlay — red (no hold reported).
func TestRunReplication_AFailedSnapshotsLeftoverHoldsTheVM(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetBackupSource(failingBackupSource{})
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{snapErr: errors.New("snapshot refused"), snapLeavesFile: true})

	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if _, err := os.Stat(pitOverlayPath(live)); err != nil {
		t.Errorf("the leftover file was moved or removed (%v)", err)
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), vmEventPITOverlayHeld) {
		t.Errorf("no hold reported: %v", pitEventTypes(t, s, "web"))
	}
}

// A commit that fails never leaves the VM on an overlay silently: an event and
// a notification say so, the overlay (the guest's writes) is kept, and the
// next copy of the disk commits it before anything else.
//
// Mutation "silent stranded overlay": commitPITOverlay does not record the
// event — red. Mutation "no heal": copyVMDiskConsistent skips healPITOverlay —
// red.
func TestRunReplication_FailedCommitIsReportedAndHealedNextRun(t *testing.T) {
	recordQemuImg(t)
	s, dir, live := pitServer(t)
	seen := seenNotifications(s)
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{commitErr: errors.New("block job failed")}
	s.SetPointInTimeSnapshotter(snap)

	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	if err := runRepl(t, s, t0); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), "disk.pit_overlay_stranded") {
		t.Errorf("no stranded-overlay event: %v", pitEventTypes(t, s, "web"))
	}
	if !hasNotification(seen, "replication.pit_overlay_stranded") {
		t.Error("no stranded-overlay notification")
	}
	if _, err := os.Stat(pitOverlayPath(live)); err != nil {
		t.Fatalf("the overlay the VM runs on was removed: %v", err)
	}
	if recs := replicaRecordsOf(t, dir, "web"); len(recs) != 1 || recs[0].NotPointInTime {
		t.Errorf("records %+v: the copy of the frozen disk is a good point-in-time replica", recs)
	}

	snap.commitErr = nil
	snap.calls = nil
	if err := runRepl(t, s, t0.Add(time.Hour)); err != nil {
		t.Fatalf("second RunReplication: %v", err)
	}
	if len(snap.calls) < 1 || snap.calls[0] != "commit" {
		t.Errorf("the next run did not commit the stranded overlay first: %v", snap.calls)
	}
	if _, err := os.Stat(pitOverlayPath(live)); !os.IsNotExist(err) {
		t.Errorf("the healed overlay is still there (%v)", err)
	}
}

// Layer 3. When nothing point-in-time can be made, main's -U copy is still
// made — nothing main allowed is refused — and it is recorded and reported as
// not point-in-time.
//
// Mutation "unmarked -U replica": replicateLocalCopy does not set
// NotPointInTime — red. Mutation "silent -U replica": no
// reportNotPointInTime — red.
func TestRunReplication_LastLayerIsMarkedNotPointInTime(t *testing.T) {
	rec := recordQemuImg(t)
	s, dir, _ := pitServer(t)
	seen := seenNotifications(s)
	s.SetBackupSource(failingBackupSource{})

	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication refused the copy main made: %v", err)
	}
	if !rec.forceShared() {
		t.Errorf("the last layer did not take main's -U copy: %v", rec.argv)
	}
	recs := replicaRecordsOf(t, dir, "web")
	if len(recs) != 1 || !recs[0].NotPointInTime {
		t.Fatalf("records %+v, want one replica marked not point-in-time", recs)
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), "disk.replica_not_point_in_time") {
		t.Errorf("no not-point-in-time event: %v", pitEventTypes(t, s, "web"))
	}
	if !hasNotification(seen, "replication.not_point_in_time") {
		t.Error("no not-point-in-time notification")
	}
}

// After a -U copy the next scheduler tick retries — point-in-time only: a
// retry that still cannot make one produces nothing (the -U replica from a
// minute ago stands) instead of copying the whole disk again. A cron run is
// not a retry: it still makes main's copy when nothing better can be made.
//
// Mutation "no retry": a layer-3 copy does not set pitRetry — red. Mutation
// "retry takes -U": RunReplication allows force-share on a retry — red.
func TestRunReplication_NotPointInTimeIsRetriedPointInTimeOnly(t *testing.T) {
	recordQemuImg(t)
	s, dir, _ := pitServer(t)
	s.SetBackupSource(failingBackupSource{})
	sched := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 10}

	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	if err := s.RunReplication(context.Background(), sched, t0); err != nil {
		t.Fatal(err)
	}
	if !s.PointInTimeRetryDue(sched) {
		t.Fatal("a not-point-in-time copy did not ask for a retry")
	}
	retry := scheduler.WithPointInTimeRetry(context.Background())
	err := s.RunReplication(retry, sched, t0.Add(time.Minute))
	if !errors.Is(err, errNoPointInTimeCopy) {
		t.Errorf("retry returned %v, want errNoPointInTimeCopy", err)
	}
	if n := len(replicaRecordsOf(t, dir, "web")); n != 1 {
		t.Errorf("%d replicas after the retry, want the one -U replica only", n)
	}
	if s.PointInTimeRetryDue(sched) {
		t.Error("a failed retry asked for another; the schedule's cron runs next")
	}

	// A retry that can make a point-in-time copy does.
	if err := s.RunReplication(context.Background(), sched, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err) // cron run: -U again, retry owed again
	}
	s.SetBackupSource(sessionSource())
	if err := s.RunReplication(retry, sched, t0.Add(3*time.Minute)); err != nil {
		t.Fatalf("retry with a session: %v", err)
	}
	recs := replicaRecordsOf(t, dir, "web")
	if len(recs) != 3 || recs[2].NotPointInTime {
		t.Errorf("records %+v, want the retry's replica point-in-time", recs)
	}
}

// A paused domain still holds its image: MoveVolume of one takes the live
// mover, not the offline copy. "stopped" in the store folds paused in.
//
// Mutation "only running is live": the live branch tests vm.State ==
// "running" again — red.
func TestMoveVolume_PausedSourceTakesTheLiveMover(t *testing.T) {
	s, _, dstDir := liveMoveTestServer(t, 4096)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'vm-live'`); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm-live", libvirtfake.StatePaused)
	s.virt = fake
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)
	prev := LiveMoverPollInterval
	LiveMoverPollInterval = 5 * time.Millisecond
	defer func() { LiveMoverPollInterval = prev }()

	_ = s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
	if mover.startCalls != 1 {
		t.Errorf("block copies started: %d; a paused VM's disk was not moved by the live mover", mover.startCalls)
	}
	_ = dstDir
}

// A genuinely shut-off VM still takes the offline copy.
func TestMoveVolume_ShutOffSourceTakesTheOfflineCopy(t *testing.T) {
	s, _, _ := liveMoveTestServer(t, 4096)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'vm-live'`); err != nil {
		t.Fatal(err)
	}
	mover := &fakeLiveMover{jobEnd: 4096}
	s.SetLiveMover(mover)
	_ = s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
	if mover.startCalls != 0 {
		t.Errorf("a stopped VM with no libvirt went to the live mover")
	}
}
