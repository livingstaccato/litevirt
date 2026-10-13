package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// resolutionStall makes every bounded symlink resolution of a path at or
// below dir, made while it is on, block until it is turned off (or the test
// ends), as one under a hard NFS mount whose server does not answer does.
type resolutionStall struct {
	dir     string
	mu      sync.Mutex
	on      bool
	release chan struct{}
}

func (st *resolutionStall) wait(p string) {
	st.mu.Lock()
	on, ch := st.on, st.release
	st.mu.Unlock()
	if on && pathWithin(st.dir, p) {
		<-ch
	}
}

// set turns the stall on or off; off lets every call it holds return.
func (st *resolutionStall) set(on bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.on && !on {
		close(st.release)
		st.release = make(chan struct{})
	}
	st.on = on
}

// stallResolutionsUnder installs a resolutionStall of dir, on, and shortens
// the bound.
func stallResolutionsUnder(t *testing.T, dir string) *resolutionStall {
	t.Helper()
	st := &resolutionStall{dir: dir, on: true, release: make(chan struct{})}
	t.Cleanup(func() { st.set(false) })
	t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
	t.Cleanup(storage.OverrideEvalSymlinksForTest(func(p string) (string, error) {
		st.wait(p)
		return filepath.EvalSymlinks(p)
	}))
	t.Cleanup(storage.OverridePathResolverForTest(func(p string) string {
		st.wait(p)
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}))
	return st
}

// answersAgain waits until a bounded resolution of p answers: the calls a
// stall held have returned, and nothing is joined to them any more.
func answersAgain(t *testing.T, p string) {
	t.Helper()
	for range 100 {
		if _, err := storage.EvalSymlinksBounded(p); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s does not answer again", p)
}

// symlinkedDataDir is a data_dir reached through a symlink (the lab 3c
// layout behind a symlinked /var/lib/litevirt): the link, and what it names.
func symlinkedDataDir(t *testing.T) (link, real string) {
	t.Helper()
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(t.TempDir(), "litevirt")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	return link, real
}

// Re-review 3, R3-I1: a prune whose resolution of the image store does not
// answer prunes nothing. With data_dir behind a symlink, the store's files are
// named by the link and a disk's header by where they are; a resolution taken
// "as given" on no answer put the two in different forms, the old version a
// stopped VM is built on was never seen in use, and it was removed. So with
// the store not answering throughout, during the scan only, or only once the
// scan is done.
//
// Mutations: prune resolves with the lenient resolvedOr — "throughout" is
// red; the scan's resolutions lenient — "during the scan" is red; the
// removal loop's lenient — "after the scan" is red.
func TestPruneImages_AStalledResolutionPrunesNothing(t *testing.T) {
	for _, when := range []string{"throughout", "during the scan", "after the scan"} {
		t.Run(when, func(t *testing.T) { prunesNothingWhileStalled(t, when) })
	}
}

func prunesNothingWhileStalled(t *testing.T, when string) {
	s := testServerWithLocks(t)
	link, _ := symlinkedDataDir(t)
	s.dataDir = link
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatal(err)
	}
	ctx := adminCtx()
	base := filepath.Join(link, "images", "ubuntu.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(link, "disks", "web-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	insertTestVM(t, ctx, s.db, "web", s.hostName, "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "web", DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20,
		BackingImage: "ubuntu", StorageType: "local", TargetDev: "vda", Bus: "virtio",
	}); err != nil {
		t.Fatal(err)
	}
	// A refresh publishes a new version: the old one is the stopped VM's base.
	tmp := filepath.Join(link, "images", "import-refresh.tmp")
	if err := qcow2.Create(tmp, 2<<20, nil); err != nil {
		t.Fatal(err)
	}
	digest, err := image.FileDigest(tmp)
	if err != nil {
		t.Fatal(err)
	}
	s.recordImageProvenance(ctx, "ubuntu")
	if _, err := s.images.Publish("ubuntu", tmp, digest); err != nil {
		t.Fatal(err)
	}

	images := filepath.Join(link, "images")
	st := stallResolutionsUnder(t, images)
	switch when {
	case "during the scan":
		s.imagePrune.afterScan = func() { st.set(false); answersAgain(t, images) }
	case "after the scan":
		st.set(false)
		s.imagePrune.afterScan = func() { st.set(true) }
	}
	type res struct {
		removed []string
		err     error
	}
	got := within(t, 30*time.Second, "a prune while the image store does not answer", func() res {
		removed, _, err := s.pruneImageVersions(ctx, "ubuntu", false)
		return res{removed, err}
	})
	if got.err == nil || !strings.Contains(got.err.Error(), "nothing is pruned") {
		t.Fatalf("prune while the store's resolution does not answer: err %v, removed %v; want an error saying nothing is pruned", got.err, got.removed)
	}
	if len(got.removed) != 0 {
		t.Fatalf("the prune removed %v", got.removed)
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("the version the stopped VM is built on is gone: %v", err)
	}
}

// The same rule for a snapshot delete: whether another VM's disk is built on
// a file the delete would merge or remove is not answered on a guess. A
// resolution that does not answer is an error, which every caller takes as
// "in use".
//
// Mutation: snapshotFileUsers resolves with the lenient resolvedOr — no user,
// no error: red.
func TestSnapshotFileUsers_AStalledResolutionIsAnError(t *testing.T) {
	s := testServer(t)
	link, real := symlinkedDataDir(t)
	s.dataDir = real
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(real, "disks"), 0o755); err != nil {
		t.Fatal(err)
	}
	snapBase := filepath.Join(real, "disks", "a-root.qcow2")
	if err := qcow2.Create(snapBase, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(real, "disks", "b-root.qcow2")
	if err := qcow2.CreateWithBacking(clone, snapBase, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	for vm, disk := range map[string]string{"a": snapBase, "b": clone} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: vm, HostName: s.hostName, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
	}
	// The delete names the file through the link; b's header names where it is.
	viaLink := filepath.Join(link, "disks", "a-root.qcow2")
	if users, err := s.snapshotFileUsers(ctx, "a", []string{viaLink}); err != nil || len(users) != 1 {
		t.Fatalf("setup: users %v, err %v; want b", users, err)
	}
	stallResolutionsUnder(t, link)
	var users []string
	err := within(t, 10*time.Second, "who uses a file while its resolution does not answer", func() error {
		var err error
		users, err = s.snapshotFileUsers(ctx, "a", []string{viaLink})
		return err
	})
	if err == nil || !storage.IsFSNoAnswer(err) {
		t.Fatalf("who uses a file whose resolution does not answer: users %v, err %v; want the no-answer error", users, err)
	}
}

// The same when it is the other VM's chain that does not answer: its disk
// is recorded, and names its base, through the link.
//
// Mutation: a layer of another VM's chain resolved leniently — no user, no
// error: red.
func TestSnapshotFileUsers_AStalledChainIsAnError(t *testing.T) {
	s := testServer(t)
	link, real := symlinkedDataDir(t)
	s.dataDir = real
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(real, "disks"), 0o755); err != nil {
		t.Fatal(err)
	}
	snapBase := filepath.Join(real, "disks", "a-root.qcow2")
	if err := qcow2.Create(snapBase, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(link, "disks", "b-root.qcow2")
	if err := qcow2.CreateWithBacking(clone, filepath.Join(link, "disks", "a-root.qcow2"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	for vm, disk := range map[string]string{"a": snapBase, "b": clone} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: vm, HostName: s.hostName, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
	}
	if users, err := s.snapshotFileUsers(ctx, "a", []string{snapBase}); err != nil || len(users) != 1 {
		t.Fatalf("setup: users %v, err %v; want b", users, err)
	}
	stallResolutionsUnder(t, link)
	var users []string
	err := within(t, 10*time.Second, "who uses a file while another VM's chain does not answer", func() error {
		var err error
		users, err = s.snapshotFileUsers(ctx, "a", []string{snapBase})
		return err
	})
	if err == nil || !storage.IsFSNoAnswer(err) {
		t.Fatalf("who uses a file while a chain does not answer: users %v, err %v; want the no-answer error", users, err)
	}
	if snapshotFileUsersCode(err) != codes.Unavailable {
		t.Fatalf("refusal code %v, want Unavailable", snapshotFileUsersCode(err))
	}
}

// A backup's base is pinned against a prune. Whether the base is in the
// image store is not answered on a guess either: a resolution of the store
// that does not answer is an error (the backup then warns that its base is
// unpinned), never a silent "not the store's".
//
// Mutation: pinBackupBase resolves with the lenient resolvedOr — nil, and
// nothing pinned: red.
func TestPinBackupBase_AStalledResolutionIsAnError(t *testing.T) {
	s := testServer(t)
	link, real := symlinkedDataDir(t)
	s.dataDir = link
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(real, "images", "ubuntu.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	stallResolutionsUnder(t, filepath.Join(link, "images"))
	err := within(t, 10*time.Second, "a backup base pin while the store does not answer", func() error {
		return s.pinBackupBase(&pbsstore.BaseIdentity{Path: base})
	})
	if err == nil {
		t.Fatalf("a pin whose store resolution does not answer returned nil (pinned: %v)", image.Pinned(base))
	}
}

// A start's chain judgement is not made on a guess: when a resolution the
// judgement needs (here the VM's own disk) does not answer, the start is
// refused as retryable, not admitted on the path as given.
//
// Mutation: the chain judge's resolutions lenient — the start is admitted:
// red.
func TestStart_AChainJudgedOnAStalledResolutionIsRefused(t *testing.T) {
	f := newStartChainFixture(t)
	vm := f.mainEraVM(t, "web", f.pa, "pa")
	if err := qcow2.Create(filepath.Join(f.pa, "ubuntu"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	startAllowed(t, f.s, vm, "setup: the intact chain")
	stallResolutionsUnder(t, filepath.Join(f.pa, "web-root.qcow2"))
	err := within(t, 10*time.Second, "a start whose chain judgement does not answer", func() error {
		return f.s.verifyImageBasesForStart(context.Background(), vm)
	})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("a start judged on a resolution that did not answer: %v; want Unavailable saying its storage does not answer", err)
	}
}

// Re-review 3 caveat (a): a local-disk VM's start is not refused because its
// check crosses several dead mounts. Each pool directory below a dead mount
// costs one bound, but they are given up on at once, not one after another
// (where five of them outlast the start check's own bound of four).
//
// Mutation: the pool directories resolved one after another — the local VM
// is refused: red.
func TestStart_ALocalDiskVMStartsBesideSeveralDeadMounts(t *testing.T) {
	f := newStartChainFixture(t)
	lines := []string{"22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw"}
	var mnts []string
	for i := range 5 {
		mnt := t.TempDir()
		mnts = append(mnts, mnt)
		src := "nas" + string(rune('a'+i)) + ":/vm"
		lines = append(lines, nfsMountLine(mnt, src))
		if err := corrosion.UpsertStoragePool(context.Background(), f.s.db, corrosion.StoragePoolRecord{
			HostName: f.s.hostName, Name: "inner" + string(rune('a'+i)), Driver: "nfs", Source: src + "/inner",
			Target: filepath.Join(mnt, "inner"), State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	overrideMounts(t, lines...)
	deadMountSeams(t, mnts...)
	vm := f.mainEraVM(t, "web", f.pa, "pa")
	if err := qcow2.Create(filepath.Join(f.pa, "ubuntu"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	err := within(t, 20*time.Second, "a local-disk VM's start checks", func() error {
		return f.s.verifyImageBasesForStart(context.Background(), vm)
	})
	if err != nil {
		t.Fatalf("start of a local-disk VM beside five dead mounts: %v", err)
	}
}

// IsDataDirDisks is a confinement judgement: a pool on <data_dir>/disks
// holds every VM's disks, and its content is confined to what its project
// owns by record. A pool directory reached through a symlink whose
// resolution does not answer cannot be told not to be that directory, so it
// is confined.
//
// Mutation: poolDirShared takes a resolution that did not answer as "not
// <data_dir>/disks" — the pool reads as its own: red.
func TestPoolDirShared_AStalledResolutionIsShared(t *testing.T) {
	s := testServer(t)
	link, real := symlinkedDataDir(t)
	s.dataDir = real
	if err := os.MkdirAll(filepath.Join(real, "disks"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := corrosion.StoragePoolRecord{HostName: s.hostName, Name: "p", Driver: "dir", Target: filepath.Join(link, "disks")}
	if !s.poolDirShared(context.Background(), rec) {
		t.Fatal("setup: a pool on <data_dir>/disks through a link is not shared")
	}
	stallResolutionsUnder(t, link)
	shared := within(t, 10*time.Second, "whether a pool's directory is shared", func() bool {
		return s.poolDirShared(context.Background(), rec)
	})
	if !shared {
		t.Fatal("a pool directory whose resolution does not answer reads as the pool's own")
	}
	// Mutation: dirConfinedAmong takes it as not <data_dir>/disks: red.
	if !s.dirConfinedAmong(nil, "p", rec.Target) {
		t.Fatal("a pool directory whose resolution does not answer is not confined")
	}
	// Mutation: poolUploadDir takes it as not <data_dir>/disks — an upload
	// lands beside the VM disks: red.
	if got := s.poolUploadDir(rec.Target); got != filepath.Join(rec.Target, poolUploadsSubdir) {
		t.Fatalf("an upload into a pool directory whose resolution does not answer lands in %s", got)
	}
}

// A pool on <data_dir>/disks adds nothing to the pools a chain may read
// from: that directory holds every project's disks, judged file by file.
// When <data_dir>/disks does not answer its resolution, whether a pool is
// that directory cannot be told, and the pool adds nothing either — another
// project's disk there is not read through it.
//
// Mutation: chainPoolDirs resolves leniently — the pool, taken as distinct
// from the unresolved <data_dir>/disks, admits b's disk: red.
func TestStart_APoolOnAnUnansweringDataDisksAdmitsNothing(t *testing.T) {
	f := newStartChainFixture(t)
	link, real := symlinkedDataDir(t)
	f.s.dataDir = link
	disks := filepath.Join(real, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(context.Background(), f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "old-default", Driver: "dir", Target: disks, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(disks, "bvm2-root.qcow2")
	if err := qcow2.Create(theirs, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f.insertVM(t, "bvm2", "b", theirs, "", "")
	disk := filepath.Join(f.pa, "web-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, theirs, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	vm := f.insertVM(t, "web", "a", disk, "pa", "")
	startRefused(t, f.s, vm, "setup: a's disk on b's disk in <data_dir>/disks")
	stallResolutionsUnder(t, filepath.Join(link, "disks"))
	err := within(t, 10*time.Second, "a start while <data_dir>/disks does not answer", func() error {
		return f.s.verifyImageBasesForStart(context.Background(), vm)
	})
	if err == nil {
		t.Fatal("a's disk on b's disk was admitted while <data_dir>/disks did not answer")
	}
}

// Re-review 4, R4-M1: an in-place restore re-points the backed-up overlay at
// exactly the recorded base, and only its top layer is held to that; the
// layers below go by the disk's broader rule. Which layer is the top is not
// decided on a guess: when resolving the restored file does not answer, the
// restore is refused, not judged by the broader rule — which here would admit
// another image-store file than the recorded base.
//
// Mutation: the top resolved leniently (resolvedOr) — the other image is
// admitted: red.
func TestRestore_ARepointedTopThatDoesNotAnswerIsRefused(t *testing.T) {
	f := newStartChainFixture(t)
	images := filepath.Join(f.s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	recorded := filepath.Join(images, "ubuntu.qcow2")
	other := filepath.Join(images, "debian.qcow2")
	for _, p := range []string{recorded, other} {
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	recorded, _ = filepath.EvalSymlinks(recorded)
	vm := f.mainEraVM(t, "web", f.pa, "pa")
	disks, err := corrosion.GetVMDisks(context.Background(), f.s.db, vm.Name)
	if err != nil || len(disks) != 1 {
		t.Fatalf("disks %v: %v", disks, err)
	}
	staging, _ := symlinkedDataDir(t)
	restored := filepath.Join(staging, "restored.qcow2")
	if err := qcow2.CreateWithBacking(restored, other, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.s.judgeRepointedChain(context.Background(), restored, recorded, "qcow2", disks[0]); err == nil {
		t.Fatal("setup: a top naming another image than the recorded base was accepted")
	}
	stallResolutionsUnder(t, staging)
	err = within(t, 10*time.Second, "an in-place restore's chain judgement", func() error {
		return f.s.judgeRepointedChain(context.Background(), restored, recorded, "qcow2", disks[0])
	})
	if err == nil || !storage.IsFSNoAnswer(err) {
		t.Fatalf("a re-pointed top whose resolution does not answer: %v; want the no-answer refusal", err)
	}
}

// Re-review 4, R4-M2: a backing in a pool whose directory does not answer
// is refused as retryable Unavailable ("its storage does not answer"), not
// as a backing outside every pool the project may use.
//
// Mutation: chainPoolDirs does not report the no-answer — FailedPrecondition:
// red.
func TestStart_ABackingInAPoolThatDoesNotAnswerIsUnavailable(t *testing.T) {
	f := newStartChainFixture(t)
	link, real := symlinkedDataDir(t)
	if err := corrosion.UpsertStoragePool(context.Background(), f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "pl", Driver: "dir", Target: link, Project: "a", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(real, "base.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(f.pa, "web-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	vm := f.insertVM(t, "web", "a", disk, "pa", "")
	startAllowed(t, f.s, vm, "setup: a backing in a pool of the project")
	stallResolutionsUnder(t, link)
	err := within(t, 10*time.Second, "a start whose backing's pool does not answer", func() error {
		return f.s.verifyImageBasesForStart(context.Background(), vm)
	})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("a backing in a pool that does not answer: %v; want Unavailable saying its storage does not answer", err)
	}
}
