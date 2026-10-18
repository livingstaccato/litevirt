package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
)

// bitmapBlock is the fake's dirty-tracking granularity.
const bitmapBlock = 4096

// bitmapSource is a backup source that models qemu's per-disk persistent
// dirty bitmaps: each checkpoint tracks one disk (path) and records every
// block written to it after the checkpoint was taken. A session from a parent
// reads that parent's dirty blocks; one with no parent reads every block that
// is not zero. A parent the fake does not have fails the session, as libvirt
// does for a checkpoint or bitmap it cannot find.
type bitmapSource struct {
	mu    sync.Mutex
	disks map[string][]byte            // path → guest-visible content
	cps   map[string]*bitmapCheckpoint // checkpoint name → its bitmap
	began map[string][]string          // path → parent of each session, in order
	fail  map[string]bool              // path → BeginBackup fails
}

type bitmapCheckpoint struct {
	path  string
	dirty map[int64]bool
}

func newBitmapSource() *bitmapSource {
	return &bitmapSource{
		disks: map[string][]byte{}, cps: map[string]*bitmapCheckpoint{},
		began: map[string][]string{}, fail: map[string]bool{},
	}
}

// write is a guest write: it changes the content and marks every checkpoint
// of the disk dirty over the blocks it touches.
func (b *bitmapSource) write(path string, off int64, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	copy(b.disks[path][off:], data)
	for blk := off / bitmapBlock; blk*bitmapBlock < off+int64(len(data)); blk++ {
		for _, cp := range b.cps {
			if cp.path == path {
				cp.dirty[blk] = true
			}
		}
	}
}

// setUntracked changes the content without marking any bitmap: what a disk
// replaced or restored behind qemu's back looks like to a bitmap that
// survived.
func (b *bitmapSource) setUntracked(path string, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.disks[path] = data
}

func (b *bitmapSource) parents(path string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.began[path]...)
}

func (b *bitmapSource) BeginBackup(domain, diskPath, parentCP, newCP string) (BackupReader, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.began[diskPath] = append(b.began[diskPath], parentCP)
	data, ok := b.disks[diskPath]
	if !ok || b.fail[diskPath] {
		return nil, fmt.Errorf("no disk with source %q in domain %s", diskPath, domain)
	}
	var extents [][2]int64
	if parentCP != "" {
		cp, ok := b.cps[parentCP]
		if !ok || cp.path != diskPath {
			return nil, fmt.Errorf("checkpoint %q not found for %s", parentCP, diskPath)
		}
		var blks []int64
		for blk := range cp.dirty {
			blks = append(blks, blk)
		}
		sort.Slice(blks, func(i, j int) bool { return blks[i] < blks[j] })
		for _, blk := range blks {
			extents = append(extents, [2]int64{blk * bitmapBlock, bitmapBlock})
		}
	} else {
		for off := int64(0); off < int64(len(data)); off += bitmapBlock {
			end := min(off+bitmapBlock, int64(len(data)))
			if !bytes.Equal(data[off:end], make([]byte, end-off)) {
				extents = append(extents, [2]int64{off, end - off})
			}
		}
	}
	if newCP != "" {
		if _, dup := b.cps[newCP]; dup {
			// libvirt refuses a checkpoint name the domain already has.
			return nil, fmt.Errorf("checkpoint %q already exists", newCP)
		}
		b.cps[newCP] = &bitmapCheckpoint{path: diskPath, dirty: map[int64]bool{}}
	}
	return &fakeBackupReader{data: append([]byte(nil), data...), extents: extents, incr: parentCP != ""}, nil
}

func (b *bitmapSource) GCCheckpoints(string, string, []string) error { return nil }

func (b *bitmapSource) DeleteCheckpoint(_, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.cps, name)
	return nil
}

// incrFixture is a running VM with a root and a data disk on this host, an
// --incremental schedule replicating into pool dr on this host, and the
// bitmap source.
type incrFixture struct {
	s     *Server
	src   *bitmapSource
	sched corrosion.BackupScheduleRecord
	paths map[string]string // disk → its file
	pool  string
}

func newIncrFixture(t *testing.T, size int) *incrFixture {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	f := libvirtfake.New()
	s.virt = f
	pool := replicaPoolDir(t, s, "dr")
	dir := t.TempDir()
	src := newBitmapSource()
	fx := &incrFixture{s: s, src: src, pool: pool, paths: map[string]string{}}
	var disks []corrosion.DiskRecord
	for i, d := range []string{"root", "data1"} {
		p := filepath.Join(dir, d+".qcow2")
		if err := os.WriteFile(p, []byte("disk file"), 0o600); err != nil {
			t.Fatal(err)
		}
		fx.paths[d] = p
		content := make([]byte, size)
		for j := range content {
			content[j] = byte(0x10 * (i + 1))
		}
		src.disks[p] = content
		disks = append(disks, corrosion.DiskRecord{VMName: "inc1", HostName: s.hostName, DiskName: d, Path: p,
			StorageType: "dir", TargetDev: fmt.Sprintf("vd%c", 'a'+i)})
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "inc1", HostName: s.hostName, State: "running", Spec: `{}`}, nil, disks); err != nil {
		t.Fatal(err)
	}
	f.SetState("inc1", libvirtfake.StateRunning)
	s.SetBackupSource(src)
	fx.sched = corrosion.BackupScheduleRecord{VMName: "inc1", Repo: "dr", Type: "replication", TargetPool: "dr",
		TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 10, Incremental: true}
	return fx
}

func (fx *incrFixture) run(t *testing.T, at string) {
	t.Helper()
	ts, err := time.Parse("20060102-150405", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.s.RunReplication(context.Background(), fx.sched, ts); err != nil {
		t.Fatalf("run %s: %v", at, err)
	}
}

// replicaOf is the bytes of disk's replica from run at.
func (fx *incrFixture) replicaOf(t *testing.T, disk, at string) ([]byte, replicaRecord) {
	t.Helper()
	recs, err := listReplicaRecords(fx.pool, "", "inc1")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Disk == disk && r.Taken == at {
			b, err := os.ReadFile(filepath.Join(replicaOwnerDir(fx.pool, "", "inc1"), r.File))
			if err != nil {
				t.Fatal(err)
			}
			return b, r
		}
	}
	t.Fatalf("no replica of %s from run %s (records %+v)", disk, at, recs)
	return nil, replicaRecord{}
}

func (fx *incrFixture) content(disk string) []byte {
	fx.src.mu.Lock()
	defer fx.src.mu.Unlock()
	return append([]byte(nil), fx.src.disks[fx.paths[disk]]...)
}

// An --incremental schedule copies a data disk through its own checkpoint
// chain: the first run reads it whole, each later run only the extents dirty
// since the run before, forked from that run's replica — and every replica is
// byte-identical to the disk at its run.
//
// Mutation "data disks full" (replicateOtherDisks never takes the incremental
// path): red — the data disk's sessions have no parent and its replica is
// qcow2.
func TestReplication_ADataDiskIsCopiedIncrementallyAndExactly(t *testing.T) {
	fx := newIncrFixture(t, 64*bitmapBlock)
	data1 := fx.paths["data1"]

	fx.run(t, "20261018-010000")
	got, rec := fx.replicaOf(t, "data1", "20261018-010000")
	if rec.Format != "raw" || !bytes.Equal(got, fx.content("data1")) {
		t.Fatalf("first run: data1 replica format %q, identical %v", rec.Format, bytes.Equal(got, fx.content("data1")))
	}

	fx.src.write(data1, 5*bitmapBlock+7, []byte("first increment"))
	fx.run(t, "20261018-020000")
	fx.src.write(data1, 40*bitmapBlock, bytes.Repeat([]byte{0xEE}, 3*bitmapBlock))
	fx.src.write(fx.paths["root"], 2*bitmapBlock, []byte("root changes too"))
	fx.run(t, "20261018-030000")

	parents := fx.src.parents(data1)
	want := []string{"", replCheckpointName("data1", "20261018-010000"), replCheckpointName("data1", "20261018-020000")}
	if fmt.Sprint(parents) != fmt.Sprint(want) {
		t.Fatalf("data1's sessions forked from %q, want %q", parents, want)
	}
	for _, disk := range []string{"data1", "root"} {
		got, rec := fx.replicaOf(t, disk, "20261018-030000")
		if rec.Format != "raw" || !bytes.Equal(got, fx.content(disk)) {
			t.Errorf("%s: the third run's replica (format %q) is not byte-identical to the disk", disk, rec.Format)
		}
	}
	// Each disk has its own chain: data1's anchor names data1's checkpoint.
	raw, _ := corrosion.GetReplicationCheckpoint(context.Background(), fx.s.db, "inc1", diskChainRepo("dr", "data1"))
	if a, ok := decodeDiskChainAnchor(raw); !ok || a.Checkpoint != replCheckpointName("data1", "20261018-030000") {
		t.Errorf("data1's anchor = %q", raw)
	}
	if root, _ := corrosion.GetReplicationCheckpoint(context.Background(), fx.s.db, "inc1", "dr"); root != replCheckpointName("root", "20261018-030000") {
		t.Errorf("the root's anchor = %q, want its own checkpoint as before", root)
	}
}

// A break in a data disk's chain is a full copy of that disk, never an
// increment over content its bitmap did not see. The bitmap here survives
// every break (the worst case); only the anchor's identity catches each one.
//
// Mutations: "no identity check" (diskChainBreak returns "") — red on the
// swap, the restore and the move; "no size check" — red on the resize.
func TestReplication_ABrokenDataDiskChainIsCopiedInFull(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, fx *incrFixture)
	}{
		{"swapped for another file", func(t *testing.T, fx *incrFixture) {
			p := fx.paths["data1"]
			other := filepath.Join(filepath.Dir(p), "data1-other.qcow2")
			if err := os.WriteFile(other, []byte("other disk"), 0o600); err != nil {
				t.Fatal(err)
			}
			// The same path, another file: a restore in place places a new file.
			if err := os.Rename(other, p); err != nil {
				t.Fatal(err)
			}
			fx.src.setUntracked(p, bytes.Repeat([]byte{0x77}, len(fx.content("data1"))))
		}},
		{"moved away and back", func(t *testing.T, fx *incrFixture) {
			if err := fx.s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = COALESCE(vm_owner_epoch, 0) + 2 WHERE name = ?`, "inc1"); err != nil {
				t.Fatal(err)
			}
			fx.src.setUntracked(fx.paths["data1"], bytes.Repeat([]byte{0x55}, len(fx.content("data1"))))
		}},
		{"resized", func(t *testing.T, fx *incrFixture) {
			grown := append(fx.content("data1"), bytes.Repeat([]byte{0x33}, 8*bitmapBlock)...)
			fx.src.setUntracked(fx.paths["data1"], grown)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newIncrFixture(t, 32*bitmapBlock)
			fx.run(t, "20261018-010000")
			tc.break_(t, fx)
			fx.run(t, "20261018-020000")
			got, _ := fx.replicaOf(t, "data1", "20261018-020000")
			if !bytes.Equal(got, fx.content("data1")) {
				t.Fatalf("after the disk was %s, its replica is not the disk: an increment over a broken chain", tc.name)
			}
			// The chain starts again from that run, and continues.
			fx.src.write(fx.paths["data1"], 3*bitmapBlock, []byte("after the break"))
			fx.run(t, "20261018-030000")
			got, _ = fx.replicaOf(t, "data1", "20261018-030000")
			if !bytes.Equal(got, fx.content("data1")) {
				t.Fatalf("the run after the break: replica is not the disk")
			}
			if p := fx.src.parents(fx.paths["data1"]); p[len(p)-1] != replCheckpointName("data1", "20261018-020000") {
				t.Errorf("the run after the break forked from %q, want the full run's checkpoint", p[len(p)-1])
			}
		})
	}
}

// A data disk whose session cannot open (the bitmap is gone, the VM stopped)
// falls back to its full point-in-time copy, resets its chain, and the run
// still succeeds with every disk copied; the root's chain is untouched.
//
// Mutation "no reset" (the fallback keeps the anchor): red — the anchor
// survives the fallback.
func TestReplication_ADataDiskSessionFailureFallsBackToAFullCopy(t *testing.T) {
	ctx := context.Background()
	fx := newIncrFixture(t, 16*bitmapBlock)
	fx.run(t, "20261018-010000")
	fx.src.mu.Lock()
	fx.src.fail[fx.paths["data1"]] = true
	fx.src.mu.Unlock()
	// The full copy is the disk's real file: give it qcow2 content to copy.
	if err := os.Remove(fx.paths["data1"]); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(fx.paths["data1"], 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	ts, _ := time.Parse("20060102-150405", "20261018-020000")
	err := fx.s.RunReplication(ctx, fx.sched, ts)
	_, rec := fx.replicaOf(t, "data1", "20261018-020000")
	if rec.Format != "qcow2" {
		t.Fatalf("the fallback wrote a %q replica (run error %v), want the full qcow2 copy", rec.Format, err)
	}
	if raw, _ := corrosion.GetReplicationCheckpoint(ctx, fx.s.db, "inc1", diskChainRepo("dr", "data1")); raw != "" {
		t.Errorf("data1's chain was not reset by the fallback: %q", raw)
	}
	if root, _ := corrosion.GetReplicationCheckpoint(ctx, fx.s.db, "inc1", "dr"); root != replCheckpointName("root", "20261018-020000") {
		t.Errorf("the root's chain = %q, want it advanced as before", root)
	}
}

func TestDiskChainRepo_NeverAPoolName(t *testing.T) {
	if err := safename.ValidatePoolName(diskChainRepo("dr", "data1")); err == nil {
		t.Fatal("a disk chain's repo key is a valid pool name: it could meet a root chain's row")
	}
}

// lastParent is the parent checkpoint of disk's newest session.
func (fx *incrFixture) lastParent(disk string) string {
	p := fx.src.parents(fx.paths[disk])
	if len(p) == 0 {
		return "<none>"
	}
	return p[len(p)-1]
}

// m-1. A base replica on this host that another host wrote is not the
// chain's base: the run is a full copy.
//
// Mutation "no source check" (chainBase ignores Source): red.
func TestReplication_ADataDiskBaseFromAnotherHostIsNotForkedFrom(t *testing.T) {
	fx := newIncrFixture(t, 16*bitmapBlock)
	fx.run(t, "20261018-010000")
	_, rec := fx.replicaOf(t, "data1", "20261018-010000")
	rec.Source = "other-host"
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(replicaOwnerDir(fx.pool, "", "inc1"), rec.File+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	fx.src.write(fx.paths["data1"], 0, []byte("changed"))
	fx.run(t, "20261018-020000")
	if p := fx.lastParent("data1"); p != "" {
		t.Fatalf("forked from %q onto a replica another host wrote", p)
	}
	if got, _ := fx.replicaOf(t, "data1", "20261018-020000"); !bytes.Equal(got, fx.content("data1")) {
		t.Fatal("replica is not the disk")
	}
}

// m-2. A VM created again under the same name is another VM: its disks'
// chains start again even where path and inode match. And a delete drops the
// per-disk rows (and the root's guard), leaving the bare root row.
//
// Mutations: "no incarnation check" — red; "no drop on delete" — red.
func TestReplication_ADataDiskChainIsTheVMIncarnations(t *testing.T) {
	ctx := context.Background()
	fx := newIncrFixture(t, 16*bitmapBlock)
	fx.run(t, "20261018-010000")
	if err := fx.s.db.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = ?`, "2030-01-01T00:00:00Z", "inc1"); err != nil {
		t.Fatal(err)
	}
	fx.run(t, "20261018-020000")
	for _, d := range []string{"data1", "root"} {
		if p := fx.lastParent(d); p != "" {
			t.Errorf("%s: a new incarnation forked from %q", d, p)
		}
	}
	fx.s.dropDiskChains(ctx, "inc1")
	for _, repo := range []string{diskChainRepo("dr", "data1"), diskChainRepo("dr", "root")} {
		if raw, _ := corrosion.GetReplicationCheckpoint(ctx, fx.s.db, "inc1", repo); raw != "" {
			t.Errorf("row %s survived the drop: %q", repo, raw)
		}
	}
	if raw, _ := corrosion.GetReplicationCheckpoint(ctx, fx.s.db, "inc1", "dr"); raw == "" {
		t.Error("the bare root row older builds read was dropped")
	}
}

// m-3. The root chain continues only when its guard row agrees with the bare
// row: an older owner, which advances the bare row alone, breaks it.
//
// Mutation "no guard" (replicateIncremental ignores rootChainGuard): red.
func TestReplication_TheRootChainNeedsItsGuard(t *testing.T) {
	ctx := context.Background()
	fx := newIncrFixture(t, 16*bitmapBlock)
	fx.run(t, "20261018-010000")
	fx.run(t, "20261018-020000")
	if p := fx.lastParent("root"); p != replCheckpointName("root", "20261018-010000") {
		t.Fatalf("fixture: the root's second run forked from %q", p)
	}
	// An older owner ran meanwhile: the bare row moved, the guard did not.
	if err := corrosion.SetReplicationCheckpoint(ctx, fx.s.db, "inc1", diskChainRepo("dr", "root"),
		anchorFor(replCheckpointName("root", "20261018-010000"), diskIdentity{host: fx.s.hostName}, 1).encode()); err != nil {
		t.Fatal(err)
	}
	fx.src.write(fx.paths["root"], 0, []byte("changed"))
	fx.run(t, "20261018-030000")
	if p := fx.lastParent("root"); p != "" {
		t.Fatalf("the root forked from %q past a guard that disagrees", p)
	}
	if got, _ := fx.replicaOf(t, "root", "20261018-030000"); !bytes.Equal(got, fx.content("root")) {
		t.Fatal("root replica is not the disk")
	}
}

// m-5. A target whose replicas cannot be listed costs a run of that disk,
// not its chain: no fallback copy, the anchor and its checkpoint are kept.
//
// Mutation "listing failure breaks the chain" (chainBase returns "", nil):
// red.
func TestReplication_AnUnlistableTargetKeepsTheDataDiskChain(t *testing.T) {
	ctx := context.Background()
	fx := newIncrFixture(t, 16*bitmapBlock)
	fx.run(t, "20261018-010000")
	before, _ := corrosion.GetReplicationCheckpoint(ctx, fx.s.db, "inc1", diskChainRepo("dr", "data1"))
	vm, _ := corrosion.GetVM(ctx, fx.s.db, "inc1")
	disks, _ := corrosion.GetVMDisks(ctx, fx.s.db, "inc1")
	var d *corrosion.DiskRecord
	for i := range disks {
		if disks[i].DiskName == "data1" {
			d = &disks[i]
		}
	}
	fullRan := false
	err := fx.s.replicateOtherDiskIncrementalOr(ctx, fx.sched, vm, d, "unreachable-host", "20261018-020000",
		func() func() { return func() {} }, func() error { fullRan = true; return nil })
	if !errors.Is(err, errChainListing) || fullRan {
		t.Fatalf("err %v, full copy ran %v; want errChainListing and no fallback", err, fullRan)
	}
	if after, _ := corrosion.GetReplicationCheckpoint(ctx, fx.s.db, "inc1", diskChainRepo("dr", "data1")); after != before {
		t.Fatalf("anchor %q → %q: the chain was touched", before, after)
	}
	fx.src.mu.Lock()
	_, kept := fx.src.cps[replCheckpointName("data1", "20261018-010000")]
	fx.src.mu.Unlock()
	if !kept {
		t.Fatal("the parent checkpoint was deleted")
	}
}
