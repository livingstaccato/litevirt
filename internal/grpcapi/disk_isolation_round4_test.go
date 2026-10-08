package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 4 of the disk-isolation review (diskiso-rereview-3.md): chains are
// judged per layer by records and by the pools the VM's project may use
// (IMP-1, IMP-2), image-store layers must be standalone (IMP-3), and the
// C-1/I-3 test gaps.

// filledQcow2 writes a 1 MiB qcow2 at path whose guest content is fill,
// repeated, and returns that content.
func filledQcow2(t *testing.T, path, fill string) []byte {
	t.Helper()
	needQemuImg(t)
	raw := bytes.Repeat([]byte(fill), 1<<20/len(fill)+1)[:1<<20]
	src := filepath.Join(t.TempDir(), "fill.raw")
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "convert", "-q", "-f", "raw", "-O", "qcow2", src, path)
	return raw
}

// registerPool records pool name (a file-based driver) on s's host and in its
// in-memory pool map.
func registerPool(t *testing.T, s *Server, name, driver, source, dir, project string) {
	t.Helper()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: driver, Source: source, Target: dir, Project: project, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.addStoragePoolRef(name, StoragePoolRef{Driver: driver, Source: source, Target: dir})
}

// nfsTemplateClone is project a's template "tpl", its root disk in NFS pool
// "shared", and "web", the clone CloneVM makes of it by default — linked,
// its overlay in <data_dir>/disks, recording no pool and the template's disk
// as its backing_disk. A dir pool "fast" is the copies' target.
func nfsTemplateClone(t *testing.T) (s *Server, web corrosion.DiskRecord, want []byte) {
	t.Helper()
	needQemuImg(t)
	s, _ = provableCreateServer(t)
	shared, fast := t.TempDir(), t.TempDir()
	registerPool(t, s, "shared", "nfs", "nas:/export", shared, "a")
	registerPool(t, s, "fast", "dir", "", fast, "")
	tplPath := filepath.Join(shared, "tpl-root.qcow2")
	want = filledQcow2(t, tplPath, "TEMPLATE ")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256, Project: "a"})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "tpl", HostName: s.hostName, State: "stopped", Project: "a", IsTemplate: true, Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: s.hostName, Path: tplPath,
			SizeBytes: 1 << 20, StorageType: "nfs", StorageVolume: "shared"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "web"}); err != nil {
		t.Fatalf("default clone of an NFS template: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
	if len(disks) != 1 || disks[0].BackingDisk != tplPath || !strings.HasPrefix(disks[0].Path, filepath.Join(s.dataDir, "disks")) {
		t.Fatalf("fixture: the clone is not a linked clone in <data_dir>/disks on the template: %+v", disks)
	}
	return s, disks[0], want
}

// IMP-1: offline move of the default clone of an NFS template.
func TestMoveVolume_LinkedCloneOfAnNFSTemplate(t *testing.T) {
	s, _, want := nfsTemplateClone(t)
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "web", DiskName: "root", TargetPool: "fast"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("MoveVolume of a linked clone of an NFS template: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
	if got := guestView(t, disks[0].Path); !bytes.Equal(got, want) {
		t.Error("the moved disk does not hold the clone's guest view")
	}
}

// IMP-1: ReplicateVolume of it.
func TestReplicateVolume_LinkedCloneOfAnNFSTemplate(t *testing.T) {
	s, _, want := nfsTemplateClone(t)
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "web", DiskName: "root", TargetPool: "fast"}, rec); err != nil {
		t.Fatalf("ReplicateVolume of a linked clone of an NFS template: %v", err)
	}
	if got := guestView(t, rec.Sent[len(rec.Sent)-1].TargetPath); !bytes.Equal(got, want) {
		t.Error("the copy does not hold the clone's guest view")
	}
}

// IMP-1: a scheduled replica of it.
func TestRunReplication_LinkedCloneOfAnNFSTemplate(t *testing.T) {
	s, _, want := nfsTemplateClone(t)
	if err := s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
		VMName: "web", Repo: "fast", Type: "replication", TargetPool: "fast", KeepReplicas: 2,
	}, time.Date(2026, 10, 13, 2, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RunReplication of a linked clone of an NFS template: %v", err)
	}
	fast := s.mustPoolDir(t, "fast")
	recs, _ := listReplicaRecords(fast, "a", "web")
	if len(recs) != 1 {
		t.Fatalf("records of web = %+v", recs)
	}
	if got := guestView(t, filepath.Join(replicaOwnerDir(fast, "a", "web"), recs[0].File)); !bytes.Equal(got, want) {
		t.Error("the replica does not hold the clone's guest view")
	}
}

func (s *Server) mustPoolDir(t *testing.T, name string) string {
	t.Helper()
	ref, ok := s.resolvePool(context.Background(), name)
	if !ok {
		t.Fatalf("pool %q", name)
	}
	dir, err := fileBasedPoolDir(s.dataDir, ref)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// IMP-1: the cold-migration flatten of it.
func TestColdMigrationFlatten_LinkedCloneOfAnNFSTemplate(t *testing.T) {
	s, web, want := nfsTemplateClone(t)
	if got := coldFlatten(t, s, web); !bytes.Equal(got, want) {
		t.Error("the flattened copy does not hold the clone's guest view")
	}
}

// coldFlatten runs a cold migration's source side on d — the check, then the
// flatten — and returns the flat copy's guest view.
func coldFlatten(t *testing.T, s *Server, d corrosion.DiskRecord) []byte {
	t.Helper()
	info, err := s.coldDiskSourceCheck(d, "qcow2")
	if err != nil {
		t.Fatalf("cold-migration check: %v", err)
	}
	if info == nil {
		t.Fatal("fixture: the disk is not an overlay")
	}
	flat := filepath.Join(t.TempDir(), "flat.qcow2")
	if err := s.flattenColdDisk(context.Background(), d, s.hostDiskFile(d.Path), flat); err != nil {
		t.Fatalf("cold-migration flatten: %v", err)
	}
	if err := qcow2.AssertStandalone(flat); err != nil {
		t.Fatalf("the flat copy is not standalone: %v", err)
	}
	return guestView(t, flat)
}

// IMP-1: a full clone of it.
func TestCloneVM_FullCloneOfALinkedCloneOfAnNFSTemplate(t *testing.T) {
	s, _, want := nfsTemplateClone(t)
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "web", Target: "web2", Mode: "full"}); err != nil {
		t.Fatalf("full clone of a linked clone of an NFS template: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web2")
	if got := guestView(t, disks[0].Path); !bytes.Equal(got, want) {
		t.Error("the full clone does not hold the guest view")
	}
}

// IMP-1: BuildImage from it.
func TestBuildImage_FromALinkedCloneOfAnNFSTemplate(t *testing.T) {
	s, _, want := nfsTemplateClone(t)
	if _, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "web", ImageName: "golden"}); err != nil {
		t.Fatalf("BuildImage from a linked clone of an NFS template: %v", err)
	}
	if got := guestView(t, s.images.ImagePath("golden")); !bytes.Equal(got, want) {
		t.Error("the image does not hold the guest view")
	}
}

// IMP-1: in-place restore of a linked clone whose template is in an NFS pool.
func TestRestoreInPlace_LinkedCloneOfAnNFSTemplate(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	shared := t.TempDir()
	registerPool(t, f.s, "shared", "nfs", "nas:/export", shared, "a")
	tplPath := filepath.Join(shared, "tpl-root.qcow2")
	base := filledQcow2(t, tplPath, "TEMPLATE ")
	templateRow(t, f, "tpl", tplPath)
	disk := filepath.Join(f.s.dataDir, "disks", "lc-root.qcow2")
	want := append(bytes.Repeat([]byte("DELTA"), 65536/5+1)[:65536], base[65536:]...)
	overlayWithData(t, disk, tplPath, "qcow2", want)
	backedVM(t, f, "lc", disk, corrosion.DiskRecord{StorageType: "nfs", BackingDisk: tplPath})
	const ts = "2026-10-10T10:00:00Z"
	pushVM(t, f, "lc", disk, ts, pbsstore.ContentDiskFile, "")
	if err := inPlace(f, "lc", ts); err != nil {
		t.Fatalf("in-place restore of a linked clone of an NFS template: %v", err)
	}
	requireRestoredOnto(t, disk, tplPath, want)
}

// IMP-1, red: a layer in a pool another project owns, that no record ties to
// the layer naming it, is still refused — by move, replicate and the flatten.
func TestDiskChain_ALayerInAnotherProjectsPoolIsRefused(t *testing.T) {
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	bpool, apool := t.TempDir(), t.TempDir()
	registerPool(t, s, "bpool", "dir", "", bpool, "b")
	registerPool(t, s, "fast", "dir", "", apool, "a")
	victim := filepath.Join(bpool, "db-root.qcow2")
	filledQcow2(t, victim, "PROJECT-B ")
	disk := filepath.Join(s.dataDir, "disks", "x-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(disk), 0o755); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", victim, "-F", "qcow2", disk)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "x", Project: "a"})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "x", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "x", DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "x", DiskName: "root", TargetPool: "fast"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "outside") {
		t.Errorf("move of a disk on another project's pool file: got %v, want FailedPrecondition naming it outside", err)
	}
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "x", DiskName: "root", TargetPool: "fast"}, rec); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("replicate of a disk on another project's pool file: got %v, want FailedPrecondition", err)
	}
	d := corrosion.DiskRecord{VMName: "x", DiskName: "root", Path: disk}
	if _, err := s.coldDiskSourceCheck(d, "qcow2"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("cold-migration flatten of it: got %v, want FailedPrecondition", err)
	}
}

// IMP-1: the pools a chain may read from without a record are the project's
// and the global ones, never another project's.
func TestDiskChainRule_PoolsAreTheProjectsAndTheGlobalOnes(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	own, global, other := t.TempDir(), t.TempDir(), t.TempDir()
	registerPool(t, s, "own", "dir", "", own, "a")
	registerPool(t, s, "global", "dir", "", global, "")
	registerPool(t, s, "other", "dir", "", other, "b")
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "x", HostName: s.hostName, State: "stopped", Project: "a"}, nil,
		[]corrosion.DiskRecord{{VMName: "x", DiskName: "root", HostName: s.hostName, Path: filepath.Join(s.dataDir, "disks", "x-root.qcow2")}}); err != nil {
		t.Fatal(err)
	}
	rule := s.diskChainRule(context.Background(), corrosion.DiskRecord{VMName: "x", DiskName: "root", Path: filepath.Join(s.dataDir, "disks", "x-root.qcow2")})
	layer := filepath.Join(s.dataDir, "disks", "x-root.qcow2")
	for _, tc := range []struct {
		dir  string
		want bool
	}{{own, true}, {global, true}, {other, false}} {
		f := filepath.Join(tc.dir, "base.qcow2")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := rule(layer, resolvedOr(f), "qcow2")
		if (err == nil) != tc.want {
			t.Errorf("layer in %s: got %v, want accepted=%v", tc.dir, err, tc.want)
		}
		// A raw layer is accepted only through a record, never by place.
		if err := rule(layer, resolvedOr(f), "raw"); err == nil {
			t.Errorf("an unrecorded raw layer in %s was accepted", tc.dir)
		}
	}
}

// IMP-1: in <data_dir>/disks, a layer is accepted only as a file the VM's
// project owns by record; another project's disk there is refused.
func TestDiskChainRule_DataDisksIsJudgedFileByFile(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	mine, theirs, nobody := filepath.Join(disks, "tpla-root.qcow2"), filepath.Join(disks, "db-root.qcow2"), filepath.Join(disks, "loose.qcow2")
	for _, p := range []string{mine, theirs, nobody} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []struct{ name, project, path string }{{"tpla", "a", mine}, {"db", "b", theirs}, {"x", "a", filepath.Join(disks, "x-root.qcow2")}} {
		if err := corrosion.InsertVM(context.Background(), s.db,
			corrosion.VMRecord{Name: v.name, HostName: s.hostName, State: "stopped", Project: v.project}, nil,
			[]corrosion.DiskRecord{{VMName: v.name, DiskName: "root", HostName: s.hostName, Path: v.path}}); err != nil {
			t.Fatal(err)
		}
	}
	layer := filepath.Join(disks, "x-root.qcow2")
	rule := s.diskChainRule(context.Background(), corrosion.DiskRecord{VMName: "x", DiskName: "root", Path: layer})
	if err := rule(layer, resolvedOr(mine), "qcow2"); err != nil {
		t.Errorf("a disk of the VM's own project: %v", err)
	}
	if err := rule(layer, resolvedOr(theirs), "qcow2"); err == nil {
		t.Error("another project's disk in <data_dir>/disks was accepted")
	}
	if err := rule(layer, resolvedOr(nobody), "qcow2"); err == nil {
		t.Error("an unrecorded file in <data_dir>/disks was accepted")
	}
}

// An external disk-only snapshot leaves the VM's record on the overlay
// (<disk>.<snap>) and its base, the old file, with no row. The VM's own
// replication still reads through it.
func TestReplicateVolume_ThroughASnapshotOverlay(t *testing.T) {
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	fast := t.TempDir()
	registerPool(t, s, "fast", "dir", "", fast, "")
	disks := filepath.Join(s.dataDir, "disks")
	base := filepath.Join(disks, "sv-root.qcow2")
	want := filledQcow2(t, base, "SNAPBASE ")
	overlay := filepath.Join(disks, "sv-root.snap1")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", overlay)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "sv", Project: "a"})
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "sv", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "sv", DiskName: "root", HostName: s.hostName, Path: overlay, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{VMName: "sv", HostName: s.hostName, Name: "snap1", State: "ok", Type: "disk"}); err != nil {
		t.Fatal(err)
	}
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "sv", DiskName: "root", TargetPool: "fast"}, rec); err != nil {
		t.Fatalf("ReplicateVolume through a snapshot overlay: %v", err)
	}
	if got := guestView(t, rec.Sent[len(rec.Sent)-1].TargetPath); !bytes.Equal(got, want) {
		t.Error("the copy does not hold the guest view")
	}
}

// ── IMP-2: a linked clone of a --no-localize promoted VM ─────────────────────

// promotedClone is promotedVMInPool's "pr" (an overlay in pool dr on a raw
// replica) and "lc", the linked clone CloneVM makes of it: clone → promoted
// overlay → raw replica, two records down.
func promotedClone(t *testing.T) (s *Server, lc corrosion.DiskRecord, raw []byte) {
	t.Helper()
	s, _ = provableCreateServer(t)
	victim := victimDisk(t)
	_, _, raw = promotedVMInPool(t, s, victim)
	registerPool(t, s, "dr", "dir", "", s.mustPoolDirFromRow(t, "dr"), "")
	registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "pr", Target: "lc", Mode: "linked"}); err != nil {
		t.Fatalf("linked clone of a promoted VM: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "lc")
	if len(disks) != 1 || disks[0].BackingDisk == "" {
		t.Fatalf("fixture: lc is not a linked clone: %+v", disks)
	}
	return s, disks[0], raw
}

func (s *Server) mustPoolDirFromRow(t *testing.T, name string) string {
	t.Helper()
	rec, ok, err := corrosion.GetStoragePool(context.Background(), s.db, s.hostName, name)
	if err != nil || !ok {
		t.Fatalf("pool row %q: %v", name, err)
	}
	return rec.Target
}

func TestMoveVolume_LinkedCloneOfAPromotedVM(t *testing.T) {
	s, _, raw := promotedClone(t)
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "lc", DiskName: "root", TargetPool: "fast"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("MoveVolume of a linked clone of a promoted VM: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "lc")
	if got := guestView(t, disks[0].Path); !bytes.Equal(got, raw) {
		t.Error("the moved disk does not hold the guest view")
	}
}

func TestReplicateVolume_LinkedCloneOfAPromotedVM(t *testing.T) {
	s, _, raw := promotedClone(t)
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "lc", DiskName: "root", TargetPool: "fast"}, rec); err != nil {
		t.Fatalf("ReplicateVolume of a linked clone of a promoted VM: %v", err)
	}
	if got := guestView(t, rec.Sent[len(rec.Sent)-1].TargetPath); !bytes.Equal(got, raw) {
		t.Error("the copy does not hold the guest view")
	}
}

func TestCloneVM_FullCloneOfALinkedCloneOfAPromotedVM(t *testing.T) {
	s, _, raw := promotedClone(t)
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "lc", Target: "lc2", Mode: "full"}); err != nil {
		t.Fatalf("full clone of a linked clone of a promoted VM: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "lc2")
	if got := guestView(t, disks[0].Path); !bytes.Equal(got, raw) {
		t.Error("the full clone does not hold the guest view")
	}
}

func TestColdMigrationFlatten_LinkedCloneOfAPromotedVM(t *testing.T) {
	s, lc, raw := promotedClone(t)
	if got := coldFlatten(t, s, lc); !bytes.Equal(got, raw) {
		t.Error("the flattened copy does not hold the guest view")
	}
}

func TestRestoreInPlace_LinkedCloneOfAPromotedVM(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	pool := t.TempDir()
	registerPool(t, f.s, "dr", "dir", "", pool, "")
	overlay, replica, raw := promotedOverRawReplica(t, pool, victimDisk(t))
	if err := corrosion.InsertVM(context.Background(), f.s.db,
		corrosion.VMRecord{Name: "pr", HostName: f.s.hostName, State: "stopped", Project: "a", Spec: `{"name":"pr"}`}, nil,
		[]corrosion.DiskRecord{{VMName: "pr", DiskName: "root", HostName: f.s.hostName, Path: overlay,
			SizeBytes: 1 << 20, StorageType: "dir", StorageVolume: "dr", BackingDisk: replica}}); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(f.s.dataDir, "disks", "lc-root.qcow2")
	want := append(bytes.Repeat([]byte("DELTA"), 65536/5+1)[:65536], raw[65536:]...)
	overlayWithData(t, disk, overlay, "qcow2", want)
	backedVM(t, f, "lc", disk, corrosion.DiskRecord{StorageType: "local", BackingDisk: overlay})
	const ts = "2026-10-10T11:00:00Z"
	pushVM(t, f, "lc", disk, ts, pbsstore.ContentDiskFile, "")
	if err := inPlace(f, "lc", ts); err != nil {
		t.Fatalf("in-place restore of a linked clone of a promoted VM: %v", err)
	}
	requireRestoredOnto(t, disk, overlay, want)
}

// ── IMP-3: an image-store layer must be standalone ───────────────────────────

// imageNamingADisk is project b's disk "db", an image "evil" whose header
// names it as a qcow2 backing, and project a's VM "im" created from that
// image. The disk lives in <data_dir>/disks, or with inPool in global pool
// "shared" — a directory project a's chains may read from, so that only the
// image layer's standalone rule keeps it out. Returns the VM's disk record.
func imageNamingADisk(t *testing.T, s *Server, inPool bool) corrosion.DiskRecord {
	t.Helper()
	ctx := context.Background()
	disks := filepath.Join(s.dataDir, "disks")
	dir, storageType, pool := disks, "local", ""
	if inPool {
		dir, storageType, pool = t.TempDir(), "dir", "shared"
		registerPool(t, s, "shared", "dir", "", dir, "")
	}
	victim := filepath.Join(dir, "db-root.qcow2")
	filledQcow2(t, victim, "PROJECT-B ")
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "db", HostName: s.hostName, State: "stopped", Project: "b", Spec: `{"name":"db"}`}, nil,
		[]corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: s.hostName, Path: victim, SizeBytes: 1 << 20, StorageType: storageType, StorageVolume: pool}}); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(s.dataDir, "images", "evil.qcow2")
	if err := os.MkdirAll(filepath.Dir(evil), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(evil, victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(disks, "im-root.qcow2")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(disk, evil, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "im", Cpu: 1, MemoryMib: 256, Project: "a"})
	rec := corrosion.DiskRecord{VMName: "im", DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20,
		StorageType: "local", BackingImage: "evil"}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "im", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{rec}); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestCloneVM_FullCloneRefusesAnImageThatNamesAFile(t *testing.T) {
	for _, inPool := range []bool{false, true} {
		t.Run(map[bool]string{false: "data-disks", true: "global-pool"}[inPool], func(t *testing.T) {
			s, _ := provableCreateServer(t)
			imageNamingADisk(t, s, inPool)
			_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "im", Target: "copy", Mode: "full"})
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("full clone through an image naming another project's disk: got %v, want FailedPrecondition", err)
			}
			if disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "copy"); len(disks) > 0 {
				if got := guestView(t, disks[0].Path); bytes.Contains(got, []byte("PROJECT-B")) {
					t.Fatal("the full clone read the other project's disk the image named")
				}
			}
		})
	}
}

func TestBuildImage_RefusesAnImageThatNamesAFile(t *testing.T) {
	for _, inPool := range []bool{false, true} {
		t.Run(map[bool]string{false: "data-disks", true: "global-pool"}[inPool], func(t *testing.T) {
			s, _ := provableCreateServer(t)
			imageNamingADisk(t, s, inPool)
			_, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "im", ImageName: "golden"})
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("BuildImage through an image naming another project's disk: got %v, want FailedPrecondition", err)
			}
			if got, err := os.ReadFile(s.images.ImagePath("golden")); err == nil && bytes.Contains(got, []byte("PROJECT-B")) {
				t.Fatal("the built image holds the other project's disk")
			}
		})
	}
}

func TestColdMigrationFlatten_RefusesAnImageThatNamesAFile(t *testing.T) {
	for _, inPool := range []bool{false, true} {
		t.Run(map[bool]string{false: "data-disks", true: "global-pool"}[inPool], func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			d := imageNamingADisk(t, s, inPool)
			if _, err := s.coldDiskSourceCheck(d, "qcow2"); status.Code(err) != codes.FailedPrecondition {
				t.Errorf("cold-migration check through an image naming another project's disk: got %v, want FailedPrecondition", err)
			}
			flat := filepath.Join(t.TempDir(), "flat.qcow2")
			if err := s.flattenColdDisk(context.Background(), d, d.Path, flat); status.Code(err) != codes.FailedPrecondition {
				t.Errorf("cold-migration flatten through it: got %v, want FailedPrecondition", err)
			}
		})
	}
}

func TestMoveVolume_RefusesAnImageThatNamesAFile(t *testing.T) {
	for _, inPool := range []bool{false, true} {
		t.Run(map[bool]string{false: "data-disks", true: "global-pool"}[inPool], func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
			imageNamingADisk(t, s, inPool)
			err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "im", DiskName: "root", TargetPool: "fast"},
				&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "image-store layer") {
				t.Errorf("move through an image naming another project's disk: got %v, want FailedPrecondition naming the image layer", err)
			}
		})
	}
}

// ── C-1 test gaps: the victim inside an allowed root ─────────────────────────

// promotedVMWithVictimInPool is promotedVMInPool with the file the replica's
// bytes name INSIDE pool dr — a root the chain may read from — so only the
// raw backing being read as raw keeps it out.
func promotedVMWithVictimInPool(t *testing.T, s *Server) (corrosion.DiskRecord, []byte) {
	t.Helper()
	pool := t.TempDir()
	registerPool(t, s, "dr", "dir", "", pool, "")
	victim := filepath.Join(pool, "db-root.qcow2")
	filledQcow2(t, victim, "PROJECT-B ")
	overlay, replica, raw := promotedOverRawReplica(t, pool, victim)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web-dr", Cpu: 1, MemoryMib: 256, Project: "a"})
	rec := corrosion.DiskRecord{VMName: "web-dr", DiskName: "root", HostName: s.hostName, Path: overlay,
		SizeBytes: 1 << 20, StorageType: "dir", StorageVolume: "dr", BackingDisk: replica}
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "web-dr", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{rec}); err != nil {
		t.Fatal(err)
	}
	return rec, raw
}

func TestCloneVM_FullCloneOfAPromotedVMNeverReadsWhatTheReplicaNamesInsideTheRoots(t *testing.T) {
	s, _ := provableCreateServer(t)
	_, raw := promotedVMWithVictimInPool(t, s)
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "web-dr", Target: "copy", Mode: "full"}); err != nil {
		t.Fatalf("full clone of a promoted VM: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "copy")
	got := guestView(t, disks[0].Path)
	if bytes.Contains(got, []byte("PROJECT-B")) {
		t.Fatal("the full clone read the disk the replica's bytes named")
	}
	if !bytes.Equal(got, raw) {
		t.Error("the full clone does not hold the replica's raw bytes")
	}
}

func TestBuildImage_FromAPromotedVMNeverReadsWhatTheReplicaNamesInsideTheRoots(t *testing.T) {
	s, _ := provableCreateServer(t)
	_, raw := promotedVMWithVictimInPool(t, s)
	if _, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "web-dr", ImageName: "golden"}); err != nil {
		t.Fatalf("build image from a promoted VM: %v", err)
	}
	got := guestView(t, s.images.ImagePath("golden"))
	if bytes.Contains(got, []byte("PROJECT-B")) {
		t.Fatal("the built image holds the disk the replica's bytes named")
	}
	if !bytes.Equal(got, raw) {
		t.Error("the built image does not hold the replica's raw bytes")
	}
}

// C-1, the cold-migration flatten (no test covered it).
func TestColdMigrationFlatten_OfAPromotedVMNeverReadsWhatTheReplicaNames(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	d, raw := promotedVMWithVictimInPool(t, s)
	got := coldFlatten(t, s, d)
	if bytes.Contains(got, []byte("PROJECT-B")) {
		t.Fatal("the cold-migration flatten read the disk the replica's bytes named")
	}
	if !bytes.Equal(got, raw) {
		t.Error("the flat copy does not hold the replica's raw bytes")
	}
}

// I-1: the refusal names why.
func TestConvertVMDisk_RefusesARawBackingNoRecordNames(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	pool := t.TempDir()
	registerPool(t, s, "dr", "dir", "", pool, "")
	overlay, _, _ := promotedOverRawReplica(t, pool, victimDisk(t))
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "pr", HostName: s.hostName, State: "stopped", Project: "a"}, nil,
		[]corrosion.DiskRecord{{VMName: "pr", DiskName: "root", HostName: s.hostName, Path: overlay, StorageType: "dir", StorageVolume: "dr"}}); err != nil {
		t.Fatal(err)
	}
	d := corrosion.DiskRecord{VMName: "pr", DiskName: "root", Path: overlay, StorageVolume: "dr"} // no backing_disk anywhere
	err := s.convertVMDisk(context.Background(), &d, filepath.Join(t.TempDir(), "x.qcow2"), func(*pb.MoveVolumeProgress) error { return nil })
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "raw backing") || !strings.Contains(err.Error(), "not the backing_disk recorded") {
		t.Errorf("a raw backing no record names: got %v, want FailedPrecondition naming it", err)
	}
}

// I-3 test gap: BackupSnapshot itself records the base's identity — the
// fixture does not compute it — and a backup taken that way restores in place.
func TestBackupSnapshot_RecordsTheBaseIdentity(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	img := filepath.Join(f.s.dataDir, "images", "ubuntu.qcow2")
	base := filledQcow2(t, img, "UBUNTU ")
	disk := filepath.Join(f.s.dataDir, "disks", "im-root.qcow2")
	want := append(bytes.Repeat([]byte("DELTA"), 65536/5+1)[:65536], base[65536:]...)
	overlayWithData(t, disk, img, "qcow2", want)
	backedVM(t, f, "im", disk, corrosion.DiskRecord{StorageType: "local", BackingImage: "ubuntu"})
	f.s.virt = nil // the disk-file backup path
	const ts = "2026-10-10T12:00:00Z"
	if err := f.s.BackupSnapshot(&pb.BackupSnapshotRequest{VmName: "im", DiskName: "root", RepoPath: "r", Timestamp: ts},
		&progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("BackupSnapshot: %v", err)
	}
	repo, err := pbsstore.Open(f.s.backupRepos["r"])
	if err != nil {
		t.Fatal(err)
	}
	m, err := repo.GetManifest("im", ts, "root")
	if err != nil {
		t.Fatal(err)
	}
	if m.BaseIdentity == nil {
		t.Fatal("BackupSnapshot recorded no base identity for an overlay's disk-file backup")
	}
	rimg, _ := filepath.EvalSymlinks(img)
	raw, _ := os.ReadFile(img)
	if m.BaseIdentity.Path != rimg || m.BaseIdentity.Size != int64(len(raw)) || m.BaseIdentity.SHA256 != sha256Hex(raw) {
		t.Errorf("recorded base identity %+v, want %s, %d bytes, sha256 %s", m.BaseIdentity, rimg, len(raw), sha256Hex(raw))
	}
	f.s.virt = libvirtfake.New()
	if err := inPlace(f, "im", ts); err != nil {
		t.Fatalf("in-place restore of a backup BackupSnapshot took: %v", err)
	}
	requireRestoredOnto(t, disk, img, want)
}

// m4: a restore that leaves the disk standalone clears the backing record a
// move left stale.
func TestRestoreInPlace_AStandaloneRestoreClearsTheBackingRecord(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	pool := t.TempDir()
	_, replica, _ := promotedOverRawReplica(t, pool, victimDisk(t))
	disk := filepath.Join(pool, "st-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", disk, "1M")
	registerPool(t, f.s, "dr", "dir", "", pool, "")
	backedVM(t, f, "st", disk, corrosion.DiskRecord{StorageType: "dir", StorageVolume: "dr", BackingDisk: replica})
	const ts = "2026-10-10T13:00:00Z"
	pushVM(t, f, "st", disk, ts, pbsstore.ContentDiskFile, "")
	if err := inPlace(f, "st", ts); err != nil {
		t.Fatalf("in-place restore of a standalone backup: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "st")
	if disks[0].BackingDisk != "" || disks[0].BackingImage != "" {
		t.Errorf("a standalone restore left backing %q/%q on the record", disks[0].BackingDisk, disks[0].BackingImage)
	}
}
