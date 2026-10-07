package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Where two of the final-review fixes meet.

// Pools C3 (an area replica is deleted through the content API) meets import
// I-5 (the area's directories are 0711) and the top-level copy a run writes
// while a main-build host is in the cluster (I-3, replica_mirror.go): the
// operator deletes both copies of her VM's replica, each by its name, never
// another project's area replica; the next run writes into the same owner
// directory, which qemu can still search.
func TestCrossFix_AnAreaReplicaAndItsMainCopyAreDeletedAndTheAreaStaysReachable(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	f := newPoolFixture(t)
	f.grantPoolWrite(t)
	setEveryHostListsReplicas(t, f.s, false)
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	sched := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 3}
	run := func(ts string) {
		t.Helper()
		if err := f.s.replicateLocalWith(ctx, sched, vm, &disks[0], ts, func(_ context.Context, _, dst string, _ func(*pb.MoveVolumeProgress) error) error {
			return os.WriteFile(dst, []byte("replica "+ts), 0o600)
		}); err != nil {
			t.Fatalf("replicate at %s: %v", ts, err)
		}
	}
	run("20261005-000000")

	area := filepath.Join(replicaOwnerDir(f.dr, "a", "web"), "1-20261005-000000.qcow2")
	top := filepath.Join(f.dr, "web-1-20261005-000000.qcow2")
	if got := listedReplicas(t, f.s, f.alice, "dr"); !slices.Contains(got, "web/"+filepath.Base(area)) {
		t.Fatalf("alice's listing = %v, want web/%s", got, filepath.Base(area))
	}
	for _, p := range []string{area, top} {
		if _, err := f.s.DeleteStoragePoolContent(f.alice, &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(p)}); err != nil {
			t.Fatalf("alice deleting %s: %v", filepath.Base(p), err)
		}
		if present(p) {
			t.Fatalf("%s is still there after a delete that returned OK", p)
		}
	}
	// Project b's replica in the area stays b's.
	theirs := areaReplica(t, f.dr, "b", "web-1", "1", "20261005-000000")
	if _, err := f.s.DeleteStoragePoolContent(f.alice, &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(theirs), ReplicaVm: "web-1"}); status.Code(err) != codes.NotFound {
		t.Errorf("alice deleting project b's area replica: got %v, want NotFound", err)
	}

	// The owner directory the delete emptied is written again, and stays
	// searchable by qemu.
	run("20261005-010000")
	next := filepath.Join(replicaOwnerDir(f.dr, "a", "web"), "1-20261005-010000.qcow2")
	if !present(next) || !present(filepath.Join(f.dr, "web-1-20261005-010000.qcow2")) {
		t.Fatalf("the next run wrote no replica after the delete")
	}
	for _, d := range []string{filepath.Join(f.dr, replicaAreaDir), filepath.Dir(next)} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o711 {
			t.Errorf("%s after a delete and a new run: %v (%v), want 0711", d, fi.Mode().Perm(), err)
		}
	}
}

// ISO C-3 (a rebuild judges the VM's ISO before it tears the VM down, and
// carries its classification into the create) meets import I-4 (every start
// judges a disk's whole backing chain): an operator rebuilds a VM whose disk
// chain the start now refuses (its base is gone) and whose ISO is a legacy
// host path. The preflight does not judge the disks the rebuild replaces, so
// the rebuild goes ahead; the rebuilt VM's fresh disk passes the chain judge,
// and its ISO the start's ISO judge.
func TestCrossFix_ARebuildReplacesADiskTheStartRefusesAndTheVMStarts(t *testing.T) {
	s, fake, _ := isoServer(t)
	ctx := adminCtx()
	if err := qcow2.Create(filepath.Join(s.dataDir, "images", "ubuntu.qcow2"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(t.TempDir(), "plain.iso")
	writeLibFile(t, plain, isoBody)
	req := isoCreate("old", plain, "")
	req.Spec.Image = "ubuntu"
	req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
	if _, err := s.CreateVM(ctx, req); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, "old")
	iso := filepath.Join(t.TempDir(), "win.iso")
	writeLibFile(t, iso, opticalImage("win"))
	spec := vmSpecFor(vmRecord(t, s, "old"))
	spec.Iso, spec.IsoScope = iso, ""
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = ?`, string(b), "old"); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(strings.ReplaceAll(fake.DefinedXML("old"), plain, iso)); err != nil {
		t.Fatal(err)
	}
	// Its disk's base is gone: the start refuses it.
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "old")
	if err := os.Remove(disks[0].Path); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(disks[0].Path, "gone", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyImageBasesForStart(context.Background(), vmRecord(t, s, "old")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("before the rebuild, the start's chain judge = %v, want it refused", err)
	}

	if _, err := s.RebuildVM(userCtx("op", "operator"), &pb.RebuildVMRequest{Name: "old"}); err != nil {
		t.Fatalf("an operator's rebuild of a VM whose disk the start refuses: %v", err)
	}
	rec := vmExists(t, s, "old", "after the rebuild")
	if got := vmSpecFor(rec).GetIso(); got != iso {
		t.Fatalf("the rebuilt VM's ISO = %q, want %q", got, iso)
	}
	if err := s.verifyImageBasesForStart(context.Background(), rec); err != nil {
		t.Fatalf("the rebuilt VM's disk chain is refused at start: %v", err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), rec); err != nil {
		t.Fatalf("start of the rebuilt VM: %v", err)
	}
}
