package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// deleteDiskServer is a server whose VM "a" runs here, its one disk at disk.
func deleteDiskServer(t *testing.T, disk string) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain("<domain><name>a</name></domain>"); err != nil {
		t.Fatal(err)
	}
	fake.SetState("a", libvirtfake.StateRunning)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "a", HostName: s.hostName, State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "a", DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20,
			StorageType: "local", DeleteWithVM: true}}); err != nil {
		t.Fatal(err)
	}
	return s, fake
}

// F-5 (lab 2): `lv rm` printed "deleted" and left the VM's disk file. One way
// is a disk whose use by another VM cannot be told — here another VM's disk
// is on storage that does not answer: the delete kept the disk on that guess
// and reported success. It is refused before anything is torn down: the VM
// keeps running, with its record and its disk.
//
// Mutation: drop preflightDiskRemoval — the VM is torn down, and the delete
// then fails on the disk it kept (or, with the post-teardown check dropped
// too, reports success with the disk left: main).
func TestDeleteVM_ADiskWhoseUseCannotBeToldRefusesBeforeTheTeardown(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "a-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, fake := deleteDiskServer(t, disk)
	dead := deadChainDir(t)
	other := filepath.Join(dead, "b-root.qcow2")
	if err := qcow2.Create(other, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	insertOneDiskVM(t, s, "b", other, true)

	err := within(t, 10*time.Second, "a delete while another VM's disk does not answer", func() error {
		_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
		return err
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("DeleteVM: %v, want Unavailable (whether the disk is used cannot be told)", err)
	}
	if active, _ := fake.DomainIsActive("a"); !active {
		t.Error("the refused delete stopped the VM")
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm == nil || vm.State != "running" {
		t.Errorf("the refused delete changed the record: %+v", vm)
	}
	if !exists(disk) {
		t.Error("the refused delete removed the disk")
	}
}

// The other way: a disk whose removal fails after the domain is gone. The
// delete fails and keeps the record — the cluster's only handle on the disk —
// recorded as stopped; once the cause is gone, the retry (which finds no
// domain) removes the disk and the record.
//
// Mutations: report success with a disk left (the post-teardown check
// dropped) — the first delete succeeds: red. Drop the stale-record path's
// disk removal — the retry deletes the record and leaves the disk: red.
func TestDeleteVM_ADiskNotRemovedKeepsTheRecordAndARetryRemovesIt(t *testing.T) {
	// A non-empty directory where the disk file is recorded: its unlink
	// fails, as one on storage that refuses it does.
	disk := filepath.Join(t.TempDir(), "a-root.qcow2")
	if err := os.MkdirAll(disk, 0o755); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(disk, "busy")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, fake := deleteDiskServer(t, disk)

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
	if err == nil {
		t.Fatal("the delete reported success with the VM's disk left behind")
	}
	if !exists(disk) {
		t.Fatal("the setup's disk is gone: the test proves nothing")
	}
	vm, _ := corrosion.GetVM(adminCtx(), s.db, "a")
	if vm == nil {
		t.Fatal("the failed delete dropped the record of a disk it left")
	}
	if vm.State != "stopped" {
		t.Errorf("record state %q after its domain was destroyed, want stopped", vm.State)
	}
	if fake.DomainExists("a") {
		t.Error("the domain is still defined: the failure is not the one after the teardown")
	}

	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"}); err != nil {
		t.Fatalf("retried delete: %v", err)
	}
	if exists(disk) {
		t.Error("the retried delete left the disk")
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm != nil {
		t.Error("the retried delete left the record")
	}
}

// A VM with no domain anywhere (here: a stopped VM a failover placed on this
// host, whose domain is defined only when it starts) is deleted through the
// stale-record path; its own disks on this host go with it, as they do for
// a VM whose domain is here. A disk on shared storage is not this path's to
// remove.
//
// Mutation: drop the stale-record path's disk removal — the disk stays: red.
func TestDeleteVM_AVMWithNoDomainHasItsOwnDisksRemoved(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "a-root.qcow2")
	shared := filepath.Join(t.TempDir(), "a-data.qcow2")
	for _, f := range []string{local, shared} {
		if err := qcow2.Create(f, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "a", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{
			{VMName: "a", DiskName: "root", HostName: s.hostName, Path: local, StorageType: "local", DeleteWithVM: true},
			{VMName: "a", DiskName: "data", HostName: s.hostName, Path: shared, StorageType: "nfs", DeleteWithVM: true},
		}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm != nil {
		t.Error("the record survived")
	}
	if exists(local) {
		t.Error("the VM's own disk on this host was left behind")
	}
	if !exists(shared) {
		t.Error("a disk on shared storage was removed by the no-domain path")
	}
}
