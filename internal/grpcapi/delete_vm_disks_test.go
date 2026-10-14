package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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
	return deleteDiskServerWith(t, true, corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: disk, SizeBytes: 1 << 20,
		StorageType: "local", DeleteWithVM: true})
}

// deleteDiskServerWith is a server with VM "a" and its disks (on this host),
// its domain defined and running here when withDomain.
func deleteDiskServerWith(t *testing.T, withDomain bool, disks ...corrosion.DiskRecord) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatal(err)
	}
	state := "stopped"
	if withDomain {
		if err := fake.DefineDomain("<domain><name>a</name></domain>"); err != nil {
			t.Fatal(err)
		}
		fake.SetState("a", libvirtfake.StateRunning)
		state = "running"
	}
	for i := range disks {
		disks[i].HostName = s.hostName
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "a", HostName: s.hostName, State: state}, nil, disks); err != nil {
		t.Fatal(err)
	}
	return s, fake
}

// trailerStream records the header and trailer a handler sets.
type trailerStream struct{ hdr, trl metadata.MD }

func (h *trailerStream) Method() string { return "/litevirt.v1.LiteVirt/DeleteVM" }
func (h *trailerStream) SetHeader(md metadata.MD) error {
	h.hdr = metadata.Join(h.hdr, md)
	return nil
}
func (h *trailerStream) SendHeader(md metadata.MD) error { return h.SetHeader(md) }
func (h *trailerStream) SetTrailer(md metadata.MD) error {
	h.trl = metadata.Join(h.trl, md)
	return nil
}

// deleteNamed runs DeleteVM of "a" and returns the kept disks its response
// names.
func deleteNamed(t *testing.T, s *Server) ([]KeptDisk, error) {
	t.Helper()
	st := &trailerStream{}
	_, err := s.DeleteVM(grpc.NewContextWithServerTransportStream(adminCtx(), st), &pb.DeleteVMRequest{Name: "a"})
	var out []KeptDisk
	for _, v := range st.hdr.Get(KeptDiskMD) {
		var k KeptDisk
		if jerr := json.Unmarshal([]byte(v), &k); jerr != nil {
			t.Fatalf("kept disk header %q: %v", v, jerr)
		}
		out = append(out, k)
	}
	return out, err
}

// assertNamed checks that path is named three ways: the response (when
// header), a vm.disk_kept event, and disk_leftover with why in its reason.
func assertNamed(t *testing.T, s *Server, kept []KeptDisk, header bool, path, why string) {
	t.Helper()
	if header {
		found := false
		for _, k := range kept {
			if k.Path == path && strings.Contains(k.Reason, why) {
				found = true
			}
		}
		if !found {
			t.Errorf("response names %+v, want %s kept because %q", kept, path, why)
		}
	}
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, "a", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	event := false
	for _, e := range evs {
		if e.Type == "vm.disk_kept" && strings.Contains(e.Detail, path) {
			event = true
		}
	}
	if !event {
		t.Errorf("no vm.disk_kept event names %s: %+v", path, evs)
	}
	s.judgeKeptDisks(context.Background())
	row, found, err := corrosion.GetHealthCondition(context.Background(), s.db, diskLeftoverEvaluator, condDiskLeftover, "host", s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved || !strings.Contains(row.Evidence, path) || !strings.Contains(row.Evidence, why) {
		t.Errorf("%s does not name %s (%q): found=%v %s", condDiskLeftover, path, why, found, row.Evidence)
	}
}

// F-5 (lab 2): `lv rm` printed "deleted" and left the VM's disk file. One way
// is a disk whose use by another VM cannot be told — here another VM's disk
// is on storage that does not answer. The delete goes on, as on main, and the
// disk is kept — never removed on a guess — and named: in the response, by
// an event, and by disk_leftover.
//
// Mutations: drop the "cannot tell" keep (remove on a guess) — the disk is
// gone: red. Drop the naming — red.
func TestDeleteVM_ADiskWhoseUseCannotBeToldIsKeptAndNamed(t *testing.T) {
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

	var kept []KeptDisk
	err := within(t, 10*time.Second, "a delete while another VM's disk does not answer", func() error {
		var err error
		kept, err = deleteNamed(t, s)
		return err
	})
	if err != nil {
		t.Fatalf("DeleteVM: %v (a delete main allowed goes on)", err)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm != nil {
		t.Error("the record survived")
	}
	if fake.DomainExists("a") {
		t.Error("the domain survived")
	}
	if !exists(disk) {
		t.Fatal("a disk whose use could not be told was removed")
	}
	assertNamed(t, s, kept, true, disk, "cannot be told")
}

// The other way: a disk whose removal fails after the domain is gone. The
// delete fails and keeps the record — the cluster's handle on the disk —
// recorded as stopped, and disk_leftover names it at once; once the cause
// is gone, the retry (which finds no domain) removes the disk and the
// record, and the condition resolves.
//
// Mutations: report success with a disk left (the post-teardown check
// dropped) — red. Drop the no-domain path's disk removal — the retry leaves
// the disk: red.
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
	assertNamed(t, s, nil, false, disk, "removal failed")

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
	s.judgeKeptDisks(context.Background())
	row, _, _ := corrosion.GetHealthCondition(context.Background(), s.db, diskLeftoverEvaluator, condDiskLeftover, "host", s.hostName)
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("%s still raised once the disk is gone: %s", condDiskLeftover, row.Evidence)
	}
}

// standInBtrfsForDelete puts a btrfs on PATH whose subvolumes are plain
// directories; "subvolume delete" fails while refuse exists.
func standInBtrfsForDelete(t *testing.T) (refuse string) {
	t.Helper()
	bin := t.TempDir()
	refuse = filepath.Join(bin, "refuse")
	script := "#!/bin/sh\ncase \"$1 $2\" in\n" +
		"\"subvolume delete\") [ -e " + refuse + " ] && { echo 'ERROR: Could not destroy subvolume: Device or resource busy' >&2; exit 1; }; exec rm -rf \"$4\";;\n" +
		"\"subvolume show\") [ -d \"$4\" ] && exit 0; exit 1;;\nesac\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "btrfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refuse, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return refuse
}

// I-2: a btrfs-pool disk whose subvolume cannot be deleted. Its qcow2 is
// removed first, so a check of the file alone found nothing left and the VM
// was reported deleted with the subvolume behind (lab 2 F-5). The delete
// fails, keeps the record, and names the subvolume; the retry removes it.
//
// Mutation: let stillLeft drop a leftover by its file again — the delete
// succeeds with the subvolume left: red.
func TestDeleteVM_ABtrfsSubvolumeLeftBehindFailsTheDelete(t *testing.T) {
	refuse := standInBtrfsForDelete(t)
	root := t.TempDir()
	subvol := filepath.Join(root, "a-root")
	if err := os.MkdirAll(subvol, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(subvol, "a-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, _ := deleteDiskServerWith(t, true, corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: disk, SizeBytes: 1 << 20,
		StorageType: "btrfs", StorageVolume: "bt", DeleteWithVM: true})
	s.addStoragePoolRef("bt", StoragePoolRef{Driver: "btrfs", Source: root})

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
	if err == nil {
		t.Fatal("the delete reported success with the disk's subvolume left behind")
	}
	if !exists(subvol) {
		t.Fatal("the setup's subvolume is gone: the test proves nothing")
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm == nil {
		t.Fatal("the failed delete dropped the record")
	}
	assertNamed(t, s, nil, false, subvol, "removal failed")

	if err := os.Remove(refuse); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"}); err != nil {
		t.Fatalf("retried delete: %v", err)
	}
	if exists(subvol) {
		t.Error("the retried delete left the subvolume")
	}
}

// A VM with no domain anywhere (here: a stopped VM a failover placed on this
// host, whose domain is defined only when it starts) is deleted through the
// no-domain path; its own disks on this host go with it, as they do for a VM
// whose domain is here. A disk on shared storage is not this path's to
// remove, and is named.
//
// Mutations: drop the no-domain path's disk removal — the local disk stays:
// red. Drop the shared-storage keep — the shared disk is removed: red.
func TestDeleteVM_AVMWithNoDomainHasItsOwnDisksRemoved(t *testing.T) {
	local := filepath.Join(t.TempDir(), "a-root.qcow2")
	shared := filepath.Join(t.TempDir(), "a-data.qcow2")
	for _, f := range []string{local, shared} {
		if err := qcow2.Create(f, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := deleteDiskServerWith(t, false,
		corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: local, StorageType: "local", DeleteWithVM: true},
		corrosion.DiskRecord{VMName: "a", DiskName: "data", Path: shared, StorageType: "nfs", DeleteWithVM: true})

	kept, err := deleteNamed(t, s)
	if err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm != nil {
		t.Error("the record survived")
	}
	if exists(local) {
		t.Error("the VM's own disk on this host was left behind")
	}
	if !exists(shared) {
		t.Fatal("a disk on shared storage was removed by the no-domain path")
	}
	assertNamed(t, s, kept, true, shared, "shared storage")
}

// I-3 / m-2: a VM with no domain here, while another host does not say
// whether it runs the VM — an active peer that cannot be reached, or a host
// not active (a maintenance host still runs VMs). Its disks are neither
// removed (it may run there) nor left unnamed: the record goes, as on main,
// and each disk is kept and named with the hosts that did not answer.
//
// Mutation: count only answering peers (skip the silent and non-active
// ones) — the disk is removed: red.
func TestDeleteVM_AVMWithNoDomainWhileAHostIsSilentKeepsAndNamesItsDisks(t *testing.T) {
	for _, tc := range []struct{ name, state string }{
		{"unreachable active peer", "active"},
		{"maintenance host", "maintenance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disk := filepath.Join(t.TempDir(), "a-root.qcow2")
			if err := qcow2.Create(disk, 1<<20, nil); err != nil {
				t.Fatal(err)
			}
			s, _ := deleteDiskServerWith(t, false,
				corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: disk, StorageType: "local", DeleteWithVM: true})
			if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
				Name: "peer-x", Address: "203.0.113.9", State: tc.state, CPUTotal: 4, MemTotal: 4096,
			}); err != nil {
				t.Fatal(err)
			}

			kept, err := deleteNamed(t, s)
			if err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			if !exists(disk) {
				t.Fatal("a disk was removed while a host did not say whether it runs the VM")
			}
			assertNamed(t, s, kept, true, disk, "peer-x")
		})
	}
}

// m-1: a VM whose domain libvirt cannot answer for (here: its state read
// fails) is not "no domain": no disk of it is removed — the guest may still
// run on it — and each is named.
//
// Mutation: read any libvirt error as "no domain" — the disk is removed: red.
func TestDeleteVM_ALibvirtErrorIsNotNoDomain(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "a-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, fake := deleteDiskServerWith(t, false,
		corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: disk, StorageType: "local", DeleteWithVM: true})
	fake.FailDomainState = func(string) error { return errors.New("injected: libvirt connection reset") }

	kept, err := deleteNamed(t, s)
	if err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if !exists(disk) {
		t.Fatal("a disk was removed although libvirt could not say the domain is gone")
	}
	assertNamed(t, s, kept, true, disk, "connection reset")
}

// m-3: a peer's local-only probe that finds the domain and refuses its
// delete marks the refusal (deleteProbeRefusedMD) with its own code, an
// Unavailable kept Unavailable, so the probing host keeps the record and
// passes the code on; one that has no domain answers NotFound, unmarked.
func TestDeleteVM_AProbeMarksItsRefusalAndKeepsItsCode(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "a-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, _ := deleteDiskServer(t, disk)
	if err := s.db.Execute(adminCtx(), `UPDATE vms SET state = 'backing-up' WHERE name = 'a'`); err != nil {
		t.Fatal(err)
	}
	probe := metadata.NewIncomingContext(adminCtx(), metadata.Pairs("x-lv-delete-local-only", "1"))
	if md, ok := metadata.FromIncomingContext(adminCtx()); ok {
		probe = metadata.NewIncomingContext(adminCtx(), metadata.Join(md, metadata.Pairs("x-lv-delete-local-only", "1")))
	}
	st := &trailerStream{}
	_, err := s.DeleteVM(grpc.NewContextWithServerTransportStream(probe, st), &pb.DeleteVMRequest{Name: "a"})
	if status.Code(err) != codes.FailedPrecondition || len(st.trl.Get(deleteProbeRefusedMD)) == 0 {
		t.Fatalf("probe of a VM being backed up here: %v, trailer %v; want FailedPrecondition, marked", err, st.trl)
	}

	st = &trailerStream{}
	_, err = s.DeleteVM(grpc.NewContextWithServerTransportStream(probe, st), &pb.DeleteVMRequest{Name: "nope"})
	if status.Code(err) != codes.NotFound || len(st.trl.Get(deleteProbeRefusedMD)) != 0 {
		t.Fatalf("probe of a VM not here: %v, trailer %v; want NotFound, unmarked", err, st.trl)
	}

}

// I-5: a disk that is no file — an rbd locator the ceph handling cannot
// name — whose removal fails. "Not a file" read as "gone" let the delete
// report success with the volume left and nothing named; it fails, and the
// record is kept.
//
// Mutation: read a locator as gone in stillLeft — the delete succeeds: red.
func TestDeleteVM_AFailedRemovalOfANonFileDiskFailsTheDelete(t *testing.T) {
	s, _ := deleteDiskServerWith(t, true, corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: "rbd:noslash",
		StorageType: "ceph", DeleteWithVM: true})
	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
	if err == nil {
		t.Fatal("the delete reported success while the removal of its rbd disk failed")
	}
	if !strings.Contains(err.Error(), "rbd:noslash") {
		t.Errorf("the failure %q does not name the volume", err)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm == nil {
		t.Fatal("the failed delete dropped the record")
	}
	assertNamed(t, s, nil, false, "rbd:noslash", "removal failed")
}

// I-5: a block volume (here an LVM path, rooted under a test filesystem so
// its node can be made) whose removal fails, its node still there: the
// delete fails and names it.
func TestDeleteVM_AFailedRemovalOfABlockVolumeFailsTheDelete(t *testing.T) {
	root := t.TempDir()
	s, _ := deleteDiskServerWith(t, true, corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: "/dev/vgfu/a-root",
		StorageType: "lvm-thin", DeleteWithVM: true})
	s.SetHostDiskRootForTest(root)
	node := filepath.Join(root, "dev", "vgfu", "a-root")
	if err := os.MkdirAll(filepath.Dir(node), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
	if err == nil {
		t.Fatal("the delete reported success while the removal of its block volume failed")
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm == nil {
		t.Fatal("the failed delete dropped the record")
	}
	assertNamed(t, s, nil, false, "/dev/vgfu/a-root", "removal failed")
}

// I-5: a ceph disk a delete keeps (a VM with no domain: on shared storage)
// is named by the ceph handling, which can recheck its pool — never dropped
// as "not a file".
//
// Mutation: keep it as a disk_leftover entry judged by a stat — it is
// dropped unnamed: red.
func TestDeleteVM_AKeptCephDiskIsNamed(t *testing.T) {
	s, _ := deleteDiskServerWith(t, false, corrosion.DiskRecord{VMName: "a", DiskName: "data",
		Path: "rbd:lv/a-data:id=litevirt:lvpool=ceph", StorageType: "ceph", StorageVolume: "ceph", DeleteWithVM: true})
	st := &trailerStream{}
	if _, err := s.DeleteVM(grpc.NewContextWithServerTransportStream(adminCtx(), st), &pb.DeleteVMRequest{Name: "a"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	vals := st.hdr.Get(KeptCephImageMD)
	if len(vals) != 1 || !strings.Contains(vals[0], "lv/a-data") || !strings.Contains(vals[0], "shared storage") {
		t.Fatalf("response names %v, want the ceph image kept on shared storage", st.hdr)
	}
	found := false
	for _, r := range s.keptRecords() {
		if r.Image == "lv/a-data" {
			found = true
		}
	}
	if !found {
		t.Error("ceph_image_leftover does not record the kept image")
	}
}

// I-6: disk_leftover is cleared by hand by removing an entry from the record
// file, which the pass re-reads when it changed — no restart.
//
// Mutation: load the file once — the hand edit is ignored: red.
func TestKeptDisks_AHandEditOfTheRecordIsReadWithinAPass(t *testing.T) {
	s, _ := deleteDiskServerWith(t, false)
	other := "/elsewhere/a-root.qcow2"
	s.recordKeptDisks(context.Background(), "a", []KeptDisk{{Path: other, Disk: "root", Host: "node-9", Reason: "recorded on host node-9"}})
	s.judgeKeptDisks(context.Background())
	if open, ev := keptDiskCondition(t, s); !open || !strings.Contains(ev, other) {
		t.Fatalf("fixture: not named: %v %s", open, ev)
	}
	if err := os.WriteFile(filepath.Join(s.dataDir, diskKeptFile), []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.judgeKeptDisks(context.Background())
	if open, ev := keptDiskCondition(t, s); open {
		t.Fatalf("still named after its entry was removed from the record: %s", ev)
	}
}

// m-7: a record file that cannot be read is never read as empty nor written
// over. The disks it named stay named from memory, and the condition names
// the file and the recovery. m-10: once the operator's fix reads, what was
// recorded while it could not be read is merged in and saved — and an entry
// the fix removed stays removed.
//
// Mutations: read a corrupt file as empty — the disk is no longer named:
// red. Merge back every entry in memory on the recovery — the removed one
// comes back: red.
func TestKeptDisks_ACorruptRecordFailsClosed(t *testing.T) {
	s, _ := deleteDiskServerWith(t, false)
	file := filepath.Join(s.dataDir, diskKeptFile)
	s.recordKeptDisks(context.Background(), "a", []KeptDisk{{Path: "/x/one", Disk: "root", Host: "node-9", Reason: "r1"}})
	// The operator removes /x/one by hand, with a typo.
	corrupt := []byte("[ not json")
	if err := os.WriteFile(file, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	s.recordKeptDisks(context.Background(), "a", []KeptDisk{{Path: "/x/two", Disk: "data", Host: "node-9", Reason: "r2"}})
	s.judgeKeptDisks(context.Background())
	open, ev := keptDiskCondition(t, s)
	if !open || !strings.Contains(ev, "/x/one") || !strings.Contains(ev, "/x/two") || !strings.Contains(ev, "record_unreadable") {
		t.Fatalf("a corrupt record: %v %s; want both disks named, and the file", open, ev)
	}
	if b, _ := os.ReadFile(file); string(b) != string(corrupt) {
		t.Fatalf("the unreadable file was written over: %q", b)
	}
	// The fix: /x/one removed, as meant.
	if err := os.WriteFile(file, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.judgeKeptDisks(context.Background())
	b, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(b), "/x/two") {
		t.Fatalf("after the fix the record is %q (%v); want the disk recorded meanwhile saved", b, err)
	}
	if strings.Contains(string(b), "/x/one") {
		t.Fatalf("the entry the fix removed came back: %q", b)
	}
	if open, ev := keptDiskCondition(t, s); !open || strings.Contains(ev, "record_unreadable") || strings.Contains(ev, "/x/one") {
		t.Fatalf("after the fix: %v %s", open, ev)
	}
}

// Nit (concern 1): a hand edit that keeps the file's size and its mtime is
// still seen — the inode's change time moved.
//
// Mutation: compare mtime and size only — the edit is missed: red.
func TestKeptDisks_AnEditKeepingSizeAndMtimeIsRead(t *testing.T) {
	s, _ := deleteDiskServerWith(t, false)
	file := filepath.Join(s.dataDir, diskKeptFile)
	s.recordKeptDisks(context.Background(), "a", []KeptDisk{{Path: "/x/aaa", Disk: "root", Host: "node-9", Reason: "r"}})
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	time.Sleep(20 * time.Millisecond) // a later ctime
	if err := os.WriteFile(file, []byte(strings.ReplaceAll(string(b), "/x/aaa", "/x/bbb")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	s.judgeKeptDisks(context.Background())
	if open, ev := keptDiskCondition(t, s); !open || !strings.Contains(ev, "/x/bbb") || strings.Contains(ev, "/x/aaa") {
		t.Fatalf("an edit keeping size and mtime was missed: %v %s", open, ev)
	}
}

func keptDiskCondition(t *testing.T, s *Server) (bool, string) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), s.db, diskLeftoverEvaluator, condDiskLeftover, "host", s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	return found && row.Lifecycle != corrosion.ConditionResolved, row.Evidence
}

// m-9: a local-only probe whose libvirt cannot say whether it has the domain
// answers Unavailable, unmarked: the probing host counts it as no answer,
// never as a refusal to pass on or as "not here".
func TestDeleteVM_AProbeThatCannotTellIsUnavailableAndUnmarked(t *testing.T) {
	s, fake := deleteDiskServerWith(t, false)
	fake.FailDomainState = func(string) error { return errors.New("injected: libvirt connection reset") }
	md, _ := metadata.FromIncomingContext(adminCtx())
	probe := metadata.NewIncomingContext(adminCtx(), metadata.Join(md, metadata.Pairs("x-lv-delete-local-only", "1")))
	st := &trailerStream{}
	_, err := s.DeleteVM(grpc.NewContextWithServerTransportStream(probe, st), &pb.DeleteVMRequest{Name: "a"})
	if status.Code(err) != codes.Unavailable || len(st.trl.Get(deleteProbeRefusedMD)) != 0 {
		t.Fatalf("probe that cannot tell: %v, trailer %v; want Unavailable, unmarked", err, st.trl)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm == nil {
		t.Error("the probe removed the record")
	}
}
