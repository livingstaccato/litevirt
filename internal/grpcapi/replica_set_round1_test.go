package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// setPromoteVMRows is setPromoteVM with the VM's other disk rows given (root
// is added, at vda on a dead host).
// testVMUUID is a uuid for a test VM of name, the same for every call.
func testVMUUID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("litevirt-test-vm/"+name)).String()
}

func setPromoteVMRows(t *testing.T, s *Server, vm string, others []corrosion.DiskRecord) string {
	t.Helper()
	s.virt = libvirtfake.New()
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"dr": {Driver: "local", Target: poolDir}})
	// A VM has a uuid: a promotion's records are bound to it.
	spec, _ := json.Marshal(&pb.VMSpec{Name: vm, Uuid: testVMUUID(vm), Cpu: 1, MemoryMib: 256})
	disks := append([]corrosion.DiskRecord{{
		VMName: vm, DiskName: "root", HostName: "dead-host", Path: "/dead/" + vm + "-root.qcow2",
		SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda", Bus: "virtio",
	}}, others...)
	for i := range disks {
		disks[i].VMName = vm
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: vm, HostName: "dead-host", State: "running", Spec: string(spec),
	}, nil, disks); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return poolDir
}

// C1/I5: a data disk on shared storage is never rebuilt from a replica — even
// a replica that exists — and its row is left exactly as it was; a reachable
// one is reattached as-is, and the manifest says so. An unreachable one (a
// ceph image no file path reaches) is named as shared at its path, never as
// on the failed host.
//
// Mutations: "nfs rebuilt" (chooseSetReplicas ignores shared) — red; "shared
// wording" (the manifest's shared cases removed) — red.
func TestPromote_ASharedDiskIsReattachedAsIsNeverRebuilt(t *testing.T) {
	s := testServer(t)
	nfsDir := t.TempDir()
	nfsDisk := filepath.Join(nfsDir, "db-data1.qcow2")
	if err := os.WriteFile(nfsDisk, []byte("current data"), 0o600); err != nil {
		t.Fatal(err)
	}
	poolDir := setPromoteVMRows(t, s, "db", []corrosion.DiskRecord{
		{DiskName: "data1", HostName: "dead-host", Path: nfsDisk, SizeBytes: 1 << 20, StorageType: "nfs", StorageVolume: "nfs1", TargetDev: "vdb", Bus: "virtio"},
		{DiskName: "data2", HostName: "dead-host", Path: "rbd:vms/db-data2", SizeBytes: 1 << 20, StorageType: "ceph", StorageVolume: "ceph1", TargetDev: "vdc", Bus: "virtio"},
	})
	run := "20260101-000000"
	seedReplica(t, poolDir, "", "db", "root", run, "raw", 1<<20)
	seedReplica(t, poolDir, "", "db", "data1", run, "raw", 1<<20) // a stale copy an earlier build made
	// dead-host has no hosts row; since fix round 5 (review R3-I2) that is no
	// proof it is off, so it is proven off by an IPMI fence on record.
	recordOwnerFence(t, s, "ipmi1", "ipmi", "fenced", time.Minute)

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	rows := diskRowsOf(t, s, "db")
	if r := rows["data1"]; r.Path != nfsDisk || r.HostName != "dead-host" || r.StorageType != "nfs" || r.StorageVolume != "nfs1" {
		t.Errorf("data1 row = %+v, want it exactly as it was", r)
	}
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("db")
	if !strings.Contains(xml, nfsDisk) {
		t.Errorf("the shared disk was not reattached as-is: %s", xml)
	}
	manifest := eventDetail(t, s, "db", "vm.promoted")
	if !strings.Contains(manifest, "data1: shared (nfs) — reattached as-is at "+nfsDisk) {
		t.Errorf("manifest %q does not say data1 was reattached as-is", manifest)
	}
	partial := eventDetail(t, s, "db", vmEventPromotedPartial)
	if !strings.Contains(partial, "data2 (shared (ceph) at rbd:vms/db-data2, not attached") {
		t.Errorf("partial %q does not name data2 as shared at its path", partial)
	}
	if strings.Contains(partial, "data1") || strings.Contains(partial, "on dead-host") {
		t.Errorf("partial %q names data1 or sends the operator to the failed host", partial)
	}
}

// C1: a run never copies a data disk on shared storage.
//
// Mutation "nfs copied": replicateOtherDisks drops its shared case — red.
func TestReplication_NeverCopiesASharedDisk(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	dir := replicaPoolDir(t, s, "dr")
	src := t.TempDir()
	var disks []corrosion.DiskRecord
	for _, d := range []struct{ name, st string }{{"root", "dir"}, {"data1", "nfs"}} {
		p := filepath.Join(src, d.name+".qcow2")
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		disks = append(disks, corrosion.DiskRecord{VMName: "sh1", HostName: s.hostName, DiskName: d.name, Path: p, StorageType: d.st})
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "sh1", HostName: s.hostName, State: "stopped", Spec: `{}`}, nil, disks); err != nil {
		t.Fatal(err)
	}
	sched := corrosion.BackupScheduleRecord{VMName: "sh1", Repo: "dr", Type: "replication", TargetPool: "dr", TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3}
	if err := s.RunReplication(ctx, sched, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	recs, _ := listReplicaRecords(dir, "", "sh1")
	for _, r := range recs {
		if r.Disk == "data1" {
			t.Fatalf("the nfs disk was copied into a replica: %+v", r)
		}
	}
}

// I1: automatic promotion takes another disk's replica only within the bound
// the root's replica passed; one older is missing, never attached.
//
// Mutation "no bound": doPromoteLocal passes no age limit — red.
func TestAutoPromote_AnotherDisksReplicaBeyondTheBoundIsMissing(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	if err := corrosion.UpsertBackupSchedule(context.Background(), s.db, corrosion.BackupScheduleRecord{
		VMName: "db", Repo: "dr", Type: "replication", TargetPool: "dr",
		TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3, AutoPromote: true,
	}); err != nil {
		t.Fatal(err)
	}
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	seedReplica(t, poolDir, "", "db", "data1", stamp(30*24*time.Hour), "raw", 1<<20)

	if err := s.AutoPromoteReplica(context.Background(), "db", "", 0); err != nil {
		t.Fatalf("AutoPromoteReplica: %v", err)
	}
	if r := diskRowsOf(t, s, "db")["data1"]; r.HostName != "dead-host" {
		t.Errorf("data1 = %+v: a month-old replica was attached by automatic promotion", r)
	}
	if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, "older than automatic promotion's bound") {
		t.Errorf("partial = %q, want data1 named as beyond the bound", p)
	}
}

// targetDevs lists the target devices in a domain XML.
func targetDevs(xml string) []string {
	var out []string
	for _, part := range strings.Split(xml, `<target dev="`)[1:] {
		out = append(out, part[:strings.Index(part, `"`)])
	}
	return out
}

// I2: target devices never collide: the root is vda, a disk whose stored name
// is taken or empty gets the next free one.
//
// Mutation "stored names as-is": assignTargetDevs keeps every stored name and
// numbers empty ones by position — red.
func TestPromote_TargetDevicesNeverCollide(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", []corrosion.DiskRecord{
		{DiskName: "a", HostName: "dead-host", Path: "/dead/a", StorageType: "local", TargetDev: "vda", Bus: "virtio"}, // the root's name
		{DiskName: "b", HostName: "dead-host", Path: "/dead/b", StorageType: "local", TargetDev: "", Bus: "virtio"},
		{DiskName: "c", HostName: "dead-host", Path: "/dead/c", StorageType: "local", TargetDev: "vdc", Bus: "virtio"},
	})
	run := "20260101-000000"
	for _, d := range []string{"root", "a", "b", "c"} {
		seedReplica(t, poolDir, "", "db", d, run, "raw", 1<<20)
	}
	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})
	devs := targetDevs(s.virt.(*libvirtfake.Fake).DefinedXML("db"))
	seen := map[string]bool{}
	for _, d := range devs {
		if seen[d] {
			t.Fatalf("duplicate target %s in %v", d, devs)
		}
		seen[d] = true
	}
	if len(devs) != 4 || !seen["vda"] || !seen["vdc"] {
		t.Fatalf("targets = %v, want four distinct ones keeping vda for the root and c's vdc", devs)
	}
}

// I2: a domain that fails to define with the other disks is promoted with
// the root alone — main's outcome — never refused into a reschedule.
//
// Mutation "no root-only retry": the retry is removed — red (the promotion
// fails).
func TestPromote_ADefineFailureFromAnotherDiskFallsBackToTheRoot(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	run := "20260101-000000"
	for _, d := range []string{"root", "data1"} {
		seedReplica(t, poolDir, "", "db", d, run, "raw", 1<<20)
	}
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(xml string) error {
		if strings.Contains(xml, "promoted-data1") {
			return errors.New("unsupported configuration: data1")
		}
		return nil
	}
	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})
	rows := diskRowsOf(t, s, "db")
	if rows["root"].HostName != s.hostName || rows["data1"].HostName != "dead-host" {
		t.Errorf("rows = %+v, want the root promoted and data1 untouched", rows)
	}
	if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, "failed to define with it") {
		t.Errorf("partial = %q, want data1 named with the define failure", p)
	}
	if matches, _ := filepath.Glob(filepath.Join(poolDir, "db-promoted-data1-*")); len(matches) != 0 {
		t.Errorf("data1's live disk was left behind: %v", matches)
	}
}

// I3: adopting a domain an earlier attempt started counts another disk only
// if its live file exists and the domain has it; otherwise the disk is
// missing and its row untouched.
//
// Mutation "adoption trusts everything": the started check is removed — red.
func TestPromote_AdoptionCountsOnlyTheDisksTheDomainHas(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	run := "20260101-000000"
	for _, d := range []string{"root", "data1"} {
		seedReplica(t, poolDir, "", "db", d, run, "raw", 1<<20)
	}
	// The earlier attempt: root built, data1's build failed, domain started
	// on the root alone, then it died before persisting.
	rootLive := filepath.Join(poolDir, "db-promoted-root-"+run+".qcow2")
	if err := os.WriteFile(rootLive, []byte("built"), 0o600); err != nil {
		t.Fatal(err)
	}
	xml, err := lv.GenerateDomainXML(lv.VMConfig{Name: "db", CPU: 1, MemoryMiB: 256,
		Disks: []lv.DiskConfig{{Name: "root", Path: rootLive, Bus: "virtio"}}})
	if err != nil {
		t.Fatal(err)
	}
	f := s.virt.(*libvirtfake.Fake)
	if err := f.DefineDomain(xml); err != nil {
		t.Fatal(err)
	}
	if err := f.StartDomain("db"); err != nil {
		t.Fatal(err)
	}
	if err := s.writePromoteMarkerFor("db", "", testVMUUID("db")); err != nil {
		t.Fatal(err)
	}

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	rows := diskRowsOf(t, s, "db")
	if rows["root"].Path != rootLive {
		t.Fatalf("root = %+v, want the adopted live disk", rows["root"])
	}
	if r := rows["data1"]; r.HostName != "dead-host" || r.Path != "/dead/db-data1.qcow2" {
		t.Errorf("data1 = %+v: re-homed to a disk the adopted domain never had", r)
	}
	if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, "data1") {
		t.Errorf("partial = %q, want data1 named", p)
	}
}

// M3: with no run time for the root's replica, no other disk's replica can
// be matched to it, so none is taken.
//
// Mutation "empty disables the filter": chooseSetReplicas takes any replica
// when rootTaken is "" — red.
func TestChooseSetReplicas_NoRootTimeTakesNothing(t *testing.T) {
	poolDir := t.TempDir()
	seedReplica(t, poolDir, "", "db", "data1", "20260101-000000", "raw", 16)
	got := chooseSetReplicas(poolDir, "", "db", "", []corrosion.DiskRecord{{DiskName: "data1", StorageType: "local"}},
		func(corrosion.DiskRecord) bool { return false }, false, 0, time.Now())
	if len(got) != 1 || got[0].recovered() {
		t.Fatalf("chose %+v with no root run time", got)
	}
}

// M6: the partial marker persists, however many events the VM records after
// it, and a later complete promotion clears it.
//
// Mutation "derived from recent events": promotedPartialReason reads the
// newest 100 events — red.
func TestPromote_ThePartialMarkerPersists(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	seedReplica(t, poolDir, "", "db", "root", "20260101-000000", "raw", 1<<20)
	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})
	for i := 0; i < 150; i++ {
		s.recordVMEvent(context.Background(), "db", "disk.replicated", "ok", fmt.Sprintf("run %d", i))
	}
	pbVM, err := s.vmToProto(context.Background(), "db")
	if err != nil || !strings.Contains(pbVM.GetPromotedPartial(), "data1") {
		t.Fatalf("promoted_partial after 150 events = %q (%v), want data1 named", pbVM.GetPromotedPartial(), err)
	}
	s.clearPromotedPartial(context.Background(), "db")
	if pbVM, _ := s.vmToProto(context.Background(), "db"); pbVM.GetPromotedPartial() != "" {
		t.Errorf("promoted_partial after a complete promotion = %q", pbVM.GetPromotedPartial())
	}
}

// lockProbe is a backup source that records whether the VM's lock was held
// when each disk's session opened and when its export was read.
type lockProbe struct {
	fakeBackupSource
	s       *Server
	vm      string
	mu      sync.Mutex
	atBegin map[string]bool
	atRead  map[string]bool
}

func (p *lockProbe) locked() bool {
	p.s.vmLocksMu.Lock()
	mu := p.s.vmLocks[p.vm]
	p.s.vmLocksMu.Unlock()
	if mu == nil {
		return false
	}
	if mu.TryLock() {
		mu.Unlock()
		return false
	}
	return true
}

func (p *lockProbe) BeginBackup(domain, diskPath, parentCP, newCP string) (BackupReader, error) {
	p.mu.Lock()
	p.atBegin[filepath.Base(diskPath)] = p.locked()
	p.mu.Unlock()
	return &probeReader{BackupReader: &fakeBackupReader{data: make([]byte, 1<<20), extents: [][2]int64{{0, 4096}}}, p: p, disk: filepath.Base(diskPath)}, nil
}

type probeReader struct {
	BackupReader
	p    *lockProbe
	disk string
}

func (r *probeReader) ReadAt(b []byte, off int64) (int, error) {
	r.p.mu.Lock()
	r.p.atRead[r.disk] = r.p.locked()
	r.p.mu.Unlock()
	return r.BackupReader.ReadAt(b, off)
}

// I4: another disk's copy holds the VM lock only for its point-in-time step:
// the session opens under it, the export is read without it.
//
// Mutation "lock held throughout": runVMReplication keeps the lock through
// the other disks — red.
func TestReplication_AnotherDiskIsReadWithoutTheVMLock(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	f := libvirtfake.New()
	s.virt = f
	replicaPoolDir(t, s, "dr")
	src := t.TempDir()
	var disks []corrosion.DiskRecord
	for _, d := range []string{"root", "data1"} {
		p := filepath.Join(src, d+".qcow2")
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		disks = append(disks, corrosion.DiskRecord{VMName: "lk1", HostName: s.hostName, DiskName: d, Path: p, StorageType: "dir"})
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "lk1", HostName: s.hostName, State: "running", Spec: `{}`}, nil, disks); err != nil {
		t.Fatal(err)
	}
	f.SetState("lk1", libvirtfake.StateRunning)
	probe := &lockProbe{s: s, vm: "lk1", atBegin: map[string]bool{}, atRead: map[string]bool{}}
	s.backupSource = probe
	sched := corrosion.BackupScheduleRecord{VMName: "lk1", Repo: "dr", Type: "replication", TargetPool: "dr", TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3}
	if err := s.RunReplication(ctx, sched, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if !probe.atBegin["data1.qcow2"] {
		t.Error("data1's session opened without the VM lock: its point in time is not fixed under it")
	}
	if probe.atRead["data1.qcow2"] {
		t.Error("data1's export was read under the VM lock")
	}
	if !probe.atRead["root.qcow2"] {
		t.Error("the root's copy no longer runs under the VM lock, as before")
	}
}

// I4: a shut-off disk copied without the lock is kept only if, under the lock
// again, the file is unchanged and the VM still shut off.
//
// Mutation "no recheck": otherDiskCopy accepts the copy without comparing —
// red.
func TestOtherDiskCopy_AShutOffDiskThatChangedDuringTheCopyIsDiscarded(t *testing.T) {
	s := testServer(t)
	f := libvirtfake.New()
	s.virt = f
	f.SetState("od1", libvirtfake.StateShutdown)
	disk := filepath.Join(t.TempDir(), "data1.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	vm := &corrosion.VMRecord{Name: "od1", HostName: s.hostName, State: "stopped", Spec: `{}`}
	d := &corrosion.DiskRecord{VMName: "od1", DiskName: "data1", Path: disk, StorageType: "dir"}
	if err := corrosion.InsertVM(context.Background(), s.db, *vm, nil, []corrosion.DiskRecord{*d}); err != nil {
		t.Fatal(err)
	}
	takes := 0
	take := func() func() {
		takes++
		if takes == 2 { // the re-check: the disk was written meanwhile
			_ = os.Chtimes(disk, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
		}
		return func() {}
	}
	noop := func(*pb.MoveVolumeProgress) error { return nil }
	_, err := s.otherDiskCopy(context.Background(), take, vm, d, filepath.Join(t.TempDir(), "out.qcow2"), noop, true)
	if !errors.Is(err, errOtherDiskChanged) {
		t.Fatalf("copy of a disk written during the copy = %v, want errOtherDiskChanged", err)
	}
	takes = 10 // no change this time
	if _, err := s.otherDiskCopy(context.Background(), take, vm, d, filepath.Join(t.TempDir(), "out2.qcow2"), noop, true); err != nil {
		t.Fatalf("copy of an unchanged shut-off disk: %v", err)
	}
}
