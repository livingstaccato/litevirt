// Fleet scenarios for cloning onto another host and into a pool there.
//
// Multi-node by construction: the clone is made where the source's disks are,
// its bytes then leave that daemon's disk and arrive on another's over real gRPC,
// the domain is defined on the target, and the staged copy is removed from the
// source. The nodes share one data-dir string, as real hosts do, and each is
// given its own filesystem root for disk files (SetHostDiskRootForTest), so a
// copy that moved nothing cannot pass.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

type cloneFleet struct {
	c               *Cluster
	entry, src, dst *Node
	tplDisk         string // the template's recorded disk path
}

func newCloneFleet(t *testing.T) *cloneFleet {
	t.Helper()
	c := New(t, Options{Nodes: 3, SharedCRDT: true, SharedDataDir: true})
	t.Cleanup(c.Stop)
	f := &cloneFleet{c: c, entry: c.Nodes[0], src: c.Nodes[1], dst: c.Nodes[2]}
	for _, n := range c.Nodes {
		n.Server.SetHostDiskRootForTest(f.root(n))
	}
	store := image.NewStore(filepath.Join(c.tmpRoot, "shared-data"))
	f.tplDisk = store.DiskPath("tpl", "root")
	hostPath := f.file(f.src, f.tplDisk)
	if err := mkdirAll(filepath.Dir(hostPath)); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(hostPath, 64<<20, nil); err != nil {
		t.Fatalf("create template disk: %v", err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), c.Nodes[0].DB, corrosion.VMRecord{
		Name: "tpl", HostName: f.src.Name, State: "stopped", IsTemplate: true, Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: "tpl", DiskName: "root", HostName: f.src.Name, Path: f.tplDisk, SizeBytes: 64 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatalf("InsertVM tpl: %v", err)
	}
	return f
}

func (f *cloneFleet) root(n *Node) string { return filepath.Join(f.c.tmpRoot, "fs-"+n.Name) }

// file is where node n keeps the disk file recorded at path.
func (f *cloneFleet) file(n *Node, path string) string { return filepath.Join(f.root(n), path) }

func (f *cloneFleet) clone(t *testing.T, req *pb.CloneVMRequest) (*pb.VM, error) {
	t.Helper()
	req.Source = "tpl"
	return f.c.SelfClient(f.entry).CloneVM(context.Background(), req)
}

func (f *cloneFleet) vm(t *testing.T, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), f.entry.DB, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM %s: %v %v", name, vm, err)
	}
	return vm
}

// A clone made on another host ends up there: the row, the disk row and the
// domain name the target, the bytes are on the target and no longer on the
// source, which keeps only the template.
//
// Mutation: drop the finishCrossHostClone call in CloneVM — the clone stays on
// the source and the host assertion fails.
func TestFleet_Clone_ToAnotherHost(t *testing.T) {
	f := newCloneFleet(t)
	vm, err := f.clone(t, &pb.CloneVMRequest{Target: "c1", DestinationHost: f.dst.Name})
	if err != nil {
		t.Fatalf("clone to another host: %v", err)
	}
	if vm.HostName != f.dst.Name {
		t.Fatalf("clone reports host %q, want %q", vm.HostName, f.dst.Name)
	}
	rec := f.vm(t, "c1")
	if rec.HostName != f.dst.Name || rec.State != "stopped" {
		t.Fatalf("clone row = host %s state %s, want %s stopped", rec.HostName, rec.State, f.dst.Name)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.entry.DB, "c1")
	if len(disks) != 1 || disks[0].HostName != f.dst.Name || disks[0].BackingDisk != "" {
		t.Fatalf("clone disk rows = %+v, want one standalone disk on %s", disks, f.dst.Name)
	}
	info, ierr := qcow2.Info(f.file(f.dst, disks[0].Path))
	if ierr != nil || info.VirtualSize != 64<<20 {
		t.Fatalf("the clone's disk is not on %s as a 64 MiB qcow2: %v %+v", f.dst.Name, ierr, info)
	}
	if _, err := os.Stat(f.file(f.src, disks[0].Path)); !os.IsNotExist(err) {
		t.Errorf("the staged copy is still on the source host (stat err %v)", err)
	}
	if !f.dst.Virt.DomainExists("c1") {
		t.Errorf("no domain for the clone on %s", f.dst.Name)
	}
	if f.src.Virt.DomainExists("c1") {
		t.Errorf("the source host still has the staged domain")
	}
	if _, err := os.Stat(f.file(f.src, f.tplDisk)); err != nil {
		t.Errorf("the template's disk was disturbed: %v", err)
	}
	if tpl := f.vm(t, "tpl"); tpl.HostName != f.src.Name || !tpl.IsTemplate {
		t.Errorf("template row changed: %+v", tpl)
	}
}

// --start starts it on the target.
func TestFleet_Clone_ToAnotherHostAndStart(t *testing.T) {
	f := newCloneFleet(t)
	if _, err := f.clone(t, &pb.CloneVMRequest{Target: "c2", DestinationHost: f.dst.Name, Start: true}); err != nil {
		t.Fatalf("clone: %v", err)
	}
	if rec := f.vm(t, "c2"); rec.HostName != f.dst.Name || rec.State != "running" {
		t.Fatalf("clone row = host %s state %s, want %s running", rec.HostName, rec.State, f.dst.Name)
	}
	if active, _ := f.dst.Virt.DomainIsActive("c2"); !active {
		t.Errorf("the clone is not running on %s", f.dst.Name)
	}
	if f.src.Virt.DomainExists("c2") {
		t.Errorf("the source host has a domain for it")
	}
}

// A target that will not take the disk (a file it did not make is already at
// the path) leaves NOTHING behind: the staged copy on the source host is
// removed (row, disk file, domain), the target's own file is untouched, and the
// error says the copy was removed.
//
// Mutation: skip the DeleteVM cleanup in finishCrossHostClone - the staged
// clone, a full disk on the source filesystem, stays.
func TestFleet_Clone_FailedMoveRemovesTheStagedCopy(t *testing.T) {
	f := newCloneFleet(t)
	store := image.NewStore(filepath.Join(f.c.tmpRoot, "shared-data"))
	blocker := f.file(f.dst, store.DiskPath("c3", "root"))
	if err := mkdirAll(filepath.Dir(blocker)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocker, []byte("not made by this clone"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A schedule added ahead for the clone's name stays, as it did: the
	// removal of the staged copy is not a delete of a VM the schedule served
	// (here the source host runs the clone as a peer's forward; see
	// TestFleet_Clone_FailedMoveEnteredOnTheSourceKeepsAScheduleAddedAhead).
	for _, n := range []*Node{f.entry, f.src} {
		if err := corrosion.UpsertBackupSchedule(context.Background(), n.DB, corrosion.BackupScheduleRecord{
			VMName: "c3", Repo: "main", Cron: "0 4 * * *", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}

	_, err := f.clone(t, &pb.CloneVMRequest{Target: "c3", DestinationHost: f.dst.Name})
	if err == nil {
		t.Fatal("the clone claimed success although the target refused the disk")
	}
	for _, n := range []*Node{f.entry, f.src} {
		if got := schedulesOn(t, n); got != "c3/main" {
			t.Errorf("schedules on %s after the failed clone = %q, want c3/main kept", n.Name, got)
		}
	}
	for _, want := range []string{"could not be cloned onto " + f.dst.Name, "staged copy on " + f.src.Name + " was removed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if vm, _ := corrosion.GetVM(context.Background(), f.entry.DB, "c3"); vm != nil {
		t.Errorf("the staged VM row is still there: host %s state %s", vm.HostName, vm.State)
	}
	if _, err := os.Stat(f.file(f.src, store.DiskPath("c3", "root"))); !os.IsNotExist(err) {
		t.Errorf("the staged disk is still on the source host (stat err %v)", err)
	}
	if f.src.Virt.DomainExists("c3") {
		t.Errorf("the staged domain is still defined on the source host")
	}
	if b, _ := os.ReadFile(blocker); string(b) != "not made by this clone" {
		t.Errorf("the file the target already had was overwritten: %q", b)
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), f.entry.DB, "c3", 20, "")
	staged := false
	for _, e := range evs {
		staged = staged || e.Type == "vm.clone.staged"
	}
	if !staged {
		t.Errorf("no vm.clone.staged event names where the clone was going")
	}
}

// Refusals before anything is made.
func TestFleet_Clone_ToAnotherHostRefusals(t *testing.T) {
	f := newCloneFleet(t)
	if _, err := f.clone(t, &pb.CloneVMRequest{Target: "c4", DestinationHost: "nowhere"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown host = %v, want NotFound", err)
	}
	if _, err := f.clone(t, &pb.CloneVMRequest{Target: "c4", DestinationHost: f.dst.Name, Mode: "linked"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("linked on another host = %v, want InvalidArgument", err)
	}
	if err := corrosion.UpdateHostState(context.Background(), f.entry.DB, f.dst.Name, "draining"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.clone(t, &pb.CloneVMRequest{Target: "c4", DestinationHost: f.dst.Name}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("draining host = %v, want FailedPrecondition", err)
	}
	if vm, _ := corrosion.GetVM(context.Background(), f.entry.DB, "c4"); vm != nil {
		t.Errorf("a refused clone left a VM row")
	}
}

// A pool on the target host takes the clone's disk after the move, and the disk
// row records the pool. (MoveVolume removes the old file by its recorded path,
// which the per-node file roots of this harness do not map, so that removal is
// not asserted here.)
//
// Mutation: drop the MoveVolume loop in finishCrossHostClone — the disk row
// stays in the default directory with no pool.
func TestFleet_Clone_ToAnotherHostIntoItsPool(t *testing.T) {
	f := newCloneFleet(t)
	poolDir := filepath.Join(f.c.tmpRoot, "pools", "ssd")
	if err := mkdirAll(poolDir); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(context.Background(), f.entry.DB, corrosion.StoragePoolRecord{
		HostName: f.dst.Name, Name: "ssd", Driver: "dir", Target: poolDir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	// The daemon seeds this from config and the replicated table at start.
	f.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"ssd": {Driver: "dir", Target: poolDir}})

	if _, err := f.clone(t, &pb.CloneVMRequest{Target: "c5", DestinationHost: f.dst.Name, TargetPool: "ssd"}); err != nil {
		t.Fatalf("clone into a pool on another host: %v", err)
	}
	rec := f.vm(t, "c5")
	disks, _ := corrosion.GetVMDisks(context.Background(), f.entry.DB, "c5")
	if rec.HostName != f.dst.Name || len(disks) != 1 {
		t.Fatalf("clone = host %s, %d disk rows", rec.HostName, len(disks))
	}
	d := disks[0]
	if d.StorageVolume != "ssd" || d.StorageType != "dir" || d.HostName != f.dst.Name || filepath.Dir(d.Path) != poolDir {
		t.Fatalf("disk row = %+v, want it in pool ssd under %s on %s", d, poolDir, f.dst.Name)
	}
	if _, err := qcow2.Info(d.Path); err != nil {
		t.Errorf("no qcow2 at the pool path %s: %v", d.Path, err)
	}
}

// A source on an older release ignores destination_host and makes a plain
// same-host clone, answering success. The entry node, which asked for another
// host, says so instead of reporting a clone that is not where it was asked for.
//
// Mutation: drop the host comparison after the forward in CloneVM - the call
// succeeds and the clone sits on the source host.
func TestFleet_Clone_ASourceThatIgnoresTheDestinationIsReported(t *testing.T) {
	f := newCloneFleet(t)
	f.src.Server.SetCloneAsOlderBuildForTest(true)
	_, err := f.clone(t, &pb.CloneVMRequest{Target: "old1", DestinationHost: f.dst.Name})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "older release") ||
		!strings.Contains(err.Error(), "lv migrate old1 "+f.dst.Name+" --cold") {
		t.Fatalf("clone through an older source = %v, want FailedPrecondition naming the older release and the way out", err)
	}
}

// The rest of the same gap (re-review m6): a source on an older release also
// ignores target_pool, so a clone into a pool on the source's own host — named
// alone, or with destination_host equal to the source's host — is made in the
// default directory and answered with success. The entry node reads the clone's
// disks back and says so. A clone this release does make in the pool, through
// the same forward, is not refused.
//
// Mutation: drop the pool comparison in cloneTargetIgnored - both older-source
// clones succeed with their disks outside the pool.
func TestFleet_Clone_ASourceThatIgnoresThePoolIsReported(t *testing.T) {
	f := newCloneFleet(t)
	poolDir := filepath.Join(f.c.tmpRoot, "pools", "src-ssd")
	for _, d := range []string{poolDir, f.file(f.src, poolDir)} {
		if err := mkdirAll(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpsertStoragePool(context.Background(), f.entry.DB, corrosion.StoragePoolRecord{
		HostName: f.src.Name, Name: "ssd", Driver: "dir", Target: poolDir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	f.src.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"ssd": {Driver: "dir", Target: poolDir}})

	vm, err := f.clone(t, &pb.CloneVMRequest{Target: "inpool", TargetPool: "ssd"})
	if err != nil {
		t.Fatalf("a pool clone this release makes, through the forward: %v", err)
	}
	if len(vm.GetDisks()) != 1 || vm.GetDisks()[0].GetStorageVolume() != "ssd" {
		t.Fatalf("the clone's disks = %+v, want one in pool ssd", vm.GetDisks())
	}

	f.src.Server.SetCloneAsOlderBuildForTest(true)
	for _, req := range []*pb.CloneVMRequest{
		{Target: "old2", TargetPool: "ssd"},
		{Target: "old3", TargetPool: "ssd", DestinationHost: f.src.Name},
	} {
		_, err := f.clone(t, req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "older release that ignores target_pool") ||
			!strings.Contains(err.Error(), "lv move-volume "+req.Target+" root ssd") {
			t.Errorf("clone %s (destination %q) through an older source = %v, want FailedPrecondition naming the older release and `lv move-volume`",
				req.Target, req.DestinationHost, err)
		}
		// The clone exists; the refusal is on its events too.
		evs, _ := corrosion.ListVMEvents(context.Background(), f.entry.DB, req.Target, 20, "")
		found := false
		for _, e := range evs {
			found = found || (e.Type == "vm.clone" && strings.Contains(e.Detail, "ignores target_pool"))
		}
		if !found {
			t.Errorf("the refusal of %s is not on its events: %+v", req.Target, evs)
		}
	}
}

// The failed move of a clone entered on the source host itself: its cleanup
// is that host's own DeleteVM, which keeps a schedule added ahead for the
// clone's name, as it always did.
//
// Mutation: drop withSchedulesKept from the cleanup's DeleteVM - red.
func TestFleet_Clone_FailedMoveEnteredOnTheSourceKeepsAScheduleAddedAhead(t *testing.T) {
	f := newCloneFleet(t)
	store := image.NewStore(filepath.Join(f.c.tmpRoot, "shared-data"))
	blocker := f.file(f.dst, store.DiskPath("c4", "root"))
	if err := mkdirAll(filepath.Dir(blocker)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocker, []byte("not made by this clone"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertBackupSchedule(context.Background(), f.src.DB, corrosion.BackupScheduleRecord{
		VMName: "c4", Repo: "main", Cron: "0 4 * * *", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, err := f.c.SelfClient(f.src).CloneVM(context.Background(), &pb.CloneVMRequest{Source: "tpl", Target: "c4", DestinationHost: f.dst.Name})
	if err == nil || !strings.Contains(err.Error(), "staged copy on "+f.src.Name+" was removed") {
		t.Fatalf("premise: the clone's move did not fail and remove its staged copy: %v", err)
	}
	if got := schedulesOn(t, f.src); got != "c4/main" {
		t.Errorf("schedules on %s after the failed clone = %q, want c4/main kept", f.src.Name, got)
	}
}
