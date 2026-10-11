package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// insertCephVMDisks records a stopped VM on this host with n rbd data disks
// of the fixture's pool.
func (f *cephPoolFixture) insertCephVMDisks(t *testing.T, name string, n int) corrosion.VMRecord {
	t.Helper()
	var disks []corrosion.DiskRecord
	f.world.mu.Lock()
	for i := 0; i < n; i++ {
		d := "d" + string(rune('a'+i))
		f.world.images["lv/"+name+"-"+d] = map[string]bool{}
		disks = append(disks, corrosion.DiskRecord{
			VMName: name, DiskName: d, HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph",
			Path: "rbd:lv/" + name + "-" + d + ":id=litevirt:keyring=" + f.keyring + ":lvpool=ceph", DeleteWithVM: true,
		})
	}
	f.world.mu.Unlock()
	vm := corrosion.VMRecord{Name: name, HostName: "test-host", State: "stopped", Spec: `{"name":"` + name + `","cpu":1,"memory_mib":256}`}
	if err := corrosion.InsertVM(context.Background(), f.s.db, vm, nil, disks); err != nil {
		t.Fatal(err)
	}
	return vm
}

func (w *cephWorld) probes() int { return w.count("info") }

// I-R3-2. A VM's disks are probed concurrently, under ONE ProbeBound, and the
// budget is checked once for the VM. A three-disk VM whose probes each take
// 2.5 s (Ceph slow while a failover's mons re-elect) starts inside a walk
// with 9.5 s left: probed one after another, its second disk found less than
// 8 s left and the VM was deferred on every pass.
func TestPrepareHardwareForStart_ThreeSlowDisksComplete(t *testing.T) {
	f := newCephPoolFixture(t)
	vm := f.insertCephVMDisks(t, "slow", 3)
	f.world.infoDelay = 2500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 9500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := f.s.PrepareHardwareForStart(ctx, &vm); err != nil {
		t.Fatalf("a three-disk VM with slow probes did not start: %v", err)
	}
	if n := f.world.probes(); n != 3 {
		t.Fatalf("%d probes, want one per disk", n)
	}
	if el := time.Since(start); el > 6*time.Second {
		t.Fatalf("the probes took %v: they ran one after another", el)
	}
}

// I-R3-2. A key proven to open a pool's images is remembered for a short
// while per (pool, client, key fingerprint): the next VM on that pool needs
// no probe, so a failover's later VMs are not deferred for want of time to
// prove what was just proven. A rotated key is a new fingerprint and is
// proven again; so is one whose proof has aged out.
func TestPrepareHardwareForStart_KeyProofIsCached(t *testing.T) {
	f := newCephPoolFixture(t)
	a := f.insertCephVMDisks(t, "pa", 1)
	b := f.insertCephVMDisks(t, "pb", 2)
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &a); err != nil {
		t.Fatal(err)
	}
	if f.world.probes() != 1 {
		t.Fatalf("first start: %d probes, want 1", f.world.probes())
	}
	short := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := f.s.PrepareHardwareForStart(ctx, &b)
		return err
	}
	if err := short(); err != nil || f.world.probes() != 1 {
		t.Fatalf("start with 1 s left after a proof: err %v, probes %d; want it started on the remembered proof", err, f.world.probes())
	}

	// A rotated key has not been proven.
	writeKeyring(t, f.keyring, []byte("another-restricted-key-bytes"))
	if err := short(); !errors.Is(err, health.ErrStartDeferred) || f.world.probes() != 1 {
		t.Fatalf("rotated key with 1 s left: err %v, probes %d; want a deferral and no probe", err, f.world.probes())
	}
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &b); err != nil || f.world.probes() != 3 {
		t.Fatalf("rotated key: err %v, probes %d; want both disks proven again", err, f.world.probes())
	}

	// An aged-out proof is proven again.
	defer func(prev func() time.Time) { cephProofNow = prev }(cephProofNow)
	cephProofNow = func() time.Time { return time.Now().Add(cephKeyProofTTL + time.Second) }
	if err := short(); !errors.Is(err, health.ErrStartDeferred) {
		t.Fatalf("aged-out proof with 1 s left: %v, want a deferral", err)
	}
}

// I-R3-1. A transient Ceph failure (or a probe there is no time for) is a
// DEFERRAL the reconciler re-drives — never a failure that parks a proof-less
// start in error. It is still Unavailable to a gRPC caller. A failure an
// operator must fix stays a FailedPrecondition, and is no deferral.
func TestPrepareHardwareForStart_TransientCephIsADeferral(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exit     int
		out      string
		code     codes.Code
		deferred bool
	}{
		{"ETIMEDOUT", 110, "rbd: couldn't connect to the cluster!", codes.Unavailable, true},
		{"EPERM", 1, "rbd: error opening image x: (1) Operation not permitted", codes.FailedPrecondition, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCephPoolFixture(t)
			vm := f.insertCephVM(t, "td", "test-host")
			f.world.infoExit, f.world.infoOut = tc.exit, tc.out
			_, err := f.s.PrepareHardwareForStart(context.Background(), &vm)
			if status.Code(err) != tc.code || errors.Is(err, health.ErrStartDeferred) != tc.deferred {
				t.Fatalf("got %v (code %v, deferred %v), want %v deferred %v", err, status.Code(err), errors.Is(err, health.ErrStartDeferred), tc.code, tc.deferred)
			}
		})
	}
	// No time left for a probe: deferred, before rbd is run at all.
	f := newCephPoolFixture(t)
	vm := f.insertCephVM(t, "nt", "test-host")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := f.s.PrepareHardwareForStart(ctx, &vm); !errors.Is(err, health.ErrStartDeferred) || status.Code(err) != codes.Unavailable || f.world.probes() != 0 {
		t.Fatalf("2 s left: %v, %d probes; want an Unavailable deferral and no rbd", err, f.world.probes())
	}
}

// I-R3-2. The reconciler asks, before it does anything for a VM (lock,
// claim, define), whether its start would be deferred for want of time: a VM
// with an unproven ceph key and less than ProbeBound left is; a VM whose key
// was just proven, or with no ceph disk, is not.
func TestCephStartDeferral_DecidedBeforeAnyWork(t *testing.T) {
	f := newCephPoolFixture(t)
	vm := f.insertCephVM(t, "sd", "test-host")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := f.s.CephStartDeferral(ctx, &vm); !errors.Is(err, health.ErrStartDeferred) || f.world.probes() != 0 {
		t.Fatalf("unproven key, 2 s left: %v (%d probes); want a deferral, no rbd", err, f.world.probes())
	}
	if err := f.s.CephStartDeferral(context.Background(), &vm); err != nil {
		t.Fatalf("no deadline: %v", err)
	}
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &vm); err != nil {
		t.Fatal(err)
	}
	if err := f.s.CephStartDeferral(ctx, &vm); err != nil {
		t.Fatalf("a proven key with 2 s left: %v, want no deferral", err)
	}
	plain := corrosion.VMRecord{Name: "plain", HostName: "test-host", State: "stopped"}
	if err := corrosion.InsertVM(context.Background(), f.s.db, plain, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.s.CephStartDeferral(ctx, &plain); err != nil {
		t.Fatalf("a VM with no ceph disk: %v", err)
	}
}

// m3. A start's monitor refresh runs only where there is libvirt to ask.
func TestRefreshRBDMonitors_WithoutLibvirt(t *testing.T) {
	s := testServer(t)
	s.virt = nil
	ctx := context.Background()
	insertTestVM(t, ctx, s.db, "nv", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "nv", DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph",
		Path: "rbd:lv/nv-data:id=litevirt:keyring=/k:lvpool=ceph",
	}); err != nil {
		t.Fatal(err)
	}
	s.refreshRBDMonitors(ctx, "nv") // must not panic
}

// m3. A main-era rbd disk (no keyring, no lvpool: the branch leaves it as it
// was everywhere else) is not given <host> elements on a start.
func TestRefreshRBDMonitors_LeavesMainEraDisksAlone(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	conf := filepath.Join(t.TempDir(), "cluster.conf")
	if err := os.WriteFile(conf, []byte("[global]\nmon_host = 10.78.0.22:6789\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	insertTestVM(t, ctx, f.s.db, "old", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, f.s.db, corrosion.DiskRecord{
		VMName: "old", DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph",
		Path: "rbd:lv/old-data:conf=" + conf,
	}); err != nil {
		t.Fatal(err)
	}
	x := `<domain type='kvm'><name>old</name><devices><disk type='network' device='disk'><driver name='qemu' type='raw'/><source protocol='rbd' name='lv/old-data'/><target dev='vda' bus='virtio'/></disk></devices></domain>`
	if err := f.fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	f.s.refreshRBDMonitors(ctx, "old")
	if got, _ := f.fake.DumpXMLInactive("old"); strings.Contains(got, "<host") {
		t.Fatalf("a main-era rbd disk was given monitors:\n%s", got)
	}
}

// I-R3-3. An image in the trash that this host cannot purge is named by a
// health condition — the pool, the trash id, the image it was and the error —
// and the condition resolves once the purge succeeds.
func TestCephTrashLeftover_NamedUntilPurged(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	f.insertCephVM(t, "gone", "test-host")
	f.s.deleteRecordedVMDiskVolumes(ctx, "gone")
	if f.world.has("lv/gone-data") || len(f.world.trash) != 1 {
		t.Fatalf("not moved to the trash: %v", f.world.calls)
	}
	f.world.trashRmExit = 110
	storage.RunCephPurgesOnceForTest()
	f.s.ReconcileCephSecrets(ctx)
	c, ok, err := corrosion.GetHealthCondition(ctx, f.s.db, cephPoolEvaluator, condCephTrashLeftover, "host", "test-host")
	if err != nil || !ok || c.Lifecycle == corrosion.ConditionResolved || !strings.Contains(c.Evidence, "gone-data") ||
		!strings.Contains(c.Evidence, "rbd trash rm lv/") || !strings.Contains(c.Evidence, "110") {
		t.Fatalf("condition %+v, %v, %v; want an open one naming the leftover and how to purge it", c, ok, err)
	}
	f.world.trashRmExit = 0
	storage.RunCephPurgesOnceForTest()
	f.s.ReconcileCephSecrets(ctx)
	if c, _, _ := corrosion.GetHealthCondition(ctx, f.s.db, cephPoolEvaluator, condCephTrashLeftover, "host", "test-host"); c.Lifecycle != corrosion.ConditionResolved || len(f.world.trash) != 0 {
		t.Fatalf("after the purge: condition %+v, trash %v; want resolved and empty", c, f.world.trash)
	}
}
