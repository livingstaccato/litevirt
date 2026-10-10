package daemon

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// N3. Every store this host serves is a protected tree for container host
// mounts: data_dir and pki_dir, every pool path, every backup repo, the image
// and disk stores and the restore cache.
func TestStoreDeny_EveryStoreThisHostServes(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "h1", DataDir: "/var/lib/litevirt", BackupRepos: map[string]string{"nightly": "/srv/backups/nightly"}}}
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: "h1", Name: "fast", Driver: "dir", Source: "/dev/vg0", Target: "/srv/pools/fast"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: "h2", Name: "other", Driver: "dir", Target: "/srv/pools/other"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertBackupRepo(ctx, db, corrosion.BackupRepo{Name: "stackrepo", Path: "/srv/backups/stack"}); err != nil {
		t.Fatal(err)
	}
	static := d.storeDenyStatic()
	dynamic, err := d.storeDenyDynamic()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/var/lib/litevirt/images", "/var/lib/litevirt/disks", "/var/lib/litevirt/ct-restore", "/srv/backups/nightly"} {
		if !slices.Contains(static, want) {
			t.Errorf("static deny list %v lacks %s", static, want)
		}
	}
	for _, want := range []string{"/srv/pools/fast", "/dev/vg0", "/srv/backups/stack"} {
		if !slices.Contains(dynamic, want) {
			t.Errorf("dynamic deny list %v lacks %s", dynamic, want)
		}
	}
	if slices.Contains(dynamic, "/srv/pools/other") {
		t.Errorf("another host's pool %v is not this host's store", dynamic)
	}
	// A store list that cannot be read is an error, never a shorter list: the
	// resolve refuses every mount on it (and a refresh keeps the policy it
	// last wrote, m-2).
	db.Close()
	if got, err := d.storeDenyDynamic(); err == nil {
		t.Errorf("a failed read returned %v and no error", got)
	}
}

// N4. A block device that is a VM disk on this host is compared by number,
// whatever path names it.
func TestVMDiskBlockInUse_ByNumber(t *testing.T) {
	disks := map[string]string{"/dev/disk/by-id/vm1-root": "vm1", filepath.Join("/var/lib/litevirt/disks", "vm2.qcow2"): "vm2"}
	number := func(p string) (uint32, uint32, bool) {
		if p == "/dev/disk/by-id/vm1-root" {
			return 8, 16, true
		}
		return 0, 0, false
	}
	if why := diskWithNumber(disks, 8, 16, number); why == "" {
		t.Error("a VM's disk by another name was not found")
	}
	if why := diskWithNumber(disks, 8, 32, number); why != "" {
		t.Errorf("an unrelated device was named as a VM disk: %s", why)
	}
	db := corrosion.NewTestClientT(t)
	d := &Daemon{db: db, cfg: &Config{HostName: "h1"}}
	db.Close()
	if why, err := d.vmDiskBlockInUse(8, 16); err == nil {
		t.Errorf("an unreadable VM disk list returned %q and no error", why)
	}
}

// m-3. A VM disk anywhere in the cluster is matched, not only this host's:
// on shared storage a LUN backing a VM on another host is visible here under
// some path, and is that VM's disk by number.
func TestVMDiskBlockInUse_ClusterWide(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "far", HostName: "h2", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "far", DiskName: "root", HostName: "h2", Path: "/dev/disk/by-path/ip-10.0.0.9-lun-3", StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	old := blockNumber
	t.Cleanup(func() { blockNumber = old })
	blockNumber = func(p string) (uint32, uint32, bool) {
		if p == "/dev/disk/by-path/ip-10.0.0.9-lun-3" {
			return 8, 112, true
		}
		return 0, 0, false
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "h1"}}
	if why, _ := d.vmDiskBlockInUse(8, 112); why == "" {
		t.Error("a LUN backing a VM on another host passed as unused")
	}
}

type countingRefresher struct{ n chan struct{} }

func (c countingRefresher) RefreshHookPolicies() error { c.n <- struct{}{}; return nil }

// m-5. The daemon rewrites every container's start-hook policy as soon as it
// starts, not only at the next container start or tick.
func TestRefreshHookPolicies_RunsAtStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := countingRefresher{n: make(chan struct{}, 4)}
	done := make(chan struct{})
	go func() { refreshHookPolicies(ctx, r); close(done) }()
	select {
	case <-r.n:
	case <-time.After(5 * time.Second):
		t.Fatal("the hook policies were not refreshed at daemon start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh loop did not stop with its context")
	}
}

// m-6. A bind_mount_paths prefix that shares a filesystem with a protected
// tree loads (it did before identity was checked) and is reported: a warning
// condition about this host, naming the overlap, resolved once the config no
// longer has one.
func TestNoteHostAccessOverlaps_RaisesAndResolvesACondition(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "h1"}}
	d.noteHostAccessOverlaps(ctx, []string{"/srv/share shares a filesystem with the protected tree /var/lib/litevirt"})
	row, found, err := corrosion.GetHealthCondition(ctx, db, hostAccessEvaluator, CondHostAccessPrefixOverlap, "host", "h1")
	if err != nil || !found || row.Lifecycle != corrosion.ConditionConfirmed || row.Severity != corrosion.SeverityWarning ||
		!strings.Contains(row.Evidence, "/var/lib/litevirt") {
		t.Fatalf("condition = %+v (found %v, %v); want a confirmed warning naming the overlap", row, found, err)
	}
	d.noteHostAccessOverlaps(ctx, nil)
	if row, _, _ := corrosion.GetHealthCondition(ctx, db, hostAccessEvaluator, CondHostAccessPrefixOverlap, "host", "h1"); row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("condition after the overlap is gone = %+v; want resolved", row)
	}
}
