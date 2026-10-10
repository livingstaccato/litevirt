package daemon

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

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
	static, dynamic := d.storeDenyStatic(), d.storeDenyDynamic()
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
	// A store list that cannot be read denies everything.
	db.Close()
	if got := d.storeDenyDynamic(); !slices.Equal(got, []string{"/"}) {
		t.Errorf("a failed read denied %v; want everything (\"/\")", got)
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
	if why := d.vmDiskBlockInUse(8, 16); why == "" {
		t.Error("an unreadable VM disk list passed a block device")
	}
}
