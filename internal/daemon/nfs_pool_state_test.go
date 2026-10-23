package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pooltrust"
	"github.com/litevirt/litevirt/internal/storage"
)

// An nfs pool's state is its mount's: the periodic registration of config
// pools and the capacity refresh keep the degraded the mount reconcile
// recorded (grpcapi.ReconcileNFSMounts) — an unmounted mount point is an
// empty local directory, which statfs measures happily — and a new pool is
// registered active.
func TestRegisterStoragePools_KeepsAnNFSPoolsMountState(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	target := t.TempDir() // an unmounted mount point: a local directory
	pools := []StoragePoolConfig{
		{Name: "shared", Driver: "nfs", Source: "10.0.0.21:/srv/lv", Target: target},
		{Name: "shared2", Driver: "nfs", Source: "10.0.0.21:/srv/lv2", Target: t.TempDir()},
	}
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "host-a", Name: "shared", Driver: "nfs", Source: pools[0].Source, Target: target, State: grpcapi.PoolStateDegraded,
	}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "host-a", DataDir: dataDir, StoragePools: pools}}
	check := func(when string) {
		t.Helper()
		for name, want := range map[string]string{"shared": grpcapi.PoolStateDegraded, "shared2": "active"} {
			rec, ok, err := corrosion.GetStoragePool(ctx, db, "host-a", name)
			if err != nil || !ok || rec.State != want {
				t.Fatalf("%s: pool %s: %+v found=%v err=%v; want state %q", when, name, rec, ok, err, want)
			}
		}
	}
	d.registerStoragePools(ctx)
	check("after registration")
	d.refreshDBPoolCapacity(ctx)
	check("after the capacity refresh")
}

// The daemon's mount loop makes its first pass at once, not a ticker later:
// after a reboot the export is mounted as soon as the daemon is up.
func TestRunNFSMountReconcile_FirstPassAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "host-a", Name: "shared", Driver: "nfs", Source: "10.0.0.21:/srv/lv", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	mounts := make(chan string, 4)
	t.Cleanup(storage.OverrideNosymfollowSupportForTest(false))
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"), nil
	}))
	t.Cleanup(storage.OverrideNFSMountCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "mount" {
			mounts <- args[len(args)-1]
			return nil, errors.New("exit status 32")
		}
		return nil, exit32{}
	}))
	dir := t.TempDir()
	d := &Daemon{db: db, cfg: &Config{HostName: "host-a", DataDir: dir}, svc: grpcapi.NewServer("host-a", dir, dir, db, nil, nil)}
	// The pool was created on this host: an nfs pool, target or not, is
	// acted on only when its host stands behind it (pooltrust).
	if err := d.svc.PoolTrust().Record("shared", pooltrust.BindingOf("nfs", "10.0.0.21:/srv/lv", "", nil), pooltrust.HowCreate); err != nil {
		t.Fatal(err)
	}
	go d.runNFSMountReconcile(ctx)
	select {
	case got := <-mounts:
		if want := filepath.Join(dir, "mounts", "10.0.0.21__srv_lv"); got != want {
			t.Fatalf("mounted at %s, want %s", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no mount within 5s of the loop's start")
	}
}

type exit32 struct{}

func (exit32) Error() string { return "exit status 32" }
func (exit32) ExitCode() int { return 32 }
