package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// rr1Host is an upgrading host: an API-created dir pool vmpool holding this
// host's VM disk (qcow2), and the rows an rc6 daemon leaves behind.
func rr1Host(t *testing.T, withISOs bool, cfgPools []StoragePoolConfig) (*Daemon, string) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	vmDir := filepath.Join(root, "vm")
	for _, d := range []string{filepath.Join(data, "disks"), filepath.Join(data, "pools", "isos"), vmDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	disk := filepath.Join(vmDir, "vm1-root.qcow2")
	if err := os.WriteFile(disk, append([]byte{'Q', 'F', 'I', 0xfb}, make([]byte, 508)...), 0o600); err != nil {
		t.Fatal(err)
	}
	const host = "h1"
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: host, Name: "vmpool", Driver: "dir", Target: vmDir, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if withISOs {
		if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: host, Name: "isos", Driver: "dir",
			Target: filepath.Join(data, "pools", "isos"), Options: map[string]string{"content": "iso"}, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm1", HostName: host, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: host, Path: disk, StorageType: "dir", StorageVolume: "vmpool"}}); err != nil {
		t.Fatal(err)
	}
	return &Daemon{db: db, cfg: &Config{HostName: host, DataDir: data, PKIDir: filepath.Join(root, "pki"), StoragePools: cfgPools}}, vmDir
}

// (re-review rr1 A): the first start of the ledger build on a host with no storage_pools
// in config (the implicit default) adopts the pool holding its VM's disk.
func TestRR1Probe_AdoptionRunsWithTheImplicitDefault(t *testing.T) {
	d, _ := rr1Host(t, false, nil)
	d.openPoolTrust(context.Background())
	if e, ok := d.poolTrust.Entry("vmpool"); !ok || e.How != pooltrust.HowUpgrade {
		t.Fatalf("vmpool (this host's VM disk in it) was not adopted on upgrade: %+v %t", e, ok)
	}
}

// (re-review rr1 B): the first start on a host with config pools and the rc6 daemon's
// own isos row adopts the pool holding its VM's disk.
func TestRR1Probe_AdoptionRunsWithAnExistingISOLibraryRow(t *testing.T) {
	cfgDir := t.TempDir()
	d, _ := rr1Host(t, true, []StoragePoolConfig{{Name: "cfgpool", Driver: "dir", Target: cfgDir}})
	d.openPoolTrust(context.Background())
	if e, ok := d.poolTrust.Entry("vmpool"); !ok || e.How != pooltrust.HowUpgrade {
		t.Fatalf("vmpool (this host's VM disk in it) was not adopted on upgrade: %+v %t", e, ok)
	}
}

// (re-review rr1 C) (information): a forged "default" row (local, <data_dir>/disks) on a
// host whose implicit default is pools/default.
func TestRR1Probe_ForgedLegacyDefaultRow(t *testing.T) {
	ctx := context.Background()
	d, _ := rr1Host(t, false, nil)
	legacy := filepath.Join(d.cfg.DataDir, "disks")
	if err := corrosion.UpsertStoragePool(ctx, d.db, corrosion.StoragePoolRecord{HostName: "h1", Name: "default", Driver: "local", Target: legacy, State: "active"}); err != nil {
		t.Fatal(err)
	}
	d.openPoolTrust(ctx)
	e, ok := d.poolTrust.Entry("default")
	t.Logf("ledger default after a forged legacy default row: %+v %t", e, ok)
	if ok && e.Target != legacy && e.Target != filepath.Join(d.cfg.DataDir, "pools", "default") {
		t.Fatalf("default recorded outside the daemon's two default dirs: %+v", e)
	}
	// A forged default elsewhere is not recorded and not trusted.
	evil := t.TempDir()
	if err := corrosion.UpsertStoragePool(ctx, d.db, corrosion.StoragePoolRecord{HostName: "h1", Name: "default", Driver: "dir", Target: evil, State: "active"}); err != nil {
		t.Fatal(err)
	}
	d.openPoolTrust(ctx)
	rec, _, _ := corrosion.GetStoragePool(ctx, d.db, "h1", "default")
	if d.poolRowTrusted(rec) {
		t.Fatalf("a forged default row elsewhere is trusted: %+v", rec)
	}
	if e, _ := d.poolTrust.Entry("default"); e.Target == evil {
		t.Fatalf("a forged default row elsewhere was recorded: %+v", e)
	}
}

// (re-review rr1 N2) The rc6-shaped host the ruling names: no storage_pools
// in config, the rc6 daemon's isos row, and VM disks in an API-created pool.
// Its first start with the ledger adopts the pool, and still records the
// daemon's own pools; a second start adopts nothing more.
//
// Mutations: record the daemon's own pools before the adoption with a ledger
// that counts any write as adopted (the round-1 order and Initialised) —
// red; drop ensureOwnPoolsTrusted after the adoption — isos is not in the
// ledger, red.
func TestOpenPoolTrust_AnRC6HostAdoptsItsPools(t *testing.T) {
	d, vmDir := rr1Host(t, true, nil)
	ctx := context.Background()
	d.openPoolTrust(ctx)
	if e, ok := d.poolTrust.Entry("vmpool"); !ok || e.How != pooltrust.HowUpgrade || e.Target != vmDir {
		t.Fatalf("vmpool was not adopted on an rc6-shaped host: %+v %t", e, ok)
	}
	if e, ok := d.poolTrust.Entry("isos"); !ok || e.How != pooltrust.HowDaemon {
		t.Fatalf("the daemon's own isos row is not in the ledger: %+v %t", e, ok)
	}
	if !d.poolTrust.Initialised() {
		t.Fatal("the adoption ran but the store does not record it")
	}
}
