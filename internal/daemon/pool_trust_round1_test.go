package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// (review r0 I3) The daemon's own pools — the implicit default pool and the
// global ISO library — are recorded in the ledger as the daemon writes them,
// so they are trusted whatever <data_dir>/pools resolves to, and the
// "default" row is a config pool of the implicit config. A forged isos row at
// a place the daemon would not use is not recorded.
//
// Mutations: drop ensureOwnPoolTrusted from registerStoragePools and
// openPoolTrust — the default entry is missing, red; drop it from
// ensureGlobalISOLibrary — the isos entry is missing, red; record any isos
// row (skip isDaemonISOLibraryRow) — the forged one is recorded, red.
func TestOpenPoolTrust_DaemonsOwnPoolsAreRecorded(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	big := filepath.Join(root, "bigdisk", "pools")
	for _, d := range []string{filepath.Join(data, "disks"), big} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(big, filepath.Join(data, "pools")); err != nil {
		t.Fatal(err)
	}
	newDB := func() *corrosion.Client {
		db := corrosion.NewTestClientT(t)
		if err := corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		return db
	}
	db := newDB()
	d := &Daemon{db: db, cfg: &Config{HostName: "h1", DataDir: data, PKIDir: filepath.Join(root, "pki")}}
	d.openPoolTrust(ctx)
	d.registerStoragePools(ctx)
	for _, name := range []string{"default", "isos"} {
		e, ok := d.poolTrust.Entry(name)
		if !ok || e.How != pooltrust.HowDaemon {
			t.Errorf("the daemon's own %s pool is not in the ledger: %+v %t", name, e, ok)
		}
		rec, found, _ := corrosion.GetStoragePool(ctx, db, "h1", name)
		if !found || !d.poolRowTrusted(rec) {
			t.Errorf("the daemon's own %s row is untrusted: %+v found=%t", name, rec, found)
		}
	}
	// The implicit default is a config pool under the name its row has.
	rec, _, _ := corrosion.GetStoragePool(ctx, db, "h1", "default")
	if v := d.poolTrust.Judge("default", pooltrust.BindingOf(rec.Driver, rec.Source, rec.Target, rec.Options)); v.Why != pooltrust.TrustConfig {
		t.Errorf("the implicit default row is trusted as %q, want as the config pool", v.Why)
	}

	// A host whose isos row was forged elsewhere before this start.
	root2 := t.TempDir()
	data2 := filepath.Join(root2, "data")
	if err := os.MkdirAll(filepath.Join(data2, "disks"), 0o755); err != nil {
		t.Fatal(err)
	}
	db2 := newDB()
	if err := corrosion.UpsertStoragePool(ctx, db2, corrosion.StoragePoolRecord{
		HostName: "h1", Name: "isos", Driver: "dir", Target: filepath.Join(root2, "srv", "pools", "isos"), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	d2 := &Daemon{db: db2, cfg: &Config{HostName: "h1", DataDir: data2, PKIDir: filepath.Join(root2, "pki")}}
	d2.openPoolTrust(ctx)
	d2.registerStoragePools(ctx)
	if _, ok := d2.poolTrust.Entry("isos"); ok {
		t.Error("a forged isos row was recorded as the daemon's own")
	}
}
