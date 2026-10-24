package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// A fresh install whose config.yaml defines nfs pools (one with no target,
// one with a target outside the data dir): both rows are trusted by config,
// with no ledger entry.
func TestRR3Probe_FreshInstallConfigNFSPools(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	ext := filepath.Join(root, "mnt", "ext")
	if err := os.MkdirAll(ext, 0o755); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "h1", DataDir: data, PKIDir: filepath.Join(root, "pki"),
		StoragePools: []StoragePoolConfig{
			{Name: "nas", Driver: "nfs", Source: "srv:/x", Options: map[string]string{"options": "vers=4.2"}},
			{Name: "nasext", Driver: "nfs", Source: "srv:/y", Target: ext},
		}}}
	d.openPoolTrust(ctx)
	d.registerStoragePools(ctx)
	rows, err := corrosion.ListStoragePoolsForHost(ctx, db, "h1")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		b := pooltrust.BindingOf(r.Driver, r.Source, r.Target, r.Options)
		v := d.poolTrust.Judge(r.Name, b)
		_, inLedger := d.poolTrust.Entry(r.Name)
		t.Logf("%-8s driver=%s target=%q opts=%v trusted=%t why=%q ledger=%t config=%t", r.Name, r.Driver, r.Target, r.Options, v.Trusted, v.Why, inLedger, d.poolTrust.IsConfigPool(r.Name, b))
		if r.Driver == "nfs" && (!v.Trusted || v.Why != pooltrust.TrustConfig || inLedger) {
			t.Errorf("config nfs pool %s on a fresh install: %+v ledger=%t", r.Name, v, inLedger)
		}
	}
	// A forged options rewrite of the config row stays a config pool (place
	// only), so the mount takes config's options.
	if !d.poolTrust.IsConfigPool("nas", pooltrust.BindingOf("nfs", "srv:/x", "", map[string]string{"options": "vers=3,soft,nolock"})) {
		t.Error("a config nfs pool row with forged options is not recognised as the config pool")
	}
	if d.poolTrust.IsConfigPool("nas", pooltrust.BindingOf("nfs", "attacker:/x", "", nil)) {
		t.Error("a config pool name with another source counts as the config pool")
	}
}
