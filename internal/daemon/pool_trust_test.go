package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// The daemon's own row consumers act only on the rows of this host it
// trusts. At its first start with the ledger, an existing pool holding this
// host's qcow2 disk is adopted, a config pool is trusted by its definition,
// and a forged row (made before the upgrade) is not: the capacity refresh
// neither measures nor rewrites it as this host's, and pool_row_untrusted
// names it.
//
// Mutations: list every row in trustedOwnPools — the forged row is rewritten
// active by the refresh, red; drop SetConfig in openPoolTrust — the config
// pool is named untrusted, red; skip AdoptOnUpgrade — vmpool is named, red.
func TestOpenPoolTrust_DaemonActsOnlyOnTrustedRows(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	cfgDir, vmDir, pwn := filepath.Join(root, "cfg"), filepath.Join(root, "vm"), filepath.Join(root, "pwn")
	for _, d := range []string{dataDir, cfgDir, vmDir, pwn} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	diskPath := filepath.Join(vmDir, "vm1-root.qcow2")
	if err := os.WriteFile(diskPath, append([]byte{'Q', 'F', 'I', 0xfb}, make([]byte, 508)...), 0o600); err != nil {
		t.Fatal(err)
	}
	const host = "host-a"
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: host, Name: "vmpool", Driver: "dir", Target: vmDir, State: "active"},
		{HostName: host, Name: "pwn", Driver: "dir", Target: pwn, State: "forged-state"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, db, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm1", HostName: host, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: host, Path: diskPath, StorageType: "dir", StorageVolume: "vmpool"}}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: host, DataDir: dataDir, PKIDir: filepath.Join(root, "pki"),
		StoragePools: []StoragePoolConfig{{Name: "cfgpool", Driver: "dir", Target: cfgDir}}}}
	d.openPoolTrust(ctx)
	if _, err := os.Stat(filepath.Join(dataDir, pooltrust.LedgerFile)); err != nil {
		t.Fatalf("no ledger after the first start: %v", err)
	}
	d.registerStoragePools(ctx)
	d.svc = grpcapi.NewServer(host, dataDir, d.cfg.PKIDir, db, nil, nil)
	d.svc.SetPoolTrust(d.poolTrust)
	d.refreshDBPoolCapacity(ctx)

	rec, _, _ := corrosion.GetStoragePool(ctx, db, host, "pwn")
	if rec.State != "forged-state" || rec.TotalBytes != 0 {
		t.Errorf("the capacity refresh rewrote the forged row as this host's: %+v", rec)
	}
	rec, _, _ = corrosion.GetStoragePool(ctx, db, host, "vmpool")
	if rec.TotalBytes == 0 {
		t.Errorf("the capacity refresh skipped the adopted pool: %+v", rec)
	}
	row, found, err := corrosion.GetHealthCondition(ctx, db, "pool_trust", "pool_row_untrusted", "host", host)
	if err != nil || !found {
		t.Fatalf("pool_row_untrusted not raised by the refresh (found %t, err %v)", found, err)
	}
	if !strings.Contains(row.Evidence, `"pool":"pwn"`) || strings.Contains(row.Evidence, `"pool":"vmpool"`) || strings.Contains(row.Evidence, `"pool":"cfgpool"`) {
		t.Errorf("pool_row_untrusted evidence = %s, want pwn only", row.Evidence)
	}
}
