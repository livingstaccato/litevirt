package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Item 3: the built-in default pool stays where an existing cluster has it.
// A host whose registered default is <data_dir>/disks keeps it there (no
// forced move); a host with none gets <data_dir>/pools/default.
func TestRegisterStoragePools_DefaultStaysWhereItIs(t *testing.T) {
	for name, tc := range map[string]struct {
		existing string // "" = no row
		want     string
	}{
		"existing cluster": {existing: "disks", want: "disks"},
		"new cluster":      {existing: "", want: "pools/default"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			db := corrosion.NewTestClientT(t)
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatal(err)
			}
			dataDir := t.TempDir()
			if tc.existing != "" {
				if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
					HostName: "host-a", Name: "default", Driver: "local", Target: filepath.Join(dataDir, tc.existing), State: "active",
				}); err != nil {
					t.Fatal(err)
				}
			}
			d := &Daemon{db: db, cfg: &Config{HostName: "host-a", DataDir: dataDir}}
			d.registerStoragePools(ctx)
			rec, ok, err := corrosion.GetStoragePool(ctx, db, "host-a", "default")
			if err != nil || !ok {
				t.Fatalf("default pool: ok=%v err=%v", ok, err)
			}
			if want := filepath.Join(dataDir, tc.want); rec.Target != want {
				t.Fatalf("default pool target = %q, want %q", rec.Target, want)
			}
		})
	}
}

// I2/M6: on a host whose data_dir is on NFS, registering the pools records
// the export <data_dir>/disks is on (so no host's nfs pool may mount it), and
// a directory pool of this host created through the API gets its export
// recorded too, read at start rather than by a backfill.
func TestRegisterStoragePools_RecordsNFSExports(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	vms := t.TempDir()
	defer storage.OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(fmt.Sprintf(
			"40 1 0:60 / %s rw,nosuid,nodev,noexec,nosymfollow - nfs4 nas:/hosts/a rw\n"+
				"41 1 0:61 / %s rw,nosuid,nodev,noexec,nosymfollow - nfs4 nas:/vms rw\n", dataDir, vms)), nil
	})()
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "host-a", Name: "api", Driver: "dir", Target: vms, State: "active", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "host-a", DataDir: dataDir}}
	d.registerStoragePools(ctx)
	def, _, _ := corrosion.GetStoragePool(ctx, db, "host-a", "default")
	if got := def.Options["data_disks_nfs_export"]; got != "nas:/hosts/a/disks" {
		t.Errorf("default pool's recorded disks/ export = %q, want nas:/hosts/a/disks", got)
	}
	api, _, _ := corrosion.GetStoragePool(ctx, db, "host-a", "api")
	if got := api.Options[storage.NFSExportOption]; got != "nas:/vms" {
		t.Errorf("API dir pool's recorded export = %q, want nas:/vms", got)
	}
	if api.Project != "acme" {
		t.Errorf("recording the export changed the row's project to %q", api.Project)
	}
}
