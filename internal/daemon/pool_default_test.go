package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
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
