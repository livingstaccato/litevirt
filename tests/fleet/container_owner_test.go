package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A cold migrate moves a container, not its identity: the target's row keeps
// the source's owner_id, and the directory laid down on the target carries the
// same owner record (stamped again there, whatever the archive held).
func TestContainerMigrate_KeepsTheOwnerRecord(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "ct-own"
	createContainer(t, c, src, name)
	row, err := corrosion.GetContainer(ctx, src.DB, src.Name, name)
	if err != nil || row == nil {
		t.Fatalf("source row: %v", err)
	}
	id := corrosion.DecodeCreateSpec(row.CreateSpec).OwnerID
	if id == "" {
		t.Fatal("create minted no owner_id")
	}
	if o, _ := src.CT.ReadOwner(name); o == nil || o.OwnerID != id {
		t.Fatalf("source owner record = %+v, want %s", o, id)
	}
	// The archive's own record is not trusted: make it name another owner
	// mid-export, and the target must still stamp the row's.
	src.CT.OnExport(func() {
		_ = os.WriteFile(filepath.Join(src.CT.dir(name), "litevirt-owner"), []byte(`{"project":"evil","owner_id":"forged"}`), 0o600)
	})
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	moved, err := corrosion.GetContainer(ctx, dst.DB, dst.Name, name)
	if err != nil || moved == nil {
		t.Fatalf("target row: %v", err)
	}
	if got := corrosion.DecodeCreateSpec(moved.CreateSpec).OwnerID; got != id {
		t.Fatalf("target owner_id = %q, want %q", got, id)
	}
	if o, _ := dst.CT.ReadOwner(name); o == nil || o.OwnerID != id || o.Project != row.Project {
		t.Fatalf("target owner record = %+v, want {%s %s}", o, row.Project, id)
	}
}
