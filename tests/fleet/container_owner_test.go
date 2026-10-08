package fleet

import (
	"context"
	"errors"
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

// A migrate keeps a container's privilege mode exactly: the target records
// the same id range and confinement the source created it with.
func TestContainerMigrate_KeepsPrivilegeMode(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "ct-sec"
	createContainer(t, c, src, name)
	row, _ := corrosion.GetContainer(ctx, src.DB, src.Name, name)
	before := corrosion.DecodeCreateSpec(row.CreateSpec)
	if before.IDMapBase == 0 || before.Confinement != "default" {
		t.Fatalf("created as %+v, want unprivileged default", before)
	}
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	moved, _ := corrosion.GetContainer(ctx, dst.DB, dst.Name, name)
	after := corrosion.DecodeCreateSpec(moved.CreateSpec)
	if after.IDMapBase != before.IDMapBase || after.Confinement != before.Confinement {
		t.Fatalf("migrated as %+v, created as %+v", after, before)
	}
	// And the config the target would start the container with says the
	// same: the row is not the only half.
	sec, err := dst.CT.ContainerSecurity(name)
	if err != nil {
		t.Fatal(err)
	}
	if sec.IDMap == nil || sec.IDMap.Base != before.IDMapBase || sec.Confinement != before.Confinement {
		t.Fatalf("target config security %+v (idmap %+v), want range %d %s", sec, sec.IDMap, before.IDMapBase, before.Confinement)
	}
}

// A migrate prepares the target before it touches the source: the target
// gets root's subordinate range for the container's id range first, and a
// target that cannot take it refuses the migrate with the source still
// running and untouched.
func TestContainerMigrate_PreparesTheTargetsSubIDsFirst(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "ct-subid"
	createContainer(t, c, src, name)
	row, _ := corrosion.GetContainer(ctx, src.DB, src.Name, name)
	base := corrosion.DecodeCreateSpec(row.CreateSpec).IDMapBase

	dst.CT.FailEnsureIDRange(errors.New("subuid locked"))
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err == nil {
		t.Fatal("migrate onto a target that cannot take the range succeeded")
	}
	if n := len(src.CT.ExportCalls()); n != 0 {
		t.Fatalf("the source was archived (%d exports) before the target was ready", n)
	}
	if got := src.CT.State(name); got != "stopped" && got != "running" {
		t.Fatalf("source state %q", got)
	}
	if len(src.CT.StopCalls()) != 0 {
		t.Fatalf("the source was stopped: %v", src.CT.StopCalls())
	}

	dst.CT.FailEnsureIDRange(nil)
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := dst.CT.EnsuredIDRanges(); len(got) == 0 || got[0] != base {
		t.Fatalf("target ensured %v, want [%d]", got, base)
	}
}
