package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// Every host gets the global ISO library at <data_dir>/pools/isos, once; a
// pool an operator put in its place (shared storage) is left alone.
func TestEnsureGlobalISOLibrary(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "node-1", DataDir: t.TempDir()}}
	d.ensureGlobalISOLibrary(ctx)
	rec, ok, err := corrosion.GetStoragePool(ctx, db, "node-1", grpcapi.GlobalISOLibraryName)
	if err != nil || !ok {
		t.Fatalf("no global ISO library pool: %v", err)
	}
	want := filepath.Join(d.cfg.DataDir, "pools", "isos")
	if rec.Target != want || rec.Project != "" || rec.Options["content"] != "iso" {
		t.Fatalf("pool = %+v, want a global content=iso pool at %s", rec, want)
	}
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Fatalf("library directory not created: %v", err)
	}
	rec.Driver, rec.Source, rec.Target = "nfs", "nas:/export/isos", ""
	if err := corrosion.UpsertStoragePool(ctx, db, rec); err != nil {
		t.Fatal(err)
	}
	d.ensureGlobalISOLibrary(ctx)
	if got, _, _ := corrosion.GetStoragePool(ctx, db, "node-1", grpcapi.GlobalISOLibraryName); got.Driver != "nfs" {
		t.Fatalf("the operator's shared isos pool was replaced: %+v", got)
	}
}
