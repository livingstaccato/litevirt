package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// wantUnresolvedVolume asserts that a storage name found neither in the stack
// nor in any pool of this host is an error naming it and where it looked —
// never a silent fallback to the local driver.
func wantUnresolvedVolume(t *testing.T, s *Server, ctx context.Context, stack, vol string) {
	t.Helper()
	cfg, err := s.resolveVolume(ctx, stack, vol)
	if err == nil {
		t.Fatalf("resolveVolume(%q, %q) = %+v, nil error; want an error, not a fallback", stack, vol, cfg)
	}
	msg := err.Error()
	for _, want := range []string{`"` + vol + `"`, "storage pool", `host "` + s.hostName + `"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %s", msg, want)
		}
	}
	if stack != "" && !strings.Contains(msg, `stack "`+stack+`"`) {
		t.Errorf("error %q does not name the stack it looked in", msg)
	}
}

// A pool registered in the cluster (lv pool create, or another daemon's
// config) resolves even before this daemon's in-memory cache has caught up —
// right after a restart, the cache knows only config pools.
func TestResolveVolume_PoolNotYetInTheCacheResolves(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "warm", Driver: "nfs", Source: "nas:/x", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	cfg := mustResolveVolume(t, s, ctx, "", "warm")
	if cfg.Driver != "nfs" || cfg.Source != "nas:/x" {
		t.Errorf("resolveVolume = %+v, want the nfs pool", cfg)
	}
}

// Deploy refuses a disk whose storage names neither a volume of the file nor
// a pool anywhere in the cluster, before anything is created: positioned in
// the file, with the name it most likely meant.
func TestValidateDeployDependencies_UndeclaredStorage(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	for _, name := range []string{"warm", "hot"} {
		if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
			HostName: "some-other-host", Name: name, Driver: "nfs", Source: "nas:/" + name, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	src := "name: s\nvms:\n  web:\n    image: ubuntu\n    disks:\n      root: { size: 20G, storage: hot }\n      data: { size: 20G, storage: wram }\n"
	f, err := compose.ParseBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	errs := s.validateDeployDependencies(ctx, f, []byte(src))
	joined := strings.Join(errs, "\n")
	want := `7:35: vms.web.disks.data.storage: storage "wram" is neither a volume of this file nor a storage pool — did you mean "warm"?`
	if !strings.Contains(joined, want) {
		t.Errorf("pre-deploy errors do not contain\n  %s\ngot:\n%s", want, joined)
	}
	if strings.Contains(joined, `"hot"`) {
		t.Errorf("a pool on another host was refused:\n%s", joined)
	}
}
