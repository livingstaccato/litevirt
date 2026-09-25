package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

func mustResolveVolume(t *testing.T, s *Server, ctx context.Context, stack, vol string) storage.Config {
	t.Helper()
	cfg, err := s.resolveVolume(ctx, stack, vol)
	if err != nil {
		t.Fatalf("resolveVolume(%q, %q): %v", stack, vol, err)
	}
	return cfg
}

// A stored stack's compose YAML was accepted when it was deployed. A check
// added since (here: a misspelt field, a named port, a VM with no image) must
// not make it unreadable: its volumes still resolve to the stack's storage.
func TestResolveVolume_StoredComposeTheValidatorRefuses(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	yaml := `name: old
volumes:
  shared:
    driver: nfs
    source: "nas:/export"
vms:
  db:
    image: u
    healthcheck:
      type: tcp
      target: postgres
      retires: 5
  web:
    cpu: 1
`
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "old", ComposeYAML: yaml, State: "running"}); err != nil {
		t.Fatal(err)
	}
	cfg := mustResolveVolume(t, s, ctx, "old", "shared")
	if cfg.Driver != "nfs" || cfg.Source != "nas:/export" {
		t.Errorf("resolveVolume = %+v, want the stack's nfs volume", cfg)
	}
}

// Nor is an unreadable stored stack an excuse to treat its external networks
// as the stack's own: the teardown must know, or it deletes what it never made.
func TestExternalNetworkNames_UnreadableStoredStackIsAnError(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "bad", ComposeYAML: "vms: [a, b]\n", State: "running"}); err != nil {
		t.Fatal(err)
	}
	if ext, err := s.externalNetworkNames(ctx, "bad"); err == nil {
		t.Errorf("externalNetworkNames on an unreadable stored stack = %v, nil error; want an error", ext)
	}
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "ok", State: "running",
		ComposeYAML: "name: ok\nnetworks:\n  lan: { external: true }\nvms:\n  a: {cpu: 1}\n"}); err != nil {
		t.Fatal(err)
	}
	ext, err := s.externalNetworkNames(ctx, "ok")
	if err != nil || !ext["lan"] || !ext["ok_lan"] {
		t.Errorf("externalNetworkNames(ok) = %v, %v; want lan and ok_lan", ext, err)
	}
}
