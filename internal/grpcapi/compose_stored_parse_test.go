package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A stored stack's compose YAML was validated when it was deployed. A field a
// later build refuses (here a misspelt healthcheck key, silently ignored when
// the stack was deployed) must not make it unreadable: resolveVolume would
// fall back to the local driver and put the disk on the wrong storage.
func TestResolveVolume_StoredComposeWithFieldALaterBuildRefuses(t *testing.T) {
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
      target: "22"
      retires: 5
`
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "old", ComposeYAML: yaml, State: "running"}); err != nil {
		t.Fatal(err)
	}
	cfg := s.resolveVolume(ctx, "old", "shared")
	if cfg.Driver != "nfs" || cfg.Source != "nas:/export" {
		t.Errorf("resolveVolume = %+v, want the stack's nfs volume", cfg)
	}
}
