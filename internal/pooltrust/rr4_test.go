package pooltrust

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/storage"
)

// (re-review rr4 3) What a forged pre-upgrade nfs row in mounts/ gets
// adopted with: never a source or target a create would refuse ("..", ".",
// empty, a NUL, over-long, an option-like "-oexec", a non-canonical one) nor
// a target that leaves mounts/. A well-formed one whose mount point is in
// mounts/ is adopted, whatever its name looks like (a .adopt- name is just a
// name).
//
// Mutation: drop CheckConfig from the adoption — the malformed sources are
// adopted, red.
func TestRR4Probe_InAreaNFSAdoptionInputs(t *testing.T) {
	f, db := adoptFixture(t)
	ctx := context.Background()
	cases := []struct{ name, source, target string }{
		{"dotdot", "..", ""},
		{"dot", ".", ""},
		{"empty", "", ""},
		{"nul", "a\x00b", ""},
		{"long", strings.Repeat("a", 300), ""},
		{"noncanon", ".adopt-evil", ""}, // fails ValidateSource; mount point mounts/.adopt-evil
		{"stagetarget", "attacker:/x", filepath.Join(f.data, "mounts", ".adopt-x")}, // a target named like a stage
		{"badsrc", "-oexec", ""},
		{"nested", "attacker:/y", filepath.Join(f.data, "mounts", "a", "..", "..", "etc")},
	}
	for _, c := range cases {
		if err := upsertNFS(ctx, db, "h1", c.name, c.source, c.target); err != nil {
			t.Fatal(err)
		}
	}
	s := f.open(t)
	a, err := s.AdoptOnUpgrade(ctx, db, "h1")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		e, ok := s.Entry(c.name)
		dir := storage.NFSPoolMountDir(f.data, storage.Config{Driver: "nfs", Source: c.source, Target: c.target})
		vs := storage.ValidateSource(storage.Config{Driver: "nfs", Source: c.source})
		t.Logf("%-12s source=%q mountpoint=%q adopted=%v (%v) ValidateSource=%v", c.name, c.source, dir, ok, e.How, vs)
	}
	t.Logf("held=%v", a.Held)
	for _, c := range cases {
		_, ok := s.Entry(c.name)
		if want := c.name == "stagetarget"; ok != want {
			t.Errorf("%s (source %q, target %q): adopted=%t, want %t", c.name, c.source, c.target, ok, want)
		}
	}
}
