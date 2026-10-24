package pooltrust

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// (re-review rr3 3) A row whose name is not a valid pool name is no pool of
// this host's, whatever it names — in the daemon's own areas, target-less
// nfs, even a name config defines with a traversal — and the upgrade
// adoption never adopts it.
//
// Mutations: drop the name check from Judge — the in-area rows are trusted,
// red; drop it from AdoptOnUpgrade — the target-less nfs row is adopted (it
// is in mounts/), red.
func TestJudge_AnInvalidPoolNameIsNeverTrusted(t *testing.T) {
	f, db := adoptFixture(t)
	ctx := context.Background()
	bad := []string{"x/../../../etc/polkit-1/rules.d", "..", "a/b", "-o", strings.Repeat("p", 300)}
	s := f.open(t)
	for _, n := range bad {
		for _, b := range []Binding{
			{Driver: "dir", Target: filepath.Join(f.data, "pools", "inarea")},
			BindingOf("nfs", "attacker:/x", "", nil),
		} {
			if v := s.Judge(n, b); v.Trusted {
				t.Errorf("Judge(%q, %+v) trusted: %+v", n, b, v)
			}
		}
		if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: "h1", Name: n, Driver: "nfs", Source: "attacker:/x", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.AdoptOnUpgrade(ctx, db, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Adopted) != 0 {
		t.Fatalf("rows with invalid names adopted: %v", a.Adopted)
	}
	for _, n := range bad {
		if _, ok := s.Entry(n); ok {
			t.Errorf("%q in the ledger", n)
		}
	}
}
