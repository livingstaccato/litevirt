package lxc

import (
	"os"
	"strings"
	"testing"
)

// A range that overlaps another user's subordinate ids (a rootless user's
// conventional user:100000:65536) is reported; root's own lines are not a
// conflict.
func TestSubIDConflict(t *testing.T) {
	defer subidFixture(t)()
	if err := os.WriteFile(subUIDPath, []byte("tim:100000:65536\nroot:1000000000:65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(subGIDPath, []byte("lxd:300000:65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		base  int64
		owner string
	}{
		{100000, "tim"}, {150000, "tim"}, {40000, "tim"}, {300000, "lxd"},
		{1_000_000_000, ""}, {500_000_000, ""},
	} {
		if owner, _ := SubIDConflict(&IDMap{Base: c.base, Size: IDMapSize}); owner != c.owner {
			t.Errorf("SubIDConflict(%d) = %q, want %q", c.base, owner, c.owner)
		}
	}
}

// Root's lines are bounded: one per distinct range a container needs, never
// repeated, however often each is ensured (start ensures on every start).
func TestEnsureRootSubIDs_OneLinePerDistinctRange(t *testing.T) {
	defer subidFixture(t)()
	r := &LxcRunner{SubIDSpan: &IDMap{Base: 1_000_000_000, Size: IDMapSize * 10}}
	for i := 0; i < 3; i++ {
		for _, b := range []int64{1_000_000_000, 1_000_065_536, 500_000_000, 600_000_000} {
			subIDsMu.Lock()
			subIDsEnsured = map[int64]bool{} // as after a daemon restart
			subIDsMu.Unlock()
			if err := r.ensureRootSubIDs(&IDMap{Base: b, Size: IDMapSize}); err != nil {
				t.Fatal(err)
			}
		}
	}
	b, _ := os.ReadFile(subUIDPath)
	if n := strings.Count(string(b), "root:"); n != 3 {
		t.Fatalf("subuid has %d root lines, want 3 (the span, and one per out-of-span range):\n%s", n, b)
	}
}
