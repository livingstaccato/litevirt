package pooltrust

import (
	"os"
	"path/filepath"
	"testing"
)

// (re-review rr1 N1): normalization sorts, but mount(8) takes the LAST of two
// conflicting options: "soft,hard" mounts hard, "hard,soft" mounts soft.
func TestRR1Probe_NormalizeKeepsLastWins(t *testing.T) {
	for _, p := range [][2]string{{"vers=4.2,soft,hard", "vers=4.2,hard,soft"}, {"vers=3,vers=4.2", "vers=4.2,vers=3"}, {"rw,ro", "ro,rw"}} {
		if NormalizeMountOptions(p[0]) == NormalizeMountOptions(p[1]) {
			t.Errorf("%q and %q mount differently but bind equal (%q)", p[0], p[1], NormalizeMountOptions(p[0]))
		}
	}
}

// (re-review rr1 N2): a quoted option value holding a comma (an SELinux context with a
// category set) is split and its halves sorted: two different contexts bind
// equal.
func TestRR1Probe_NormalizeQuotedCommas(t *testing.T) {
	a := `context="system_u:object_r:nfs_t:s0:c1,c2",fscontext="system_u:object_r:nfs_t:s0:c3,c4"`
	b := `context="system_u:object_r:nfs_t:s0:c1,c4",fscontext="system_u:object_r:nfs_t:s0:c3,c2"`
	if NormalizeMountOptions(a) == NormalizeMountOptions(b) {
		t.Errorf("different contexts bind equal: %q", NormalizeMountOptions(a))
	}
}

// (re-review rr1 Nit 5) Normalization drops a hardening option in any case,
// as storage.hardenNFSOptions now does too
// (TestHardenNFSOptions_DropsCaseVariants): "SUID" binds equal to its
// absence because it never reaches mount(8). The reviewer's probe failed
// unconditionally once the binding dropped it; this is its consistent form.
//
// Mutation: compare the hardening set case-sensitively — red.
func TestRR1Probe_NormalizeCaseVsHardening(t *testing.T) {
	if got := NormalizeMountOptions("vers=4.2,SUID,Exec,NoDev"); got != NormalizeMountOptions("vers=4.2") {
		t.Errorf("upper-case hardening options are bound: %q", got)
	}
}

// (re-review rr1 A1): a pools/ symlinked to an ANCESTOR of the data dir (an operator
// layout mistake) makes every directory under that ancestor the daemon's own
// area: a forged row there is trusted with no ledger entry and no evidence.
func TestRR1Probe_AreaRootSymlinkedToAnAncestor(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "var", "lib", "litevirt")
	other := filepath.Join(root, "var", "lib", "polkit-1", "localauthority", "50-local.d")
	for _, d := range []string{filepath.Join(data, "disks"), filepath.Join(root, "pki"), other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "var", "lib"), filepath.Join(data, "pools")); err != nil {
		t.Fatal(err)
	}
	s, err := Open(data, filepath.Join(root, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	if v := s.Judge("pwn", Binding{Driver: "dir", Target: other}); v.Trusted {
		t.Errorf("a forged row outside <data_dir>/pools as written is trusted as %q (pools/ -> an ancestor)", v.Why)
	}
}
