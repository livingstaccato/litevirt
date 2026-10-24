package lxc

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The hook-policy refresh can be the first to need /run/litevirt after a
// boot. The daemon's endpoint file goes in the same directory and is read by
// every user on the node, so the parent is made 0755, whatever the umask,
// while the policy directory itself stays 0700.
//
// Mutation: create the parent with the policy dir's MkdirAll(…, 0o700): red.
func TestWriteHookPolicy_MakesASharedParentEveryoneCanSearch(t *testing.T) {
	_, access := hostTree(t) // sets hookPolicyDir (fakeKernelSupport), restored at cleanup
	run := filepath.Join(t.TempDir(), "run")
	hookPolicyDir = filepath.Join(run, "lxc-hook-policy")
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	if err := r.writeHookPolicy("c1", nil, nil); err != nil {
		t.Fatalf("writeHookPolicy: %v", err)
	}
	for dir, want := range map[string]os.FileMode{run: 0o755, hookPolicyDir: 0o700} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s = %04o, want %04o", dir, fi.Mode().Perm(), want)
		}
	}
}
