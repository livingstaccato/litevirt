package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// P5. A refresh whose own resolve hangs — a hard-mounted NFS source that does
// not answer, while the refresh holds the container's lock — does not stall
// the refresh of every other container: past the per-container deadline the
// loop moves on, names the hung container, and the next container's policy
// is still rewritten. The hung one keeps the policy it last wrote.
//
// Mutation: call refreshHookPolicy directly in RefreshHookPolicies (no
// deadline) — the refresh never returns and this goes red.
func TestRefreshHookPolicies_HungContainerDoesNotStallOthers(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	data := Mount{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/srv"}
	for _, n := range []string{"a", "b"} {
		containerDir(t, r, n, "lxc.uts.name = "+n+"\n")
		if err := r.SetHostAccess(n, []Mount{data}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// b's policy is gone, so only a refresh that reaches b writes it again.
	if err := os.Remove(hookPolicyFile("b")); err != nil {
		t.Fatal(err)
	}
	old := refreshDeadline
	refreshDeadline = 200 * time.Millisecond
	release := make(chan struct{})
	refreshPauseHook = func(name string) {
		if name == "a" {
			<-release
		}
	}
	t.Cleanup(func() {
		close(release)
		// Wait for the hung refresh of a to finish (it holds a's lock), so
		// nothing writes into the test's directories after it ends.
		for {
			if unlock, ok := r.tryLockHostAccess("a"); ok {
				unlock()
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		refreshPauseHook, refreshDeadline = nil, old
	})

	done := make(chan error, 1)
	go func() { done <- r.RefreshHookPolicies() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), `"a"`) {
			t.Errorf("a refresh past its deadline is not named: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("one container whose refresh hangs stalled the refresh of every other")
	}
	if _, err := os.Stat(hookPolicyFile("b")); err != nil {
		t.Errorf("the container after the hung one was not refreshed: %v", err)
	}
}
