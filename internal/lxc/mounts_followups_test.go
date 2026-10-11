package lxc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// I-1. A refresh the loop abandoned still holds the container's host-access
// lock. Everything else that needs that lock — SetHostAccess (lv ct convert,
// create, restore) and the start's judgment — waits for it only so long, then
// fails with ErrHostAccessBusy naming the container and the stuck refresh,
// so the caller's own locks (StartContainer's per-container lock, which stop,
// delete and the checker's sweep also take) are released. Later refresh runs
// keep saying it is stuck, and once the lookup returns everything clears.
//
// Mutation: make lockHostAccess wait without a bound — red (the calls hang).
func TestHostAccessLock_BoundedBehindAStuckRefresh(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	containerDir(t, r, "a", "lxc.uts.name = a\n")
	if err := r.SetHostAccess("a", []Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/srv"}}, nil); err != nil {
		t.Fatal(err)
	}
	oldDeadline, oldWait := refreshDeadline, hostAccessLockWait
	refreshDeadline, hostAccessLockWait = 100*time.Millisecond, 300*time.Millisecond
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	refreshPauseHook = func(name string) {
		if name == "a" {
			<-release
		}
	}
	waitFree := func() {
		for {
			if unlock, ok := r.tryLockHostAccess("a"); ok {
				unlock()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Cleanup(func() {
		unblock()
		waitFree()
		refreshPauseHook, refreshDeadline, hostAccessLockWait = nil, oldDeadline, oldWait
	})

	if err := r.RefreshHookPolicies(); err == nil {
		t.Fatal("the refresh that hung was not reported")
	}
	if err := r.RefreshHookPolicies(); err == nil || !strings.Contains(err.Error(), "has not returned since") {
		t.Errorf("a later refresh run does not say the refresh is still stuck: %v", err)
	}
	for _, call := range []struct {
		name string
		f    func() error
	}{
		{"SetHostAccess", func() error { return r.SetHostAccess("a", nil, nil) }},
		{"checkHostAccessForStart", func() error { return r.checkHostAccessForStart("a") }},
	} {
		done := make(chan error, 1)
		go func() { done <- call.f() }()
		select {
		case err := <-done:
			if !errors.Is(err, ErrHostAccessBusy) || !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), "refresh") {
				t.Errorf("%s behind a stuck refresh = %v; want ErrHostAccessBusy naming a and the refresh", call.name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waited without a bound behind a stuck refresh", call.name)
		}
	}

	unblock()
	waitFree()
	if err := r.SetHostAccess("a", nil, nil); err != nil {
		t.Errorf("SetHostAccess once the refresh returned: %v", err)
	}
	if err := r.RefreshHookPolicies(); err != nil {
		t.Errorf("the refresh still reports a stuck container after it returned: %v", err)
	}
}
