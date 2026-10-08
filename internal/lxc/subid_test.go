package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func subidFixture(t *testing.T) func() {
	t.Helper()
	tmp := t.TempDir()
	oldU, oldG, oldW, oldWait := subUIDPath, subGIDPath, subIDsWanted, subIDLockWait
	subUIDPath, subGIDPath = filepath.Join(tmp, "subuid"), filepath.Join(tmp, "subgid")
	subIDsWanted = func() bool { return true }
	subIDLockWait = 300 * time.Millisecond
	subIDsMu.Lock()
	subIDsEnsured = map[int64]bool{}
	subIDsMu.Unlock()
	return func() { subUIDPath, subGIDPath, subIDsWanted, subIDLockWait = oldU, oldG, oldW, oldWait }
}

// The append keeps every line it did not write byte for byte — a last line
// with no newline included — adds root's range once however many daemons or
// creates race, and waits for shadow's lock file (usermod holds
// /etc/subuid.lock while it rewrites the file).
func TestEnsureRootSubIDs_AppendOnlyIdempotentLocked(t *testing.T) {
	defer subidFixture(t)()
	foreign := "tim:100000:65536\nlxd:1000000:1000000000" // no trailing newline
	if err := os.WriteFile(subUIDPath, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	span := &IDMap{Base: 1_000_000_000, Size: 65536 * 4}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := &LxcRunner{SubIDSpan: span}
			if err := r.ensureRootSubIDs(&IDMap{Base: 1_000_000_000 + int64(i%4)*65536, Size: 65536}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	b, _ := os.ReadFile(subUIDPath)
	if !strings.HasPrefix(string(b), foreign+"\n") {
		t.Fatalf("lines the daemon did not write were changed:\n%q", b)
	}
	if n := strings.Count(string(b), "root:1000000000:262144"); n != 1 {
		t.Fatalf("root's range appended %d times:\n%s", n, b)
	}
	if _, err := os.Stat(subUIDPath + ".lock"); !os.IsNotExist(err) {
		t.Fatal("the lock file was left behind")
	}

	// Another tool holds the lock: the append waits for it, then gives up
	// without touching the file.
	subIDsMu.Lock()
	subIDsEnsured = map[int64]bool{}
	subIDsMu.Unlock()
	if err := os.WriteFile(subGIDPath+".lock", []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &LxcRunner{}
	if err := r.ensureRootSubIDs(&IDMap{Base: 2_000_000_000, Size: 65536}); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("append while the file is locked: %v", err)
	}
	if b, _ := os.ReadFile(subGIDPath); strings.Contains(string(b), "2000000000") {
		t.Fatal("wrote while another tool held the lock")
	}
	if b, _ := os.ReadFile(subGIDPath + ".lock"); string(b) != "123\n" {
		t.Fatal("removed another tool's lock")
	}
}

// Another daemon's append between this one's check and its lock is seen under
// the lock: the line is not added twice.
func TestAppendSubIDLocked_RechecksUnderTheLock(t *testing.T) {
	defer subidFixture(t)()
	m := &IDMap{Base: 1_000_000_000, Size: 65536}
	for i := 0; i < 2; i++ {
		if err := appendSubIDLocked(subUIDPath, m, m); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(subUIDPath); strings.Count(string(b), "root:") != 1 {
		t.Fatalf("subuid = %q", b)
	}
}
