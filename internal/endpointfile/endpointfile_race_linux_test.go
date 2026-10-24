//go:build linux

package endpointfile

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// The directory judged is the directory read through. With an ancestor
// someone can write, swapping a good directory for one that fails the check
// (renameat2 RENAME_EXCHANGE in a loop) between the check and the open never
// gets the bad directory's file read. Judged by path, then opened by path,
// the swap won within about 4 to 25 reads. (Made permanent from re-review
// 2's TestProbe_DirSwapRace.)
//
// Mutation: open the file by path instead of relative to the directory
// judged (os.OpenFile(path, O_NOFOLLOW…)): red.
func TestRead_ADirectorySwappedAfterTheCheckIsNotReadThrough(t *testing.T) {
	anc := t.TempDir() // the writable ancestor
	good := filepath.Join(anc, "run")
	bad := filepath.Join(anc, "bad")
	for dir, mode := range map[string]os.FileMode{good: 0o755, bad: 0o777} {
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	for dir, body := range map[string]string{
		good: "grpc_port: 7443\npki_dir: /etc/litevirt/pki\n",
		bad:  "grpc_port: 9555\npki_dir: /attacker/pki\n",
	} {
		p := filepath.Join(dir, "endpoint")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var stop atomic.Bool
	var swaps atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			if unix.Renameat2(unix.AT_FDCWD, good, unix.AT_FDCWD, bad, unix.RENAME_EXCHANGE) == nil {
				swaps.Add(1)
			}
		}
	}()
	defer func() { stop.Store(true); <-done }()
	for i := 0; i < 20000; i++ {
		if e, err := Read(filepath.Join(good, "endpoint")); err == nil && e.PKIDir == "/attacker/pki" {
			t.Fatalf("read %d returned the bad directory's file (%+v) after %d swaps", i+1, e, swaps.Load())
		}
	}
	if swaps.Load() == 0 {
		t.Skip("renameat2 RENAME_EXCHANGE is not supported here: the swap never happened")
	}
}
