//go:build linux

package lxc

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Many takers (pulls) and unlinkers (a failed first pull's cleanup,
// start-up recovery) race on one item's lock; at no moment may two of them
// believe they hold it.
func TestLockExclusionUnderUnlinkRaces(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "web")
	dir := filepath.Join(parent, unpackDirName)
	path := filepath.Join(dir, "web"+lockSuffix)
	var inside, violations, holds, unlinks int64
	deadline := time.Now().Add(1500 * time.Millisecond)
	var wg sync.WaitGroup
	enter := func() {
		if atomic.AddInt64(&inside, 1) != 1 {
			atomic.AddInt64(&violations, 1)
		}
		atomic.AddInt64(&holds, 1)
		time.Sleep(time.Duration(rand.Intn(300)) * time.Microsecond)
	}
	leave := func() { atomic.AddInt64(&inside, -1) }
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { // a pull; sometimes it fails and unlinks its lock while holding it
			defer wg.Done()
			for time.Now().Before(deadline) {
				rel, err := lockItemFile(context.Background(), dest)
				if err != nil {
					t.Error(err)
					return
				}
				enter()
				// The real unlinkers (PullOCI's failure cleanup, recovery)
				// unlink as their last act under the lock: leave first.
				leave()
				if rand.Intn(2) == 0 {
					if os.Remove(path) == nil {
						atomic.AddInt64(&unlinks, 1)
					}
				}
				rel()
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { // start-up recovery's removeItemLock path
			defer wg.Done()
			for time.Now().Before(deadline) {
				rel, ok := tryLockItem(dir, "web")
				if !ok {
					time.Sleep(50 * time.Microsecond)
					continue
				}
				enter()
				leave()
				if os.Remove(path) == nil {
					atomic.AddInt64(&unlinks, 1)
				}
				rel()
			}
		}()
	}
	wg.Wait()
	t.Logf("holds %d, unlinks %d, violations %d", holds, unlinks, violations)
	if violations != 0 {
		t.Fatalf("%d times two takers held the item's lock at once", violations)
	}
}
