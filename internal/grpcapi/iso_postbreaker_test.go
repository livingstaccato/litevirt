package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Post-breaker fix (restore-iso-rereview-5.md).

// N5-2: one tenant's creates naming directories on a dead network mount
// cannot spend the reads another tenant's start needs. A non-admin's path that
// names no pool directory is refused before the filesystem is touched.
func TestISOPostBreaker_OneTenantsFloodDoesNotRefuseAnothersStart(t *testing.T) {
	s, _, _ := isoServer(t)
	_ = acmeOperator(t, s)
	bob := isoEngineCtx(t, s, "bob", "Operator", projectRBACBase("other"))
	_, _ = libraryVMStopped(t, s, "a-vm")
	dead := filepath.Join(t.TempDir(), "dead-nfs")
	block := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	origP, origM, origT := isoDirProbe, isoMountInfo, isoDirProbeTimeout
	t.Cleanup(func() { close(block); isoDirProbe, isoMountInfo, isoDirProbeTimeout = origP, origM, origT })
	isoDirProbeTimeout = 300 * time.Millisecond
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if strings.HasPrefix(p, dead) {
			mu.Lock()
			calls++
			mu.Unlock()
			<-block
		}
		return origP(p)
	}
	real, _ := origM()
	isoMountInfo = func() ([]mountEntry, error) {
		return append(append([]mountEntry(nil), real...), mountEntry{point: dead, dev: "0:991", fstype: "nfs4", options: "rw"}), nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			iso := filepath.Join(dead, "d"+strconv.Itoa(i), "x.iso")
			if _, err := s.CreateVM(bob, isoCreate("b"+strconv.Itoa(i), iso, "other")); status.Code(err) != codes.PermissionDenied {
				t.Errorf("tenant other naming %s, no pool's directory: got %v, want PermissionDenied", iso, err)
			}
		}(i)
	}
	wg.Wait()
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 0 {
		t.Errorf("%d reads of directories a non-admin named that no pool maps; want none", n)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "a-vm")); err != nil {
		t.Fatalf("another tenant's start after the flood: %v", err)
	}
}

// N5-2: the bounds on waiting reads are per network mount (counted from the
// start of each read, so a burst inside the timeout is bounded too), per
// project, and with slots kept for reads not on a network mount. One project
// filling its share leaves another project's reads, and local reads, alone.
func TestISOPostBreaker_ReadBudgetsAreNotShared(t *testing.T) {
	root := t.TempDir()
	block := make(chan struct{})
	var mu sync.Mutex
	calls := map[string]int{}
	origP, origM, origT := isoDirProbe, isoMountInfo, isoDirProbeTimeout
	t.Cleanup(func() { close(block); isoDirProbe, isoMountInfo, isoDirProbeTimeout = origP, origM, origT })
	isoDirProbeTimeout = 2 * time.Second // the whole burst runs inside it
	var mounts []mountEntry
	for i := 0; i < 40; i++ {
		mounts = append(mounts, mountEntry{point: filepath.Join(root, "m"+strconv.Itoa(i)), dev: "0:" + strconv.Itoa(500+i), fstype: "nfs4", options: "rw"})
	}
	isoMountInfo = func() ([]mountEntry, error) { return mounts, nil }
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if strings.Contains(p, "/dead") {
			mu.Lock()
			calls[filepath.Dir(filepath.Dir(p))]++
			mu.Unlock()
			<-block
		}
		return p, nil, nil
	}
	total := func() (n int) {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range calls {
			n += c
		}
		return n
	}
	burst := func(ctx context.Context, n int, dir func(i int) string) {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); _, _ = probeDirCtx(ctx, dir(i)) }(i)
		}
		time.Sleep(200 * time.Millisecond) // every read has started or been refused
		_ = wg.Wait
	}
	b := withReadProject(context.Background(), "b")

	// One mount, 1000 distinct directories at once: at most isoMaxReadsPerMount.
	burst(b, 1000, func(i int) string { return filepath.Join(root, "m0", "dead", strconv.Itoa(i)) })
	if n := total(); n > isoMaxReadsPerMount {
		t.Fatalf("%d reads are blocked on one mount; want at most %d", n, isoMaxReadsPerMount)
	}
	// Project b across many mounts: at most its share.
	burst(b, 19, func(i int) string { return filepath.Join(root, "m"+strconv.Itoa(i+1), "dead", "x") })
	if n := total(); n > isoMaxReadsPerProject {
		t.Fatalf("%d reads of project b are blocked; want at most %d", n, isoMaxReadsPerProject)
	}
	// Project a still reads, on a mount b has not used and on local disk.
	a := withReadProject(context.Background(), "a")
	if _, err := probeDirCtx(a, filepath.Join(root, "m39", "live")); err != nil {
		t.Fatalf("project a's read on another mount after project b filled its share: %v", err)
	}
	if _, err := probeDirCtx(a, filepath.Join(t.TempDir(), "local")); err != nil {
		t.Fatalf("project a's local read: %v", err)
	}
	// Other projects fill what network reads may take; local reads still run.
	for p := 0; p < 4; p++ {
		ctx := withReadProject(context.Background(), "flood"+strconv.Itoa(p))
		burst(ctx, 16, func(i int) string {
			return filepath.Join(root, "m"+strconv.Itoa(20+i%19), "dead", "f"+strconv.Itoa(p)+"-"+strconv.Itoa(i))
		})
	}
	if n := total(); n > isoMaxReadsInFlight-isoReservedLocalReads {
		t.Fatalf("%d network reads are blocked; want at most %d", n, isoMaxReadsInFlight-isoReservedLocalReads)
	}
	if _, err := probeDirCtx(a, filepath.Join(t.TempDir(), "local")); err != nil {
		t.Fatalf("a local read once network reads hold their share: %v", err)
	}
}
