package vfio

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// blockUnbind makes k's vfio-pci unbind write block, the way the kernel's
// vfio_unregister_group_dev does while a process holds the device fd open, until
// the returned release is called. entered fires when the write starts.
func blockUnbind(t *testing.T, k *kernelFS) (entered <-chan struct{}, release func()) {
	t.Helper()
	in := make(chan struct{}, 8)
	gate := make(chan struct{})
	k.onWrite = func(p string) {
		if p == k.devPath()+"/driver/unbind" && k.driver() == vfioDriver {
			in <- struct{}{}
			<-gate
		}
	}
	var once bool
	release = func() {
		if !once {
			once = true
			close(gate)
		}
	}
	t.Cleanup(release)
	return in, release
}

// shortUnbindWait shrinks the bounded wait for a test.
func shortUnbindWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := unbindTimeout
	unbindTimeout = d
	t.Cleanup(func() { unbindTimeout = old })
}

// waitUnbindSettled waits until no unbind of addr is in flight.
func waitUnbindSettled(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if unbindInFlight(addr) == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the unbind of %s never settled", addr)
}

func unbindWrites(k *kernelFS) int {
	n := 0
	for _, w := range k.log {
		if strings.HasPrefix(w, k.devPath()+"/driver/unbind=") {
			n++
		}
	}
	return n
}

// TestHost_ABlockedUnbindTimesOutAndKeepsTheDevice: a process holding the vfio
// device fd makes the kernel block the unbind write until it lets go. The
// release must come back within its bound, fail closed (the device still on
// vfio-pci and its record kept, so the caller keeps ownership), and must not
// leave the caller waiting on the kernel.
func TestHost_ABlockedUnbindTimesOutAndKeepsTheDevice(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
	defer SetFS(k)()
	path := recordPath(t)
	writeRecord(t, path, map[string]string{addr: "igbvf"})
	h := HostAt(path)
	entered, release := blockUnbind(t, k)
	shortUnbindWait(t, 200*time.Millisecond)

	start := time.Now()
	err := h.Unbind(addr, "")
	took := time.Since(start)
	if err == nil {
		t.Fatal("Unbind succeeded while the kernel write was still blocked")
	}
	if !errors.Is(err, ErrUnbindBlocked) {
		t.Fatalf("Unbind error = %v, want ErrUnbindBlocked", err)
	}
	if took > 2*time.Second {
		t.Fatalf("Unbind took %v; the bounded wait is 200ms", took)
	}
	select {
	case <-entered:
	default:
		t.Fatal("the unbind write was never attempted")
	}
	if k.driver() != vfioDriver {
		t.Fatalf("driver = %q, want still vfio-pci", k.driver())
	}
	if got := readRecord(t, path); got[addr] != "igbvf" {
		t.Fatalf("record = %v, want the igbvf entry kept for the retry", got)
	}
	// Shutdown names it (review M3): a stop would otherwise hang unexplained.
	if _, ok := StuckUnbinds()[addr]; !ok || LogStuckUnbinds() != 1 {
		t.Fatalf("StuckUnbinds = %v, want %s listed for the shutdown log", StuckUnbinds(), addr)
	}

	// Once the holder lets go, the write lands, and the retry converges.
	release()
	waitUnbindSettled(t, addr)
	if err := h.ReleaseUnbound(addr); err != nil {
		t.Fatalf("retry after the holder let go: %v", err)
	}
	if k.driver() != "igbvf" {
		t.Fatalf("driver after the retry = %q, want igbvf", k.driver())
	}
	if got := readRecord(t, path); len(got) != 0 {
		t.Fatalf("record after the retry = %v, want empty", got)
	}
}

// TestHost_AStuckUnbindMakesLaterCallsFailFast: the kernel write cannot be
// cancelled, so at most one goroutine may sit in it per device. While it does,
// every later Unbind, ReleaseUnbound and Bind of that device must fail at once,
// without a second write, rather than queue behind the first.
func TestHost_AStuckUnbindMakesLaterCallsFailFast(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
	defer SetFS(k)()
	path := recordPath(t)
	writeRecord(t, path, map[string]string{addr: "igbvf"})
	h := HostAt(path)
	entered, release := blockUnbind(t, k)
	shortUnbindWait(t, 100*time.Millisecond)

	if err := h.Unbind(addr, ""); !errors.Is(err, ErrUnbindBlocked) {
		t.Fatalf("first Unbind = %v, want ErrUnbindBlocked", err)
	}
	// The stuck write is in the kernel, and its log entry is visible here.
	<-entered
	// A call that queued behind it would now hang the test.
	shortUnbindWait(t, time.Hour)
	for name, call := range map[string]func() error{
		"Unbind":         func() error { return h.Unbind(addr, "") },
		"ReleaseUnbound": func() error { return h.ReleaseUnbound(addr) },
		"Bind":           func() error { _, err := h.Bind(addr); return err },
	} {
		start := time.Now()
		err := call()
		if !errors.Is(err, ErrUnbindBlocked) {
			t.Fatalf("%s while the first write is stuck = %v, want ErrUnbindBlocked", name, err)
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("%s took %v; it must fail fast", name, took)
		}
	}
	if n := unbindWrites(k); n != 1 {
		t.Fatalf("%d unbind writes reached the kernel, want exactly 1", n)
	}
	release()
	waitUnbindSettled(t, addr)
}

// TestHost_AnOpenVfioFdRefusesTheUnbindUpFront: when a process holds the
// device's vfio group (or its iommufd cdev) open, the unbind would block, so it
// is refused before anything changes, naming the process.
func TestHost_AnOpenVfioFdRefusesTheUnbindUpFront(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
	defer SetFS(k)()
	old := inUseGrace
	inUseGrace = 50 * time.Millisecond
	t.Cleanup(func() { inUseGrace = old })
	path := recordPath(t)
	writeRecord(t, path, map[string]string{addr: "igbvf"})
	h := HostAt(path)

	k.links[k.devPath()+"/iommu_group"] = "../../../../kernel/iommu_groups/17"
	k.dirs["/proc"] = []os.DirEntry{fakeEntry{"1"}, fakeEntry{"4242"}, fakeEntry{"self"}}
	k.dirs["/proc/1/fd"] = []os.DirEntry{fakeEntry{"0"}}
	k.links["/proc/1/fd/0"] = "/dev/null"
	k.dirs["/proc/4242/fd"] = []os.DirEntry{fakeEntry{"0"}, fakeEntry{"9"}}
	k.links["/proc/4242/fd/0"] = "/dev/null"
	k.links["/proc/4242/fd/9"] = "/dev/vfio/17"
	k.files["/proc/4242/comm"] = []byte("qemu-system-x86\n")

	err := h.Unbind(addr, "")
	if err == nil {
		t.Fatal("Unbind went ahead while a process held the vfio group open")
	}
	if !strings.Contains(err.Error(), "4242") || !strings.Contains(err.Error(), "qemu-system-x86") {
		t.Fatalf("error = %v, want it to name pid 4242 (qemu-system-x86)", err)
	}
	if n := unbindWrites(k); n != 0 {
		t.Fatalf("%d unbind writes reached the kernel, want none", n)
	}
	if k.driver() != vfioDriver || k.override != vfioDriver {
		t.Fatalf("driver=%q override=%q, want the device untouched on vfio-pci", k.driver(), k.override)
	}

	// The holder exits: the release goes ahead.
	delete(k.links, "/proc/4242/fd/9")
	k.dirs["/proc/4242/fd"] = []os.DirEntry{fakeEntry{"0"}}
	if err := h.Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind after the holder exited: %v", err)
	}
	if k.driver() != "igbvf" {
		t.Fatalf("driver = %q, want igbvf", k.driver())
	}
}
