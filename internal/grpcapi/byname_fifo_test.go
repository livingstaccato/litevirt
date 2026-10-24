package grpcapi

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// The judgements before a cold migration's flatten (precheckChain,
// coldDiskSourceCheck, chainAllocated) find each layer a regular file and then
// read its image. A FIFO swapped in at the name between the two must not hang
// them: each layer is opened O_NOFOLLOW|O_NONBLOCK, found regular by fstat,
// and read through that descriptor. (Re-review 5b, R5b-3.)
//
// byNameReadHook swaps the FIFO in exactly there. Mutation: read the layer by
// name again (qcow2.Info(path) in place of the descriptor) in any of the three
// and its test here is red: the call blocks in the FIFO's open.

// swapInFIFO is a byNameReadHook that, the first time it runs for target,
// moves the file aside and leaves a FIFO at its name.
func swapInFIFO(t *testing.T, target string) {
	t.Helper()
	done := false
	byNameReadHook = func(p string) {
		if done || filepath.Base(p) != filepath.Base(target) {
			return
		}
		done = true
		if err := os.Rename(target, target+".saved"); err != nil {
			t.Error(err)
			return
		}
		if err := syscall.Mkfifo(target, 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { byNameReadHook = nil })
}

// notHung runs fn and fails if it does not return within a bound. A run that
// blocks in the FIFO's open is released (a writer opens the FIFO), so a red
// run fails rather than hanging the package.
func notHung(t *testing.T, fifo string, what string, fn func() error) error {
	t.Helper()
	ch := make(chan error, 1)
	go func() { ch <- fn() }()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		<-ch
		t.Fatalf("%s blocked on a FIFO at %s", what, fifo)
		return nil
	}
}

func TestPrecheckChain_AFIFOSwappedInAfterTheStatDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	top := filepath.Join(dir, "vm-root.qcow2")
	if err := qcow2.Create(top, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	swapInFIFO(t, top)
	err := notHung(t, top, "precheckChain", func() error {
		_, err := precheckChain(top, nil)
		return err
	})
	if err != nil {
		t.Errorf("precheckChain of the file it opened: %v", err)
	}
}

func TestPrecheckChain_AFIFOSwappedInAtABackingDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	top := filepath.Join(dir, "vm-root.qcow2")
	if err := qcow2.CreateWithBacking(top, "base.qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	rbase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	swapInFIFO(t, base)
	err = notHung(t, rbase, "precheckChain", func() error {
		_, err := precheckChain(top, func(layer, resolved, format string) error { return nil })
		return err
	})
	if err != nil {
		t.Errorf("precheckChain of the files it opened: %v", err)
	}
}

func TestColdDiskSourceCheck_AFIFOSwappedInAfterTheLstatDoesNotHang(t *testing.T) {
	s := testServer(t)
	dir := t.TempDir()
	top := filepath.Join(dir, "vm-root.qcow2")
	if err := qcow2.Create(top, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	swapInFIFO(t, top)
	err := notHung(t, top, "coldDiskSourceCheck", func() error {
		_, err := s.coldDiskSourceCheck(corrosion.DiskRecord{VMName: "vm", DiskName: "root", Path: top}, "qcow2")
		return err
	})
	if err != nil {
		t.Errorf("coldDiskSourceCheck of the file it opened: %v", err)
	}
}

func TestChainAllocated_AFIFOSwappedInAfterTheStatDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	top := filepath.Join(dir, "vm-root.qcow2")
	if err := qcow2.Create(top, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	swapInFIFO(t, top)
	err := notHung(t, top, "chainAllocated", func() error {
		_, err := chainAllocated(top)
		return err
	})
	if err != nil {
		t.Errorf("chainAllocated of the file it opened: %v", err)
	}
}

// A FIFO already at a backing's name (no swap): the open itself must not wait
// for a writer. Mutation: drop O_NONBLOCK from openRegularNoFollow - red.
func TestChainAllocated_AFIFOAtABackingDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	top := filepath.Join(dir, "vm-root.qcow2")
	if err := qcow2.CreateWithBacking(top, "base.qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(base, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := notHung(t, base, "chainAllocated", func() error {
		_, err := chainAllocated(top)
		return err
	}); err != nil {
		t.Errorf("chainAllocated: %v", err)
	}
}
