//go:build linux

package lb

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fifoWithWriter makes a FIFO at p with a writer blocked in open(2) until
// something opens the FIFO for reading. woken reports whether anything has;
// an O_PATH open, which never calls the FIFO's own open, does not.
func fifoWithWriter(t *testing.T, p string) (woken func() bool) {
	t.Helper()
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	// An O_PATH handle on the inode, so cleanup can release the writer
	// whatever name the FIFO has by then.
	ref, err := syscall.Open(p, unix.O_PATH|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			f.Close()
		}
		close(done)
	}()
	time.Sleep(200 * time.Millisecond) // the writer is blocked in open(2) by now
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			if r, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", ref), os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
				<-done
				r.Close()
			}
		}
		syscall.Close(ref)
	})
	return func() bool {
		select {
		case <-done:
			return true
		case <-time.After(200 * time.Millisecond):
			return false
		}
	}
}

// TestReadTLSFile_NeverOpensANonRegularFile (M-R3, M-R6): a device or FIFO
// is refused without being opened for reading (opening a device can act, as
// a watchdog's does), including one swapped in after the path was resolved:
// for the final name, for a symlink there, and for a directory above it. A
// FIFO's waiting writer shows whether it was opened.
//
// Mutations (each red): open the resolved path O_RDONLY instead of O_PATH;
// drop the regular-file check on the O_PATH descriptor.
func TestReadTLSFile_NeverOpensANonRegularFile(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	t.Cleanup(func() { beforeTLSOpen = func() {} })

	for _, p := range []string{"/dev/null", "/dev/zero"} {
		if _, err := m.readTLSFile(p); err == nil {
			t.Errorf("%s read", p)
		}
	}

	fifo := filepath.Join(dir, "fifo")
	woken := fifoWithWriter(t, fifo)
	if _, err := m.readTLSFile(fifo); err == nil {
		t.Error("fifo read")
	}
	if woken() {
		t.Error("fifo opened for reading")
	}

	write := func(p string) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("CERT"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// The final name: a regular file when resolved, a FIFO when opened.
	a := write(filepath.Join(dir, "a", "tls.crt"))
	staged := filepath.Join(dir, "staged-fifo")
	woken = fifoWithWriter(t, staged)
	beforeTLSOpen = func() {
		if err := os.Rename(staged, a); err != nil {
			t.Error(err)
		}
	}
	if _, err := m.readTLSFile(a); err == nil {
		t.Error("file swapped for a fifo: read")
	}
	if woken() {
		t.Error("file swapped for a fifo: opened for reading")
	}

	// The final name swapped for a symlink to a FIFO.
	b := write(filepath.Join(dir, "b", "tls.crt"))
	target := filepath.Join(dir, "target-fifo")
	woken = fifoWithWriter(t, target)
	beforeTLSOpen = func() {
		if err := os.Remove(b); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(target, b); err != nil {
			t.Error(err)
		}
	}
	if _, err := m.readTLSFile(b); err == nil {
		t.Error("file swapped for a symlink to a fifo: read")
	}
	if woken() {
		t.Error("file swapped for a symlink to a fifo: opened for reading")
	}

	// A directory above it swapped for a symlink to a directory whose entry
	// of the same name is a FIFO.
	c := write(filepath.Join(dir, "c", "tls.crt"))
	evil := filepath.Join(dir, "evil")
	if err := os.Mkdir(evil, 0o700); err != nil {
		t.Fatal(err)
	}
	woken = fifoWithWriter(t, filepath.Join(evil, "tls.crt"))
	cdir := filepath.Dir(c)
	beforeTLSOpen = func() {
		if err := os.Rename(cdir, cdir+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(evil, cdir); err != nil {
			t.Error(err)
		}
	}
	if _, err := m.readTLSFile(c); err == nil {
		t.Error("directory swapped for a symlink to a fifo's: read")
	}
	if woken() {
		t.Error("directory swapped for a symlink to a fifo's: opened for reading")
	}
}
