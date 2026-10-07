//go:build unix

package qcow2

import (
	"context"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// m8: the chain reader judges a backing's file type before opening it. A FIFO
// named as a backing — raw or qcow2 — is refused at once; opening it would
// block forever.
func TestConvertConfined_AFIFOBackingIsRefusedWithoutBlocking(t *testing.T) {
	for _, format := range []string{"raw", "qcow2"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			fifo := filepath.Join(dir, "pipe")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			overlay := filepath.Join(dir, "o.qcow2")
			if err := CreateWithBackingFormat(overlay, fifo, format, 1<<20, nil); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- ConvertConfined(context.Background(), overlay, filepath.Join(dir, "out.qcow2"), nil, nil)
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Error("a FIFO backing was read")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the chain reader blocked opening a FIFO backing")
			}
		})
	}
}

// m6: a v2 image's header extensions start right after its 72-byte header
// (it has no header_length field), as qemu reads them: the backing format a
// qemu-made v2 overlay declares is read, not missed.
func TestInfo_V2HeaderBackingFormatIsRead(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "base.raw")
	if out, err := exec.Command("qemu-img", "create", "-q", "-f", "raw", base, "1M").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	overlay := filepath.Join(dir, "o.qcow2")
	if out, err := exec.Command("qemu-img", "create", "-q", "-f", "qcow2", "-o", "compat=0.10",
		"-b", base, "-F", "raw", overlay).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	info, err := Info(overlay)
	if err != nil {
		t.Fatal(err)
	}
	if info.BackingFormat != "raw" {
		t.Errorf("v2 overlay's backing format = %q, want %q (what qemu reads)", info.BackingFormat, "raw")
	}
	if n, err := BackingFormatExtensionCount(overlay); err != nil || n != 1 {
		t.Errorf("BackingFormatExtensionCount = %d, %v; want 1", n, err)
	}
}
