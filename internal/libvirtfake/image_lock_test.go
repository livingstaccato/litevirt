package libvirtfake

import (
	"strings"
	"testing"
)

// A paused QEMU still holds its image: a start of the same image on another
// member fails with QEMU's lock error, and succeeds once the holder is
// destroyed. A domain on a member with no shared image, and a fake that never
// joined, start as before.
//
// Mutations: count only running holders — the paused case starts and this
// goes red; skip the check — the running case starts and this goes red.
func TestImageLocks_ALiveOrPausedHolderRefusesTheStart(t *testing.T) {
	l := NewImageLocks()
	a, b := New(), New()
	l.Join(a)
	l.Join(b)
	l.Declare("vm", "/mnt/nfs/vm-root.qcow2")
	a.SetState("vm", StateRunning)
	b.SetState("vm", StateDefined)
	b.SetState("other", StateDefined)

	err := b.StartDomain("vm")
	if err == nil || !strings.Contains(err.Error(), `Failed to get "write" lock`) ||
		!strings.Contains(err.Error(), "/mnt/nfs/vm-root.qcow2") {
		t.Fatalf("start while a's copy runs = %v, want the image-lock refusal", err)
	}
	if err := a.SuspendDomain("vm"); err != nil {
		t.Fatal(err)
	}
	if err := b.StartDomain("vm"); err == nil {
		t.Fatal("start succeeded while a's PAUSED copy still holds the image")
	}
	if st, _ := b.RawState("vm"); st != StateDefined {
		t.Fatalf("a refused start left b's domain %s", st)
	}
	if err := b.StartDomain("other"); err != nil {
		t.Fatalf("a domain with no shared image was refused: %v", err)
	}

	if err := a.DestroyDomain("vm"); err != nil {
		t.Fatal(err)
	}
	if err := b.StartDomain("vm"); err != nil {
		t.Fatalf("start after the holder was destroyed = %v, want it to start", err)
	}
	if err := a.StartDomain("vm"); err == nil {
		t.Fatal("a started vm while b's copy holds the image")
	}

	c := New() // never joined: no cross-host locking
	c.SetState("vm", StateDefined)
	if err := c.StartDomain("vm"); err != nil {
		t.Fatalf("a fake outside the registry was refused: %v", err)
	}
}
