package image

import (
	"os"
	"testing"
)

// Withdraw takes a just-published file back from being the image's current
// file (re-review 3, m-2): the name points again at what was current before,
// or at nothing when nothing was, and the file stays for the prune.
func TestWithdraw_TheNamePointsAgainAtWhatWasCurrent(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	v1, v2 := []byte("version one"), []byte("version two")

	// The image's first content withdrawn: no current file.
	p1, err := s.Publish("ubuntu", stage(t, s, v1), digestOf(v1))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Withdraw("ubuntu", p1.Path, ""); err != nil {
		t.Fatal(err)
	}
	if s.ImageExists("ubuntu") {
		t.Fatalf("after withdrawing the first content, ImagePath %s exists", s.ImagePath("ubuntu"))
	}
	if _, err := os.Stat(p1.Path); err != nil {
		t.Fatalf("the withdrawn file is gone: %v; want it left for the prune", err)
	}

	// A refresh withdrawn: the version before is current again.
	p1, err = s.Publish("ubuntu", stage(t, s, v1), digestOf(v1))
	if err != nil || s.ImagePath("ubuntu") != p1.Path {
		t.Fatalf("republish v1: %+v err=%v", p1, err)
	}
	prev := s.ImagePath("ubuntu")
	p2, err := s.Publish("ubuntu", stage(t, s, v2), digestOf(v2))
	if err != nil || s.ImagePath("ubuntu") != p2.Path {
		t.Fatalf("publish v2: %+v err=%v", p2, err)
	}
	if err := s.Withdraw("ubuntu", p2.Path, prev); err != nil {
		t.Fatal(err)
	}
	if got := s.ImagePath("ubuntu"); got != prev {
		t.Fatalf("after withdrawing the refresh, ImagePath = %s, want %s", got, prev)
	}

	// Republishing the current content made nothing current: nothing changes.
	if err := s.Withdraw("ubuntu", prev, prev); err != nil || s.ImagePath("ubuntu") != prev {
		t.Fatalf("withdraw of a republish: ImagePath %s err=%v, want %s kept", s.ImagePath("ubuntu"), err, prev)
	}
	// A file no longer current: nothing changes.
	if err := s.Withdraw("ubuntu", p2.Path, ""); err != nil || s.ImagePath("ubuntu") != prev {
		t.Fatalf("withdraw of a file not current: ImagePath %s err=%v, want %s kept", s.ImagePath("ubuntu"), err, prev)
	}
}

// A Publish of new content that lands while a Withdraw runs is not reverted:
// Withdraw's check that the stale file is still current, and its re-point,
// are one step against any Publish of the name. The Publish begins after
// Withdraw has found the stale file current; it either waits for Withdraw
// (the name's lock) or, without one, re-points the name first and is then
// reverted.
func TestWithdraw_AConcurrentPublishIsNotReverted(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	v1, stale, v3 := []byte("version one"), []byte("stale copy"), []byte("version three")
	p1, err := s.Publish("ubuntu", stage(t, s, v1), digestOf(v1))
	if err != nil {
		t.Fatal(err)
	}
	ps, err := s.Publish("ubuntu", stage(t, s, stale), digestOf(stale))
	if err != nil || s.ImagePath("ubuntu") != ps.Path {
		t.Fatalf("publish the stale copy: %+v err=%v", ps, err)
	}

	tmp3 := stage(t, s, v3)
	contended := make(chan struct{}, 1)
	s.testHooks.nameContended = func(string) {
		select {
		case contended <- struct{}{}:
		default:
		}
	}
	type result struct {
		pub Published
		err error
	}
	done := make(chan result, 1)
	s.testHooks.withdrawChecked = func() {
		go func() {
			pub, err := s.Publish("ubuntu", tmp3, digestOf(v3))
			done <- result{pub, err}
		}()
		select {
		case r := <-done: // no lock held it back: it re-pointed the name first
			done <- r
		case <-contended: // it waits for this Withdraw
		}
	}
	if err := s.Withdraw("ubuntu", ps.Path, p1.Path); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if got := s.ImagePath("ubuntu"); got != r.pub.Path {
		t.Fatalf("after a Publish during a Withdraw, ImagePath = %s, want the published %s", got, r.pub.Path)
	}
	for _, f := range []string{r.pub.Path, ps.Path, p1.Path} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s is gone: %v", f, err)
		}
	}
}

// Published.Prev is the file current as the publish read it: what a
// withdrawal of it points the name back to. A publish between an operation's
// start and its own is that file, not what was current when it began.
func TestPublish_PrevIsTheFileItSuperseded(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	v1, v3, stale := []byte("version one"), []byte("version three"), []byte("stale copy")
	p1, err := s.Publish("ubuntu", stage(t, s, v1), digestOf(v1))
	if err != nil || p1.Prev != "" {
		t.Fatalf("first content: %+v err=%v, want no Prev", p1, err)
	}
	p3, err := s.Publish("ubuntu", stage(t, s, v3), digestOf(v3))
	if err != nil || p3.Prev != p1.Path {
		t.Fatalf("refresh: %+v err=%v, want Prev %s", p3, err, p1.Path)
	}
	ps, err := s.Publish("ubuntu", stage(t, s, stale), digestOf(stale))
	if err != nil || ps.Prev != p3.Path {
		t.Fatalf("stale copy: %+v err=%v, want Prev %s", ps, err, p3.Path)
	}
	if err := s.Withdraw("ubuntu", ps.Path, ps.Prev); err != nil || s.ImagePath("ubuntu") != p3.Path {
		t.Fatalf("withdrawn to Prev: ImagePath %s err=%v, want %s", s.ImagePath("ubuntu"), err, p3.Path)
	}
	re, err := s.Publish("ubuntu", stage(t, s, v3), digestOf(v3))
	if err != nil || re.Prev != re.Path {
		t.Fatalf("republish: %+v err=%v, want Prev = Path", re, err)
	}
}

// Until a withdrawable publish is released, the file it would be withdrawn to
// is not removed; once released, it is an ordinary superseded version.
func TestRemoveImageFile_RefusesAPendingWithdrawalsTarget(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	v1, stale := []byte("version one"), []byte("stale copy")
	p1, err := s.Publish("ubuntu", stage(t, s, v1), digestOf(v1))
	if err != nil {
		t.Fatal(err)
	}
	ps, release, err := s.PublishWithdrawable("ubuntu", stage(t, s, stale), digestOf(stale))
	if err != nil || ps.Prev != p1.Path {
		t.Fatalf("withdrawable publish: %+v err=%v", ps, err)
	}
	if err := s.RemoveImageFile("ubuntu", p1.Path); err == nil {
		t.Fatal("the pending withdrawal's target was removed")
	}
	if err := s.Withdraw("ubuntu", ps.Path, ps.Prev); err != nil || s.ImagePath("ubuntu") != p1.Path {
		t.Fatalf("withdraw: ImagePath %s err=%v, want %s", s.ImagePath("ubuntu"), err, p1.Path)
	}
	release()
	release() // idempotent
	if err := s.RemoveImageFile("ubuntu", ps.Path); err != nil {
		t.Fatalf("the withdrawn file, once released: %v", err)
	}
	if err := s.RemoveImageFile("ubuntu", p1.Path); err == nil {
		t.Fatal("the current file was removed")
	}
}
