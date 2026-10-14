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
