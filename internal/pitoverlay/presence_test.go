package pitoverlay

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// C-1 of the pit-restore review: only a clean ENOENT of both the overlay and
// its binding is "absent"; any other stat error, or a binding left without
// its overlay, is "unknown" — never read as absence.
//
// Mutations "any error is absent" and "the binding is not looked at" — red.
func TestPresenceOf_OnlyENOENTOfBothIsAbsent(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "d.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(what string, want Presence) {
		t.Helper()
		if got, _ := PresenceOf(disk); got != want {
			t.Errorf("%s: PresenceOf = %v, want %v", what, got, want)
		}
	}
	check("nothing beside the disk", OverlayAbsent)

	if err := os.WriteFile(SidecarPath(disk), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("a binding with no overlay", OverlayUnknown)

	if err := os.WriteFile(Path(disk), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check("overlay and binding", OverlayPresent)

	_ = os.Remove(Path(disk))
	_ = os.Remove(SidecarPath(disk))
	for _, e := range []error{syscall.EIO, syscall.ESTALE, syscall.EACCES} {
		restore := SetLstatForTest(func(p string) (os.FileInfo, error) {
			return nil, &os.PathError{Op: "lstat", Path: p, Err: e}
		})
		got, err := PresenceOf(disk)
		restore()
		if got != OverlayUnknown || !errors.Is(err, e) {
			t.Errorf("lstat %v: PresenceOf = %v, %v; want unknown, with the error", e, got, err)
		}
	}
}

// diskToken stubs the window token getxattr reads off the disk: "" is no
// token (ENODATA); "!" is a filesystem without user xattrs.
func diskToken(t *testing.T, tok string) {
	t.Helper()
	prev := getXattr
	getXattr = func(string) ([]byte, error) {
		switch tok {
		case "":
			return nil, errNoAttr
		case "!":
			return nil, syscall.ENOTSUP
		}
		return []byte(tok), nil
	}
	t.Cleanup(func() { getXattr = prev })
}

// orphan sets aside a fake overlay of disk with a binding recording token
// (none written when token is "-").
func orphan(t *testing.T, disk, stamp, token string) {
	t.Helper()
	p := Path(disk) + ".orphan-" + stamp
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if token == "-" {
		return
	}
	if err := os.WriteFile(p+".id", []byte(`{"token":"`+token+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The set-aside evidence is an orphan of this disk's overlay, not its
// binding alone, nor another disk's.
//
// Mutations "no evidence ever" / "any file is evidence" — red.
func TestSetAsideEvidence(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "d.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	diskToken(t, "")
	if SetAsideEvidence(disk) {
		t.Fatal("evidence with nothing beside the disk")
	}
	other := filepath.Join(dir, "e.qcow2")
	orphan(t, other, "20261011-161109", "")
	if err := os.WriteFile(Path(disk)+".orphan-20261011-161109.id", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if SetAsideEvidence(disk) {
		t.Fatal("another disk's orphan, or a lone binding, taken as evidence")
	}
	if err := os.WriteFile(Path(disk)+".orphan-20261011-161109", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !SetAsideEvidence(disk) {
		t.Fatal("this disk's set-aside overlay is not evidence")
	}
}

// The evidence is bound to the window the definition names (re-review 1,
// I-1): the disk's current window token. A disk with no token (a restore
// placed a new file, and no window has opened on it since) takes any orphan
// of it; a disk with a token takes only an orphan whose binding recorded
// that token — an older window's orphan is no evidence that THIS window's
// overlay was set aside. Without user xattrs nothing can be told apart, and
// nothing counts.
//
// Mutations "the token is not compared" and "unsupported xattrs accept" — red.
func TestSetAsideEvidence_IsBoundToTheDisksWindow(t *testing.T) {
	newDisk := func(t *testing.T) string {
		t.Helper()
		disk := filepath.Join(t.TempDir(), "d.qcow2")
		if err := os.WriteFile(disk, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return disk
	}
	for _, c := range []struct {
		name      string
		diskTok   string
		orphanTok []string // per orphan; "-" is an orphan with no binding
		want      bool
	}{
		{"no token on the disk, an orphan of window A", "", []string{"aaaa"}, true},
		{"no token on the disk, an orphan with no binding", "", []string{"-"}, true},
		{"window B on the disk, only window A's orphan", "bbbb", []string{"aaaa"}, false},
		{"window B on the disk, an orphan with no binding", "bbbb", []string{"-"}, false},
		{"window B on the disk, B's orphan among others", "bbbb", []string{"aaaa", "bbbb"}, true},
		{"no user xattrs", "!", []string{"aaaa"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			disk := newDisk(t)
			diskToken(t, c.diskTok)
			for i, tok := range c.orphanTok {
				orphan(t, disk, fmt.Sprintf("2026101%d-000000", i), tok)
			}
			if got := SetAsideEvidence(disk); got != c.want {
				t.Fatalf("SetAsideEvidence = %v, want %v", got, c.want)
			}
		})
	}
}
