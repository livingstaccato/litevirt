package ssh

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

// Every known_hosts source is checked on its own: a key that one file
// matches is refused when another file that records the host disagrees.
// Merging the files into one database let any match win, so a stale or
// planted entry in ~/.ssh/known_hosts overrode the operator's pin.

// Lab 4 (rc2) repro: genuine key in ~/.ssh/known_hosts, a different key
// pinned in the configured UserKnownHostsFile. ssh, reading only the
// configured file, refuses; so must litevirt.
func TestPerSource_WrongPinWithGenuineDefault(t *testing.T) {
	for _, strict := range []bool{true, false} {
		name := map[bool]string{true: "strict", false: "accept-new"}[strict]
		t.Run(name, func(t *testing.T) {
			extra := "  UserKnownHostsFile %H/pinned_kh\n"
			if strict {
				extra += "  StrictHostKeyChecking yes\n"
			}
			ed := ed25519Signer(t)
			home, addr := configServer(t, extra, ed)
			pin := filepath.Join(home, "pinned_kh")
			writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
			writeFile(t, pin, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
			err := dialLabnode(t)
			if err == nil || !strings.Contains(err.Error(), "CHANGED") || !strings.Contains(err.Error(), pin) {
				t.Fatalf("err = %v, want CHANGED naming %s", err, pin)
			}
		})
	}
}

// The other way round: a stale ~/.ssh/known_hosts entry with a correct pin
// is refused too. Stricter than ssh, which would read only the pin file; the
// stale entry must be removed (documented).
func TestPerSource_StaleDefaultWithCorrectPin(t *testing.T) {
	ed := ed25519Signer(t)
	home, addr := configServer(t, "  UserKnownHostsFile %H/pinned_kh\n", ed)
	def := filepath.Join(home, ".ssh", "known_hosts")
	writeFile(t, def, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	writeFile(t, filepath.Join(home, "pinned_kh"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "CHANGED") || !strings.Contains(err.Error(), def) {
		t.Fatalf("err = %v, want CHANGED naming %s", err, def)
	}
}

// A global known_hosts file that disagrees with a matching user file refuses.
func TestPerSource_GlobalConflicts(t *testing.T) {
	ed := ed25519Signer(t)
	home, addr := configServer(t, "  GlobalKnownHostsFile %H/global_kh\n", ed)
	g := filepath.Join(home, "global_kh")
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
	writeFile(t, g, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "CHANGED") || !strings.Contains(err.Error(), g) {
		t.Fatalf("err = %v, want CHANGED naming %s", err, g)
	}
}

// A @cert-authority line in one file vouches for the host's certificate, and
// another file records a different plain key for the host: refused, since
// that file does not vouch for what the host presented.
func TestPerSource_CAInOneFilePlainConflictInAnother(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	home, addr := configServer(t, "  UserKnownHostsFile %H/ca_kh\n", hostCert(t, ca, ed, "127.0.0.1"), ed)
	writeFile(t, filepath.Join(home, "ca_kh"), caLine(addr, ca.PublicKey()))
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	if err := dialLabnode(t); err == nil {
		t.Fatal("a certificate one file vouches for was accepted although another file records a different key")
	}
}

// What still holds: several sources agreeing is accepted, a source with no
// entry for the host does not count, several keys for the host in ONE file
// accept on any match (as ssh), and a host no source knows is first contact.
func TestPerSource_AgreementAndAbsence(t *testing.T) {
	t.Run("all sources agree", func(t *testing.T) {
		ed := ed25519Signer(t)
		home, addr := configServer(t, "  UserKnownHostsFile %H/pinned_kh\n  GlobalKnownHostsFile %H/global_kh\n", ed)
		line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey())
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), line)
		writeFile(t, filepath.Join(home, "pinned_kh"), line)
		writeFile(t, filepath.Join(home, "global_kh"), line)
		if err := dialLabnode(t); err != nil {
			t.Fatalf("three agreeing sources refused: %v", err)
		}
	})
	t.Run("other sources do not know the host", func(t *testing.T) {
		ed := ed25519Signer(t)
		home, addr := configServer(t, "  UserKnownHostsFile %H/pinned_kh\n  GlobalKnownHostsFile %H/global_kh\n", ed)
		other := knownhosts.Line([]string{"other.example"}, ed25519Signer(t).PublicKey())
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), other)
		writeFile(t, filepath.Join(home, "pinned_kh"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
		writeFile(t, filepath.Join(home, "global_kh"), other)
		if err := dialLabnode(t); err != nil {
			t.Fatalf("one matching source, the rest silent, refused: %v", err)
		}
	})
	t.Run("two keys for the host in one file", func(t *testing.T) {
		ed := ed25519Signer(t)
		home, addr := configServer(t, "", ed)
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"),
			knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()),
			knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
		if err := dialLabnode(t); err != nil {
			t.Fatalf("a file holding the genuine key among others refused: %v", err)
		}
	})
	t.Run("no source knows the host", func(t *testing.T) {
		home, _ := configServer(t, "  UserKnownHostsFile %H/pinned_kh\n", ed25519Signer(t))
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{"other.example"}, ed25519Signer(t).PublicKey()))
		writeFile(t, filepath.Join(home, "pinned_kh"), knownhosts.Line([]string{"other2.example"}, ed25519Signer(t).PublicKey()))
		if err := dialLabnode(t); err != nil {
			t.Fatalf("first contact refused: %v", err)
		}
	})
	t.Run("UserKnownHostsFile /dev/null keeps the default's pin", func(t *testing.T) {
		home, addr := configServer(t, "  UserKnownHostsFile /dev/null\n", ed25519Signer(t))
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
		if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "CHANGED") {
			t.Fatalf("err = %v, want CHANGED", err)
		}
	})
}

// HostKeyAlias: the per-source rule applies under the alias's name too.
func TestPerSource_AliasConflict(t *testing.T) {
	ed := ed25519Signer(t)
	home, _ := configServer(t, "  HostKeyAlias pinned-alias\n  UserKnownHostsFile %H/pinned_kh\n", ed)
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{"pinned-alias"}, ed.PublicKey()))
	writeFile(t, filepath.Join(home, "pinned_kh"), knownhosts.Line([]string{"pinned-alias"}, ed25519Signer(t).PublicKey()))
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Fatalf("err = %v, want CHANGED under the alias", err)
	}
}

// Type mismatch applies per source: a file that records the host only under
// another key type cannot vouch for the presented key, and refuses, even when
// another file matches it. Otherwise a stale ed25519 entry in one file would
// override an RSA-only pin in another.
func TestPerSource_TypeMismatchInAnotherSourceRefuses(t *testing.T) {
	ed, ec := ed25519Signer(t), ecdsaSigner(t)
	home, addr := configServer(t, "  GlobalKnownHostsFile %H/global_kh\n", ed, ec)
	g := filepath.Join(home, "global_kh")
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
	writeFile(t, g, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ecdsaSigner(t).PublicKey()))
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), g) {
		t.Fatalf("err = %v, want a refusal naming %s", err, g)
	}
}
