package libvirt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The swtpm tree is keyed by a UUID that reaches the wipe from a peer RPC.
// Whatever arrives, the wipe must stay inside one per-UUID directory under the
// swtpm base: never the base itself, its parent, or a sibling of the base.
func TestWipeFirmwareStateByUUID_RefusesTraversal(t *testing.T) {
	base := redirectSwtpmBase(t)
	parent := filepath.Dir(base)
	sibling := filepath.Join(parent, "x")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "11111111-2222-3333-4444-555555555555")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "tpm2-00.permall"), []byte("B"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, uuid := range []string{"..", "../x", ".", "/", "/etc", "a/../..", "x/.."} {
		WipeFirmwareStateByUUID(uuid)
		for _, p := range []string{parent, sibling, base, other} {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("WipeFirmwareStateByUUID(%q) removed %s: %v", uuid, p, err)
			}
		}
	}
}

func TestValidFirmwareUUID(t *testing.T) {
	for _, ok := range []string{
		"aad2e0bb-3311-42a9-92f9-4062205a4dc1",
		"AAD2E0BB-3311-42A9-92F9-4062205A4DC1",
	} {
		if !ValidFirmwareUUID(ok) {
			t.Errorf("ValidFirmwareUUID(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", ".", "..", "../x", "/etc", "uuid-w",
		"aad2e0bb33114 2a992f94062205a4dc1",
		"aad2e0bb331142a992f94062205a4dc1", // no dashes
		"aad2e0bb-3311-42a9-92f9-4062205a4dc1/..",
		"{aad2e0bb-3311-42a9-92f9-4062205a4dc1}",
		"urn:uuid:aad2e0bb-3311-42a9-92f9-4062205a4dc1",
	} {
		if ValidFirmwareUUID(bad) {
			t.Errorf("ValidFirmwareUUID(%q) = true, want false", bad)
		}
	}
}

// A bundle restore under a traversal UUID must not stage or swap state outside
// the base either.
func TestReadFirmwareBundle_RefusesTraversalUUID(t *testing.T) {
	base := redirectSwtpmBase(t)
	src := t.TempDir()
	seedFirmware(t, src, "src", "uuid-src", true, true)
	var buf bytes.Buffer
	if _, err := WriteFirmwareBundle(src, "src", "uuid-src", &buf); err != nil {
		t.Fatal(err)
	}
	if err := ReadFirmwareBundle(bytes.NewReader(buf.Bytes()), t.TempDir(), "dst", ".."); err == nil {
		t.Fatal("ReadFirmwareBundle accepted uuid \"..\"")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(base), "tpm2")); err == nil {
		t.Fatal("swtpm state materialised outside the swtpm base")
	}
}
