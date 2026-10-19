package lxc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Once the new image is in place, a replacing pull has succeeded: failing
// to remove the old one leaves a leftover for the next pull or daemon start,
// not a failed pull whose caller skips what it records with the content
// (PullOCIOptions.Publish).
func TestReplaceBundle_TheOldImageLeftBehindIsNotAFailedPull(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "web")
	stage := filepath.Join(parent, unpackDirName, "web+x")
	for dir, img := range map[string]string{dest: "old", stage: "new"} {
		if err := os.MkdirAll(filepath.Join(dir, "rootfs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(img), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prev := removeOldBundle
	t.Cleanup(func() { removeOldBundle = prev })
	removeOldBundle = func(string) error { return errors.New("injected") }
	if err := replaceBundle(stage, dest); err != nil {
		t.Fatalf("replaceBundle with the old image left behind: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "config.json")); string(b) != "new" {
		t.Fatalf("the item holds %q", b)
	}
	// The leftover goes at the item's next recovery, and the new image stays.
	if err := recoverItem(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage + oldPlus); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the old image is still at %s: %v", stage+oldPlus, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "config.json")); string(b) != "new" {
		t.Fatalf("after recovery the item holds %q", b)
	}
}
