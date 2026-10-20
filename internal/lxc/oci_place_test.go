package lxc

import (
	"os"
	"path/filepath"
	"testing"
)

// stagedPull lays down an unpacked bundle at <parent>/.litevirt+unpack/<item>+x
// whose config.json says what, and returns it.
func stagedPull(t *testing.T, parent, item, what string) string {
	t.Helper()
	stage := filepath.Join(parent, unpackDirName, item+"+x")
	if err := os.MkdirAll(filepath.Join(stage, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "config.json"), []byte(what), 0o644); err != nil {
		t.Fatal(err)
	}
	return stage
}

// A pull with a project puts its owner in the bundle before the rename, so
// the item and its owner go in place together: as Publish runs, the item
// at Dest already records the new owner.
func TestPlacePulled_TheOwnerGoesInPlaceWithTheContent(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "web")
	old := stagedPull(t, parent, "old", "old")
	if err := writeOwner(old, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(old, dest); err != nil {
		t.Fatal(err)
	}
	stage := stagedPull(t, parent, "web", "new")
	var atPublish string
	err := placePulled(stage, PullOCIOptions{Dest: dest, Owner: "other", Publish: func() error {
		atPublish, _, _ = ReadOwner(dest)
		return nil
	}}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "config.json")); string(b) != "new" {
		t.Fatalf("the item holds %q", b)
	}
	if owner, ok, err := ReadOwner(dest); err != nil || !ok || owner != "other" || atPublish != "other" {
		t.Fatalf("owner %q (%v %v), at publish %q; want the pull's project, in place with the content", owner, ok, err, atPublish)
	}
}

// A first pull with a project makes the item that project's.
func TestPlacePulled_AFirstPullIsOwned(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "web")
	stage := stagedPull(t, parent, "web", "new")
	if err := placePulled(stage, PullOCIOptions{Dest: dest, Owner: "acme"}, false, true); err != nil {
		t.Fatal(err)
	}
	if owner, ok, _ := ReadOwner(dest); !ok || owner != "acme" {
		t.Fatalf("a first pull's item is owned by %q (%v)", owner, ok)
	}
}

// When the owner cannot be recorded in the bundle, nothing goes in place:
// the item keeps its content and its owner.
func TestPlacePulled_AnOwnerThatCannotBeRecordedLeavesTheItem(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "web")
	old := stagedPull(t, parent, "old", "old")
	if err := writeOwner(old, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(old, dest); err != nil {
		t.Fatal(err)
	}
	stage := stagedPull(t, parent, "web", "new")
	// The record's name is taken by a directory: it cannot be written.
	if err := os.MkdirAll(filepath.Join(stage, OwnerFile, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	published := false
	err := placePulled(stage, PullOCIOptions{Dest: dest, Owner: "other", Publish: func() error { published = true; return nil }}, true, false)
	if err == nil {
		t.Fatal("the pull succeeded without recording its owner")
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "config.json")); string(b) != "old" || published {
		t.Fatalf("the item holds %q (published %v), want it as it was", b, published)
	}
	if owner, _, _ := ReadOwner(dest); owner != "acme" {
		t.Fatalf("the item's owner is %q, want it as it was", owner)
	}
}
