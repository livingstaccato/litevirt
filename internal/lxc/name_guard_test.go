package lxc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A legacy record's name reaches the runtime unchecked (a relocation
// recreate builds CreateOpts from a replicated row). Create, CloneContainer
// and Delete refuse a name that is not a container name, so a ".." can never
// make a path the store's parent, and leave the store as it was.
func TestRuntimeRefusesANameThatIsNotAContainerName(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls")
	for _, tool := range []string{"lxc-create", "lxc-destroy", "lxc-copy"} {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\necho "+tool+" \"$@\" >> "+log+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	parent := t.TempDir()
	store := filepath.Join(parent, "lxc")
	if err := os.MkdirAll(filepath.Join(store, "web", "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := mkRootfs(t, filepath.Join(t.TempDir(), "img", "rootfs"))
	r := &LxcRunner{Lxcpath: store}
	ctx := context.Background()
	for _, bad := range []string{"..", "."} {
		if _, err := r.Create(ctx, CreateOpts{Name: bad, Template: src}); err == nil {
			t.Errorf("Create(%q) from a rootfs was accepted", bad)
		}
		if _, err := r.Create(ctx, CreateOpts{Name: bad, Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"}); err == nil {
			t.Errorf("Create(%q) from download was accepted", bad)
		}
		if err := r.CloneContainer(ctx, "web", bad); err == nil {
			t.Errorf("CloneContainer(web, %q) was accepted", bad)
		}
		if err := r.CloneContainer(ctx, bad, "copy"); err == nil {
			t.Errorf("CloneContainer(%q, copy) was accepted", bad)
		}
		if err := r.Delete(ctx, bad); err == nil {
			t.Errorf("Delete(%q) was accepted", bad)
		}
	}
	// A clone whose source or target path leaves the store.
	if err := os.MkdirAll(filepath.Join(parent, "outside", "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "outside", "config"), []byte("lxc.rootfs.path = dir:"+filepath.Join(parent, "outside", "rootfs")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.CloneContainer(ctx, "web", "../escaped"); err == nil {
		t.Error("CloneContainer(web, ../escaped) was accepted")
	}
	if err := r.CloneContainer(ctx, "../outside", "copy2"); err == nil {
		t.Error("CloneContainer(../outside, copy2) was accepted")
	}
	for _, p := range []string{filepath.Join(parent, "escaped"), filepath.Join(store, "copy2")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("a clone wrote %s", p)
		}
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Errorf("an lxc tool ran for a bad name: %q", b)
	}
	if _, err := os.Stat(filepath.Join(parent, "keep")); err != nil {
		t.Error("the store's parent lost a file")
	}
	if _, err := os.Stat(filepath.Join(store, "web", "rootfs")); err != nil {
		t.Error("the store lost a container")
	}
	if _, err := os.Stat(filepath.Join(parent, "rootfs")); err == nil {
		t.Error("a rootfs was copied beside the store")
	}
}

// adoptFetched checks the name itself: a stage planted for ".." is never
// moved into place.
func TestAdoptFetched_RefusesABadName(t *testing.T) {
	store := t.TempDir()
	r := &LxcRunner{Lxcpath: store}
	opts := CreateOpts{Name: "..", Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"}
	stage := filepath.Join(store, fetchDirName, "..")
	if err := os.MkdirAll(filepath.Join(stage, ".."), 0o755); err != nil {
		t.Fatal(err)
	}
	if adopted, err := r.adoptFetched(opts); err == nil || adopted {
		t.Fatalf("adoptFetched(..) = %v, %v; want a refusal", adopted, err)
	}
}

// A container whose name starts with "." (earlier releases allowed one)
// that uses an item's rootfs in place is a holder like any other; only the
// fetch staging directory is skipped.
func TestRootfsReferences_ADotNamedHolder(t *testing.T) {
	store, item := t.TempDir(), filepath.Join(t.TempDir(), "web")
	for n, ref := range map[string]string{
		".web":       filepath.Join(item, "rootfs"),
		fetchDirName: filepath.Join(item, "rootfs"), // not a container
	} {
		if err := os.MkdirAll(filepath.Join(store, n), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store, n, "config"), []byte("lxc.rootfs.path = dir:"+ref+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := (&LxcRunner{Lxcpath: store}).RootfsReferences(item)
	if err != nil || strings.Join(got, ",") != ".web" {
		t.Fatalf("RootfsReferences = %v (%v), want [.web]", got, err)
	}
}

// A ref that reaches the item through an alias and leaves it through an
// in-image link still runs from the item's tree.
func TestRootfsReferences_AliasThenLink(t *testing.T) {
	store, real, outside := t.TempDir(), t.TempDir(), t.TempDir()
	item := filepath.Join(real, "web")
	if err := os.MkdirAll(filepath.Join(item, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(item, "rootfs", "srv")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(store, "old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "old", "config"), []byte("lxc.rootfs.path = dir:"+filepath.Join(alias, "web", "rootfs", "srv")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := (&LxcRunner{Lxcpath: store}).RootfsReferences(item)
	if err != nil || strings.Join(got, ",") != "old" {
		t.Fatalf("RootfsReferences = %v (%v), want [old]", got, err)
	}
}
