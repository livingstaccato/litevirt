package lxc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeOCITools puts a skopeo and a umoci on PATH that behave as the real ones
// do for PullOCI: skopeo copies into an OCI layout (recording the tag), and
// umoci unpack writes a bundle (config.json + rootfs/) and, as the real one
// does, refuses a bundle directory that already holds a config.json or a
// rootfs. failUnpack makes umoci fail on any bundle.
func fakeOCITools(t *testing.T, failUnpack bool) {
	t.Helper()
	bin := t.TempDir()
	skopeo := `#!/bin/sh
for a in "$@"; do last="$a"; done
# last is oci:<layout>:<tag>
rest="${last#oci:}"; layout="${rest%:*}"; tag="${rest##*:}"
mkdir -p "$layout" && echo "$tag" > "$layout/tag-$tag"
`
	fail := "0"
	if failUnpack {
		fail = "1"
	}
	umoci := `#!/bin/sh
img=""; bundle=""
while [ $# -gt 0 ]; do
  case "$1" in
    unpack|--rootless) ;;
    --image) img="$2"; shift ;;
    *) bundle="$1" ;;
  esac
  shift
done
[ -n "$FAKE_UMOCI_LOG" ] && echo "$bundle" >> "$FAKE_UMOCI_LOG"
if [ ` + fail + ` = 1 ]; then echo "umoci: get manifest: blob not found" >&2; exit 1; fi
mkdir -p "$bundle"
if [ -e "$bundle/config.json" ]; then echo "create runtime bundle: config.json already exists" >&2; exit 1; fi
if [ -e "$bundle/rootfs" ]; then echo "create runtime bundle: rootfs ($bundle/rootfs) already exists" >&2; exit 1; fi
tag="${img##*:}"
mkdir -p "$bundle/rootfs/etc" && echo "$tag" > "$bundle/rootfs/etc/image" && echo '{}' > "$bundle/config.json"
`
	for name, body := range map[string]string{"skopeo": skopeo, "umoci": umoci} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func imageIn(t *testing.T, dest string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dest, "rootfs", "etc", "image"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// A pull with Replace into an item that already exists replaces it: an
// Admin claiming an owner-less library item for a project (lv ct pull
// --project) unpacks over a bundle umoci already wrote, and umoci refuses a
// bundle that holds a config.json — every such pull failed with
// "config.json already exists". Each pull writes a new generation.
func TestPullOCI_ReplaceOverAnExistingItemReplacesIt(t *testing.T) {
	fakeOCITools(t, false)
	lib := t.TempDir()
	dest := filepath.Join(lib, "web")
	ctx := context.Background()
	if err := PullOCI(ctx, PullOCIOptions{Image: "docker.io/library/alpine:3.21", Dest: dest}); err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if got := imageIn(t, dest); got != "3.21" {
		t.Fatalf("after the first pull the item holds %q", got)
	}
	gen1 := ReadImageGen(dest)
	if gen1 == "" {
		t.Fatal("the pull wrote no image generation")
	}
	if err := PullOCI(ctx, PullOCIOptions{Image: "docker.io/library/alpine:3.22", Dest: dest, Replace: true}); err != nil {
		t.Fatalf("pull over the existing item: %v", err)
	}
	if got := imageIn(t, dest); got != "3.22" {
		t.Fatalf("after the second pull the item holds %q, want 3.22", got)
	}
	if gen2 := ReadImageGen(dest); gen2 == "" || gen2 == gen1 {
		t.Fatalf("the replacing pull's generation %q, want a new one (was %q)", gen2, gen1)
	}
	ents, _ := os.ReadDir(lib)
	for _, e := range ents {
		if e.Name() != "web" && e.Name() != "web.oci" {
			t.Errorf("the pull left %s behind in the library", e.Name())
		}
	}
}

// A pull over an existing item that fails to unpack leaves the item as it
// was.
func TestPullOCI_AFailedPullKeepsTheExistingItem(t *testing.T) {
	fakeOCITools(t, false)
	lib := t.TempDir()
	dest := filepath.Join(lib, "web")
	ctx := context.Background()
	if err := PullOCI(ctx, PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err != nil {
		t.Fatal(err)
	}
	fakeOCITools(t, true)
	if err := PullOCI(ctx, PullOCIOptions{Image: "alpine:3.22", Dest: dest, Replace: true}); err == nil {
		t.Fatal("a failing unpack reported success")
	}
	if got := imageIn(t, dest); got != "3.21" {
		t.Fatalf("after a failed pull the item holds %q, want 3.21 as it was", got)
	}
	ents, _ := os.ReadDir(lib)
	for _, e := range ents {
		if e.Name() != "web" && e.Name() != "web.oci" {
			t.Errorf("the failed pull left %s behind in the library", e.Name())
		}
	}
}

// A destination that is not a bundle umoci wrote (a rootfs with no
// config.json beside it, and other files) is never replaced: umoci refuses
// it as before, and nothing in it is removed.
func TestPullOCI_ADirectoryThatIsNotABundleIsNotReplaced(t *testing.T) {
	fakeOCITools(t, false)
	dest := filepath.Join(t.TempDir(), "srv")
	if err := os.MkdirAll(filepath.Join(dest, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "notes"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.22", Dest: dest}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("pull into a directory holding a rootfs and no config.json: %v, want umoci's refusal", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "notes")); err != nil || string(b) != "keep" {
		t.Fatalf("a file in the destination was lost: %q %v", b, err)
	}
}

// Without Replace a pull over an existing item is refused, as umoci refused
// it, and the item is left as it was.
func TestPullOCI_WithoutReplaceAnExistingItemIsRefused(t *testing.T) {
	fakeOCITools(t, false)
	dest := filepath.Join(t.TempDir(), "web")
	ctx := context.Background()
	if err := PullOCI(ctx, PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err != nil {
		t.Fatal(err)
	}
	gen := ReadImageGen(dest)
	if err := PullOCI(ctx, PullOCIOptions{Image: "alpine:3.22", Dest: dest}); !errors.Is(err, ErrOCIItemExists) {
		t.Fatalf("a pull over an existing item without Replace: %v, want ErrOCIItemExists", err)
	}
	if got := imageIn(t, dest); got != "3.21" || ReadImageGen(dest) != gen {
		t.Fatalf("the item now holds %q (generation changed: %v)", got, ReadImageGen(dest) != gen)
	}
}

// What a crash leaves of a replacing pull is finished at start: an old
// bundle whose item is missing goes back, one whose item is there and every
// unpack directory are removed. The leftovers live in a directory whose name
// no item can have, so an item named like one (a pull --dest
// .web.unpack-1) is never touched.
func TestRecoverOCILibrary(t *testing.T) {
	lib := t.TempDir()
	mk := func(rel, marker string) {
		if err := os.MkdirAll(filepath.Join(lib, rel, "rootfs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(lib, rel, "m"), []byte(marker), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk(filepath.Join(unpackDirName, "web+1+old"), "web-old") // crash between the renames: web missing
	mk(filepath.Join(unpackDirName, "web+2"), "web-stage")   // a staged unpack
	mk("db", "db-new")                                       // swap finished
	mk(filepath.Join(unpackDirName, "db+3+old"), "db-old")   // ...but the old one was not removed
	mk(".web.unpack-1", "user item")                         // an item a user named like a leftover
	mk(".x.unpack-2.old", "user item 2")
	mk("notes", "keep")
	if err := RecoverOCILibrary(lib); err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string { b, _ := os.ReadFile(filepath.Join(lib, rel, "m")); return string(b) }
	if read("web") != "web-old" {
		t.Errorf("web holds %q, want the old bundle put back", read("web"))
	}
	if read("db") != "db-new" || read("notes") != "keep" || read(".web.unpack-1") != "user item" || read(".x.unpack-2.old") != "user item 2" {
		t.Errorf("an item was changed: db=%q notes=%q .web.unpack-1=%q .x.unpack-2.old=%q",
			read("db"), read("notes"), read(".web.unpack-1"), read(".x.unpack-2.old"))
	}
	if ents, _ := os.ReadDir(filepath.Join(lib, unpackDirName)); len(ents) != 0 {
		t.Errorf("leftovers survived the recovery: %v", ents)
	}
}

// A replacing pull stages in the reserved directory, never beside the item
// under a name an item could have.
func TestPullOCI_ReplaceStagesInTheReservedDir(t *testing.T) {
	fakeOCITools(t, false)
	lib := t.TempDir()
	dest := filepath.Join(lib, "web")
	ctx := context.Background()
	if err := PullOCI(ctx, PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err != nil {
		t.Fatal(err)
	}
	umoci := filepath.Join(t.TempDir(), "umoci-args")
	t.Setenv("FAKE_UMOCI_LOG", umoci)
	if err := PullOCI(ctx, PullOCIOptions{Image: "alpine:3.22", Dest: dest, Replace: true}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(umoci)
	if !strings.Contains(string(b), filepath.Join(lib, unpackDirName)+"/web+") {
		t.Fatalf("the replacing pull unpacked into %q, want under %s", b, unpackDirName)
	}
}

// RootfsReferences names every container whose config uses the item's
// rootfs in place, and only those.
func TestRootfsReferences(t *testing.T) {
	store, item := t.TempDir(), filepath.Join(t.TempDir(), "web")
	cfg := map[string]string{
		"old1":  "lxc.rootfs.path = dir:" + filepath.Join(item, "rootfs") + "\n",
		"old2":  "lxc.uts.name = old2\nlxc.rootfs.path = " + filepath.Join(item, "rootfs", "sub") + "\n",
		"copy":  "lxc.rootfs.path = dir:" + filepath.Join(store, "copy", "rootfs") + "\n",
		"other": "lxc.rootfs.path = dir:" + item + "2/rootfs\n",
	}
	for n, c := range cfg {
		if err := os.MkdirAll(filepath.Join(store, n), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store, n, "config"), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := &LxcRunner{Lxcpath: store}
	got, err := r.RootfsReferences(item)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "old1,old2" {
		t.Fatalf("RootfsReferences = %v, want [old1 old2]", got)
	}
}

// A replacing pull waits for whatever holds the item's lock (a create
// copying it), so no create copies a bundle half replaced.
func TestPullOCI_ReplaceWaitsForTheItemLock(t *testing.T) {
	fakeOCITools(t, false)
	dest := filepath.Join(t.TempDir(), "web")
	ctx := context.Background()
	if err := PullOCI(ctx, PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err != nil {
		t.Fatal(err)
	}
	unlock := LockOCIItem(dest)
	done := make(chan error, 1)
	go func() { done <- PullOCI(ctx, PullOCIOptions{Image: "alpine:3.22", Dest: dest, Replace: true}) }()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("the replacing pull did not wait for the item's lock (%v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	if got := imageIn(t, dest); got != "3.21" {
		t.Fatalf("the item changed under its lock: %q", got)
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A create from a library item copies it under the item's lock, and records
// the generation it copied.
func TestCreateFromAnItem_HoldsTheLockAndRecordsTheGeneration(t *testing.T) {
	fakeOCITools(t, false)
	dest := filepath.Join(t.TempDir(), "web")
	if err := PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err != nil {
		t.Fatal(err)
	}
	mkRootfs(t, filepath.Join(dest, "rootfs"))
	r := &LxcRunner{Lxcpath: t.TempDir()}
	unlock := LockOCIItem(dest)
	type res struct {
		c   *Container
		err error
	}
	done := make(chan res, 1)
	go func() {
		c, err := r.Create(context.Background(), CreateOpts{Name: "ct", Template: filepath.Join(dest, "rootfs")})
		done <- res{c, err}
	}()
	select {
	case <-done:
		unlock()
		t.Fatal("the create did not wait for the item's lock")
	case <-time.After(300 * time.Millisecond):
	}
	unlock()
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.c.ImageGen == "" || got.c.ImageGen != ReadImageGen(dest) {
		t.Fatalf("the create recorded generation %q, want the item's %q", got.c.ImageGen, ReadImageGen(dest))
	}
}

// A container created through another path to the item (a symlinked data
// directory) uses it in place too, and is named; a pull through either path
// takes the same lock.
func TestRootfsReferences_ThroughAnAlias(t *testing.T) {
	store, real := t.TempDir(), t.TempDir()
	item := filepath.Join(real, "web")
	if err := os.MkdirAll(filepath.Join(item, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(store, "old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "old", "config"), []byte("lxc.rootfs.path = dir:"+filepath.Join(alias, "web", "rootfs")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &LxcRunner{Lxcpath: store}
	got, err := r.RootfsReferences(item)
	if err != nil || strings.Join(got, ",") != "old" {
		t.Fatalf("RootfsReferences through an alias = %v (%v), want [old]", got, err)
	}
	unlock := LockOCIItem(item)
	done := make(chan struct{})
	go func() { LockOCIItem(filepath.Join(alias, "web"))(); close(done) }()
	select {
	case <-done:
		unlock()
		t.Fatal("the lock taken through an alias is another lock")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	<-done
}
