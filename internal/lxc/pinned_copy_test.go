package lxc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// pinnedItem lays down a library item (a bundle) of generation gen whose
// rootfs/etc/image says image, and returns its rootfs path.
func pinnedItem(t *testing.T, bundle, gen, image string) string {
	t.Helper()
	rootfs := mkRootfs(t, filepath.Join(bundle, "rootfs"))
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "image"), []byte(image), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, ImageGenFile), []byte(gen+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return rootfs
}

func ctImage(t *testing.T, lxcpath, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(lxcpath, name, "rootfs", "etc", "image"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A pinned recreate's copy is taken, from the judged generation, by the
// fetch before the delete: an item replaced between the delete and the
// create does not cost the member, which is rebuilt from that copy.
func TestCreate_APinnedRecreateIsBuiltFromTheCopyTakenBeforeTheDelete(t *testing.T) {
	tmp := t.TempDir()
	r := &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc")}
	bundle := filepath.Join(tmp, "oci", "build")
	tmpl := pinnedItem(t, bundle, "g1", "judged")
	opts := CreateOpts{Name: "web", Template: tmpl, Pinned: true, PinnedGen: "g1"}
	if err := r.FetchImage(context.Background(), opts); err != nil {
		t.Fatalf("pinned fetch: %v", err)
	}
	// An Admin's claim replaces the item after the delete.
	if err := os.RemoveAll(bundle); err != nil {
		t.Fatal(err)
	}
	pinnedItem(t, bundle, "g2", "replaced")
	c, err := r.Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("pinned create after the item was replaced: %v", err)
	}
	if got := ctImage(t, r.Lxcpath, "web"); got != "judged" {
		t.Fatalf("the member was rebuilt from %q, want the judged image", got)
	}
	if c.ImageGen != "g1" {
		t.Errorf("ImageGen %q, want g1", c.ImageGen)
	}
	if _, err := os.Stat(r.fetchStage("web")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staged copy is still there: %v", err)
	}
}

// A pinned fetch of an item that is no longer the judged generation is
// refused, before the delete, and stages nothing.
func TestFetchImage_APinnedFetchOfAReplacedItemIsRefused(t *testing.T) {
	tmp := t.TempDir()
	r := &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc")}
	tmpl := pinnedItem(t, filepath.Join(tmp, "oci", "build"), "g2", "replaced")
	err := r.FetchImage(context.Background(), CreateOpts{Name: "web", Template: tmpl, Pinned: true, PinnedGen: "g1"})
	if !errors.Is(err, ErrImageReplaced) {
		t.Fatalf("pinned fetch of a replaced item: %v, want ErrImageReplaced", err)
	}
	if _, err := os.Stat(r.fetchStage("web")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something was staged: %v", err)
	}
}

// Without a staged copy, a pinned create copies the item only while it is
// the judged generation, and creates nothing otherwise.
func TestCreate_APinnedCreateWithNoCopyRefusesAReplacedItem(t *testing.T) {
	tmp := t.TempDir()
	r := &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc")}
	tmpl := pinnedItem(t, filepath.Join(tmp, "oci", "build"), "g2", "replaced")
	_, err := r.Create(context.Background(), CreateOpts{Name: "web", Template: tmpl, Pinned: true, PinnedGen: "g1"})
	if !errors.Is(err, ErrImageReplaced) {
		t.Fatalf("pinned create of a replaced item: %v, want ErrImageReplaced", err)
	}
	if _, err := os.Stat(filepath.Join(r.Lxcpath, "web")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a container was created: %v", err)
	}
}

// The staged copy outlives a daemon restart (SweepFetchDir) for as long as
// a recreate may still need it; a day-old one goes.
func TestSweepFetchDir_KeepsAPinnedCopyARecreateMayStillNeed(t *testing.T) {
	tmp := t.TempDir()
	r := &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc")}
	bundle := filepath.Join(tmp, "oci", "build")
	tmpl := pinnedItem(t, bundle, "g1", "judged")
	for _, n := range []string{"web", "old"} {
		if err := r.FetchImage(context.Background(), CreateOpts{Name: n, Template: tmpl, Pinned: true, PinnedGen: "g1"}); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * pinnedCopyKeep)
	if err := os.Chtimes(filepath.Join(r.fetchStage("old"), fetchedImageFile), past, past); err != nil {
		t.Fatal(err)
	}
	if err := r.SweepFetchDir(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.fetchStage("old")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a day-old pinned copy was kept: %v", err)
	}
	if err := os.RemoveAll(bundle); err != nil {
		t.Fatal(err)
	}
	pinnedItem(t, bundle, "g2", "replaced")
	if _, err := r.Create(context.Background(), CreateOpts{Name: "web", Template: tmpl, Pinned: true, PinnedGen: "g1"}); err != nil {
		t.Fatalf("pinned create after a restart: %v", err)
	}
	if got := ctImage(t, r.Lxcpath, "web"); got != "judged" {
		t.Fatalf("the member was rebuilt from %q after a restart, want the judged image", got)
	}
}

// A create from the item that is not pinned leaves no pinned copy of its
// name behind (one staged for a create that came without the pin, from an
// entry on an earlier build).
func TestCreate_AnUnpinnedCreateDropsAPinnedCopyOfItsName(t *testing.T) {
	tmp := t.TempDir()
	r := &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc")}
	tmpl := pinnedItem(t, filepath.Join(tmp, "oci", "build"), "g1", "judged")
	if err := r.FetchImage(context.Background(), CreateOpts{Name: "web", Template: tmpl, Pinned: true, PinnedGen: "g1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(context.Background(), CreateOpts{Name: "web", Template: tmpl}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.fetchStage("web")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the pinned copy is still there: %v", err)
	}
}

// Create judges a library item where it copies it: CheckItem runs under the
// item's lock with the item's generation, and its refusal creates nothing.
func TestCreate_CheckItemJudgesTheItemUnderItsLock(t *testing.T) {
	tmp := t.TempDir()
	r := &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc")}
	bundle := filepath.Join(tmp, "oci", "build")
	tmpl := pinnedItem(t, bundle, "g7", "img")
	var gotGen string
	var locked bool
	refuse := errors.New("refused")
	_, err := r.Create(context.Background(), CreateOpts{Name: "web", Template: tmpl, CheckItem: func(gen string) error {
		gotGen = gen
		m, _ := ociItemLocks.Load(canonPath(bundle))
		locked = m != nil && !m.(*sync.Mutex).TryLock()
		return refuse
	}})
	if !errors.Is(err, refuse) {
		t.Fatalf("create: %v, want the check's refusal", err)
	}
	if gotGen != "g7" || !locked {
		t.Fatalf("CheckItem saw gen %q, under the item lock %v; want g7 under the lock", gotGen, locked)
	}
	if _, err := os.Stat(filepath.Join(r.Lxcpath, "web")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused create left %v", err)
	}
}

// A recreate bound to whatever generation its fetch finds is built from
// that copy too, and records that generation.
func TestCreate_ABoundRecreateIsBuiltFromItsCopyWhateverTheGeneration(t *testing.T) {
	tmp := t.TempDir()
	r := &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc")}
	bundle := filepath.Join(tmp, "oci", "build")
	tmpl := pinnedItem(t, bundle, "g5", "judged")
	opts := CreateOpts{Name: "web", Template: tmpl, Pinned: true, PinAnyGen: true}
	if err := r.FetchImage(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(bundle); err != nil {
		t.Fatal(err)
	}
	pinnedItem(t, bundle, "g6", "replaced")
	c, err := r.Create(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := ctImage(t, r.Lxcpath, "web"); got != "judged" || c.ImageGen != "g5" {
		t.Fatalf("built from %q at %q, want the copy (judged, g5)", got, c.ImageGen)
	}
}

// The copy is judged where it is taken: CheckItem's refusal stages nothing.
func TestFetchImage_APinnedCopyIsJudgedUnderTheItemLock(t *testing.T) {
	tmp := t.TempDir()
	r := &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc")}
	tmpl := pinnedItem(t, filepath.Join(tmp, "oci", "build"), "g1", "img")
	refuse := errors.New("not this project's")
	err := r.FetchImage(context.Background(), CreateOpts{Name: "web", Template: tmpl, Pinned: true, PinAnyGen: true,
		CheckItem: func(string) error { return refuse }})
	if !errors.Is(err, refuse) {
		t.Fatalf("fetch: %v, want the check's refusal", err)
	}
	if _, err := os.Stat(r.fetchStage("web")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something was staged: %v", err)
	}
}
