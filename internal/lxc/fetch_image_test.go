package lxc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeLxcCreate puts an lxc-create on PATH that records its arguments in
// <dir>/args and exits with rc, writing a container dir under -P first as
// the real one does.
func fakeLxcCreate(t *testing.T, rc int) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "args")
	script := `#!/bin/sh
echo "$@" >> ` + log + `
p=""; n=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) p="$2"; shift ;;
    -n) n="$2"; shift ;;
  esac
  shift
done
if [ -z "$p" ]; then p="$LXCPATH_DEFAULT"; fi
mkdir -p "$p/$n/rootfs/etc" && printf 'lxc.rootfs.path = dir:%s/%s/rootfs\nlxc.uts.name = %s\nlxc.mount.fstab = %s/%s/fstab\n' "$p" "$n" "$n" "$p" "$n" > "$p/$n/config"
echo "$n" > "$p/$n/rootfs/etc/hostname"; printf '127.0.0.1 localhost\n127.0.1.1 %s\n' "$n" > "$p/$n/rootfs/etc/hosts"
echo "proc $p/$n/rootfs/proc proc defaults 0 0" > "$p/$n/fstab"
if [ ` + map[bool]string{true: "1", false: "0"}[rc != 0] + ` = 1 ]; then echo "ERROR: Failed to download the image index" >&2; exit 1; fi
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "lxc-create"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// A download image is fetched by lxc-create into a staging lxcpath, never
// into the store's own: the container of that name is not touched, and a
// failed fetch leaves nothing staged.
func TestFetchImage_DownloadRunsInAStagingLxcpath(t *testing.T) {
	for _, rc := range []int{0, 1} {
		store := t.TempDir()
		member := filepath.Join(store, "web")
		if err := os.MkdirAll(filepath.Join(member, "rootfs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(member, "config"), []byte("the member"), 0o644); err != nil {
			t.Fatal(err)
		}
		log := fakeLxcCreate(t, rc)
		r := &LxcRunner{Lxcpath: store}
		err := r.FetchImage(context.Background(), CreateOpts{Name: "web", Template: "download", Distro: "alpine", Release: "3.99", Arch: "amd64"})
		if (err != nil) != (rc != 0) {
			t.Fatalf("rc %d: FetchImage = %v", rc, err)
		}
		if rc != 0 && !strings.Contains(err.Error(), "download the image index") {
			t.Errorf("the fetch error does not carry lxc-create's: %v", err)
		}
		args, _ := os.ReadFile(log)
		if !strings.Contains(string(args), "-t download -- -d alpine -r 3.99 -a amd64") ||
			!strings.Contains(string(args), "-P "+filepath.Join(store, fetchDirName, "web")+" ") {
			t.Errorf("lxc-create args %q: want the download of alpine 3.99 under %s", args, fetchDirName)
		}
		if b, _ := os.ReadFile(filepath.Join(member, "config")); string(b) != "the member" {
			t.Errorf("the member's config is now %q", b)
		}
		if _, err := os.Stat(filepath.Join(store, fetchDirName, "web")); (err == nil) != (rc == 0) {
			t.Errorf("rc %d: staged container present = %v", rc, err == nil)
		}
	}
}

// The create after a fetch moves the fetched container into place instead
// of running lxc-create again (a fetch of the same image is not repeated
// either), and it is configured as the container it becomes.
func TestFetchImage_TheCreateAdoptsTheFetchedContainer(t *testing.T) {
	store := t.TempDir()
	log := fakeLxcCreate(t, 0)
	r := &LxcRunner{Lxcpath: store}
	opts := CreateOpts{Name: "web", Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"}
	for i := 0; i < 2; i++ {
		if err := r.FetchImage(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Create(context.Background(), opts); err != nil {
		t.Fatalf("Create after the fetch: %v", err)
	}
	args, _ := os.ReadFile(log)
	if n := strings.Count(string(args), "lxc-create") + strings.Count(string(args), "-t download"); n != 1 {
		t.Errorf("lxc-create ran %d times (%q), want once: by the first fetch", n, args)
	}
	cfg, _ := os.ReadFile(filepath.Join(store, "web", "config"))
	if !strings.Contains(string(cfg), "lxc.rootfs.path = dir:"+filepath.Join(store, "web", "rootfs")) ||
		!strings.Contains(string(cfg), "lxc.uts.name = web") || strings.Contains(string(cfg), fetchDirName) {
		t.Errorf("the adopted container's config does not name it in place:\n%s", cfg)
	}
	if _, err := os.Stat(filepath.Join(store, fetchDirName, "web")); err == nil {
		t.Errorf("the staging directory was left behind")
	}
	// The guest is the container it became, not the staging name: the
	// download template wrote its name into /etc/hostname and /etc/hosts.
	if b, _ := os.ReadFile(filepath.Join(store, "web", "rootfs", "etc", "hostname")); strings.TrimSpace(string(b)) != "web" {
		t.Errorf("the guest's /etc/hostname is %q, want web", b)
	}
	if b, _ := os.ReadFile(filepath.Join(store, "web", "rootfs", "etc", "hosts")); !strings.Contains(string(b), "127.0.1.1 web") {
		t.Errorf("the guest's /etc/hosts is %q, want 127.0.1.1 web", b)
	}
	if b, _ := os.ReadFile(filepath.Join(store, "web", "fstab")); strings.Contains(string(b), fetchDirName) ||
		!strings.Contains(string(b), filepath.Join(store, "web", "rootfs")) {
		t.Errorf("the fstab does not name the container in place: %q", b)
	}
	// Another image for the name is not adopted: lxc-create builds it.
	other := opts
	other.Name, other.Release = "db", "3.23"
	if err := r.FetchImage(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	other.Release = "3.21"
	if _, err := r.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	args, _ = os.ReadFile(log)
	if !strings.Contains(string(args), "-n db -t download -- -d alpine -r 3.21") {
		t.Errorf("a create of another image than the one fetched did not run lxc-create: %q", args)
	}
}

// SweepFetchDir clears what an earlier run left staged.
func TestSweepFetchDir(t *testing.T) {
	store := t.TempDir()
	if err := os.MkdirAll(filepath.Join(store, fetchDirName, "web", "web", "rootfs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(store, "web"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &LxcRunner{Lxcpath: store}
	if err := r.SweepFetchDir(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store, fetchDirName)); err == nil {
		t.Error("the staging directory survived the sweep")
	}
	if _, err := os.Stat(filepath.Join(store, "web")); err != nil {
		t.Error("the sweep removed a container")
	}
}

// A rootfs path is judged as Create judges it, with nothing run.
func TestFetchImage_RootfsPathIsResolvedAsCreateResolvesIt(t *testing.T) {
	log := fakeLxcCreate(t, 0)
	r := &LxcRunner{Lxcpath: t.TempDir()}
	good := mkRootfs(t, filepath.Join(t.TempDir(), "rootfs"))
	if err := r.FetchImage(context.Background(), CreateOpts{Name: "web", Template: good}); err != nil {
		t.Errorf("a rootfs: %v", err)
	}
	notRootfs := t.TempDir()
	if err := r.FetchImage(context.Background(), CreateOpts{Name: "web", Template: notRootfs}); err == nil {
		t.Errorf("a directory that is not a rootfs was accepted")
	}
	if err := r.FetchImage(context.Background(), CreateOpts{Name: "web", Template: "/nonexistent/rootfs"}); err == nil {
		t.Errorf("a missing path was accepted")
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Errorf("lxc-create ran for a rootfs path: %q", b)
	}
}

// A staged fetch is adopted only while fresh: one left by a recreate that
// did not proceed is not taken, weeks later, by an unrelated create of the
// name, which fetches anew.
func TestFetchImage_AStaleStageIsNotAdopted(t *testing.T) {
	store := t.TempDir()
	log := fakeLxcCreate(t, 0)
	r := &LxcRunner{Lxcpath: store}
	opts := CreateOpts{Name: "web", Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"}
	if err := r.FetchImage(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * fetchStageTTL)
	if err := os.Chtimes(filepath.Join(store, fetchDirName, "web", fetchedImageFile), old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(log)
	if n := strings.Count(string(args), "-t download"); n != 2 {
		t.Fatalf("lxc-create ran %d times (%q), want twice: the stale stage is not adopted", n, args)
	}
}

// Adoption rewrites the staged container to its final place before the
// one rename that moves it: a crash at any point leaves either a stage the
// start-up sweep removes, or a complete container.
func TestFetchImage_AdoptionRepointsBeforeTheRename(t *testing.T) {
	store := t.TempDir()
	fakeLxcCreate(t, 0)
	r := &LxcRunner{Lxcpath: store}
	opts := CreateOpts{Name: "web", Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"}
	if err := r.FetchImage(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	var seen string
	adoptBeforeRename = func(built string) {
		b, _ := os.ReadFile(filepath.Join(built, "config"))
		seen = string(b)
	}
	t.Cleanup(func() { adoptBeforeRename = nil })
	if _, err := r.Create(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(seen, "lxc.rootfs.path = dir:"+filepath.Join(store, "web", "rootfs")) || strings.Contains(seen, fetchDirName) {
		t.Fatalf("at the rename the staged config was:\n%s\nwant it already naming %s", seen, filepath.Join(store, "web"))
	}
}

// A stage whose fetch time lies in the future (the clock was set back) is
// not taken as fresh.
func TestFetchImage_AStageFromTheFutureIsNotFresh(t *testing.T) {
	store := t.TempDir()
	log := fakeLxcCreate(t, 0)
	r := &LxcRunner{Lxcpath: store}
	opts := CreateOpts{Name: "web", Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"}
	if err := r.FetchImage(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(24 * time.Hour)
	if err := os.Chtimes(filepath.Join(store, fetchDirName, "web", fetchedImageFile), future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); strings.Count(string(b), "-t download") != 2 {
		t.Fatalf("a stage from the future was adopted: %q", b)
	}
}

// FetchImage refuses a name that is not a container name itself, so a
// caller's slip cannot make its staging path the store.
func TestFetchImage_RefusesABadName(t *testing.T) {
	store := t.TempDir()
	fakeLxcCreate(t, 0)
	if err := os.MkdirAll(filepath.Join(store, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &LxcRunner{Lxcpath: store}
	for _, n := range []string{"..", "."} {
		if err := r.FetchImage(context.Background(), CreateOpts{Name: n, Template: "download", Distro: "alpine", Release: "3.22"}); err == nil {
			t.Errorf("FetchImage accepted name %q", n)
		}
	}
	if _, err := os.Stat(filepath.Join(store, "web")); err != nil {
		t.Fatal("the store lost a container")
	}
}
