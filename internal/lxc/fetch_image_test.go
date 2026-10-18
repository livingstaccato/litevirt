package lxc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
[ -n "$p" ] && mkdir -p "$p/$n/rootfs" && echo x > "$p/$n/config"
if [ ` + map[bool]string{true: "1", false: "0"}[rc != 0] + ` = 1 ]; then echo "ERROR: Failed to download the image index" >&2; exit 1; fi
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "lxc-create"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// A download image is fetched by lxc-create into a throwaway lxcpath, never
// into the store's own: the container of that name is not touched, and the
// throwaway is removed whether the fetch succeeds or fails.
func TestFetchImage_DownloadRunsInAThrowawayLxcpath(t *testing.T) {
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
			!strings.Contains(string(args), "-P "+filepath.Join(store, fetchDirName)+"/") {
			t.Errorf("lxc-create args %q: want the download of alpine 3.99 under %s", args, fetchDirName)
		}
		if b, _ := os.ReadFile(filepath.Join(member, "config")); string(b) != "the member" {
			t.Errorf("the member's config is now %q", b)
		}
		ents, _ := os.ReadDir(filepath.Join(store, fetchDirName))
		if len(ents) != 0 {
			t.Errorf("rc %d: the throwaway lxcpath was left behind: %v", rc, ents)
		}
	}
}

// A rootfs path is judged as Create judges it, with nothing run.
func TestFetchImage_RootfsPathIsResolvedAsCreateResolvesIt(t *testing.T) {
	log := fakeLxcCreate(t, 0)
	r := &LxcRunner{Lxcpath: t.TempDir()}
	good := mkRootfs(t, filepath.Join(t.TempDir(), "rootfs"))
	if err := r.FetchImage(context.Background(), CreateOpts{Template: good}); err != nil {
		t.Errorf("a rootfs: %v", err)
	}
	notRootfs := t.TempDir()
	if err := r.FetchImage(context.Background(), CreateOpts{Template: notRootfs}); err == nil {
		t.Errorf("a directory that is not a rootfs was accepted")
	}
	if err := r.FetchImage(context.Background(), CreateOpts{Template: "/nonexistent/rootfs"}); err == nil {
		t.Errorf("a missing path was accepted")
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Errorf("lxc-create ran for a rootfs path: %q", b)
	}
}
