package lxc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// A pull into an item that already exists replaces it: an Admin claiming an
// owner-less library item for a project (lv ct pull --project), or anyone
// re-pulling an item, unpacks over a bundle umoci already wrote, and umoci
// refuses a bundle that holds a config.json — every such pull failed with
// "config.json already exists".
func TestPullOCI_OverAnExistingItemReplacesIt(t *testing.T) {
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
	if err := PullOCI(ctx, PullOCIOptions{Image: "docker.io/library/alpine:3.22", Dest: dest}); err != nil {
		t.Fatalf("pull over the existing item: %v", err)
	}
	if got := imageIn(t, dest); got != "3.22" {
		t.Fatalf("after the second pull the item holds %q, want 3.22", got)
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
	if err := PullOCI(ctx, PullOCIOptions{Image: "alpine:3.22", Dest: dest}); err == nil {
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
