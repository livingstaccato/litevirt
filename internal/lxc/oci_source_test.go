package lxc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The transport is what skopeo would read: the name before the first ":"
// when it is a transport's name; a reference with none is a registry image.
func TestParseOCISource(t *testing.T) {
	for _, tc := range []struct {
		ref       string
		transport string
		path      string
		local     bool
		bad       bool
	}{
		{ref: "alpine", transport: "docker"},
		{ref: "alpine:3.19", transport: "docker"},
		{ref: "registry.local:5000/team/img:v1", transport: "docker"},
		{ref: "docker://ghcr.io/org/x:v1", transport: "docker"},
		{ref: "oci:/srv/app.oci:v2", transport: "oci", path: "/srv/app.oci", local: true},
		{ref: "oci:/srv/app.oci", transport: "oci", path: "/srv/app.oci", local: true},
		{ref: "oci:/srv/a:b:v2", transport: "oci", path: "/srv/a", local: true}, // first colon, as skopeo splits it
		{ref: "dir:/srv/img", transport: "dir", path: "/srv/img", local: true},
		{ref: "dir:///srv/img", transport: "dir", path: "/srv/img", local: true},
		{ref: "dir:/srv/a:b", transport: "dir", path: "/srv/a:b", local: true}, // dir: has no reference
		{ref: "oci-archive:/srv/x.tar", transport: "oci-archive", path: "/srv/x.tar", local: true},
		{ref: "oci-archive:///srv/x.tar:v1", transport: "oci-archive", path: "/srv/x.tar", local: true},
		{ref: "docker-archive:/srv/x.tar", transport: "docker-archive", path: "/srv/x.tar", local: true},
		{ref: "docker-archive:///dev/zero", transport: "docker-archive", path: "/dev/zero", local: true},
		{ref: "docker-daemon:alpine:latest", bad: true},
		{ref: "containers-storage:alpine", bad: true},
		{ref: "ostree:/x", bad: true},
		{ref: "sif:/x.sif", bad: true},
		{ref: "tarball:/x.tar", bad: true},
		{ref: "-alpine", bad: true},
		{ref: "", bad: true},
		{ref: "oci:", bad: true},
		{ref: "dir:relative/path", bad: true},
	} {
		src, err := ParseOCISource(tc.ref)
		if tc.bad {
			if err == nil {
				t.Errorf("ParseOCISource(%q) = %+v, want refused", tc.ref, src)
			}
			continue
		}
		if err != nil || src.Transport != tc.transport || src.Path != tc.path || src.Local != tc.local {
			t.Errorf("ParseOCISource(%q) = %+v, %v; want transport %s path %q local %v", tc.ref, src, err, tc.transport, tc.path, tc.local)
		}
	}
}

// PullOCI copies only from the allowed transports, and passes "--" before
// the positional references so no image can read as a flag.
func TestPullOCI_RefusesOtherTransportsAndEndsFlags(t *testing.T) {
	fakeOCITools(t, false)
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "skopeo-args")
	skopeo := `#!/bin/sh
echo "$@" >> ` + log + `
for a in "$@"; do last="$a"; done
rest="${last#oci:}"; layout="${rest%:*}"; tag="${rest##*:}"
mkdir -p "$layout" && echo "$tag" > "$layout/tag-$tag"
`
	if err := os.WriteFile(filepath.Join(bin, "skopeo"), []byte(skopeo), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, ref := range []string{"docker-daemon:alpine:latest", "containers-storage:alpine", "-alpine"} {
		if err := PullOCI(context.Background(), PullOCIOptions{Image: ref, Dest: filepath.Join(t.TempDir(), "web")}); err == nil {
			t.Errorf("a pull from %q was accepted", ref)
		}
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Fatalf("skopeo ran for a refused source: %q", b)
	}
	if err := PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: filepath.Join(t.TempDir(), "web")}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), "copy -- docker://alpine:3.21 oci:") {
		t.Fatalf("skopeo args %q: want -- before the references", b)
	}
}

// The pull's own temp layout is removed when the pull ends, on success and
// on failure.
func TestPullOCI_TheTempLayoutIsRemoved(t *testing.T) {
	for _, fail := range []bool{false, true} {
		fakeOCITools(t, fail)
		parent := t.TempDir()
		_ = PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: filepath.Join(parent, "web")})
		ents, _ := os.ReadDir(filepath.Join(parent, unpackDirName))
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), lockSuffix) {
				t.Errorf("fail=%v: %s left in the staging directory", fail, e.Name())
			}
		}
	}
}
