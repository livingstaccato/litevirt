package lxc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// fdSkopeo is a skopeo that logs its arguments and, for a source given as
// /proc/self/fd/N, records what it reads through that descriptor.
func fdSkopeo(t *testing.T) (log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(t.TempDir(), "skopeo-args")
	skopeo := `#!/bin/sh
echo "$@" >> ` + log + `
for a in "$@"; do last="$a"; done
rest="${last#oci:}"; layout="${rest%:*}"; tag="${rest##*:}"
mkdir -p "$layout" && echo "$tag" > "$layout/tag-$tag"
for a in "$@"; do
  case "$a" in
    *:/proc/self/fd/*) p="${a#*:}"; p="${p%%:*}"; if [ -d "$p" ]; then ls "$p" > ` + log + `.read; else cat "$p" > ` + log + `.read; fi ;;
  esac
done
`
	if err := os.WriteFile(filepath.Join(bin, "skopeo"), []byte(skopeo), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// A local source is opened once by the daemon, without following a link at
// its own name, judged as the object opened (CheckSource gets the path it
// really is), and handed to skopeo as that open descriptor: skopeo reads the
// object that was judged, whatever happens to the path afterwards.
func TestPullOCI_ALocalSourceIsOpenedJudgedAndPinned(t *testing.T) {
	fakeOCITools(t, false)
	log := fdSkopeo(t)
	real := t.TempDir()
	archive := filepath.Join(real, "img.tar")
	if err := os.WriteFile(archive, []byte("the archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(real, "layout")
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ref, judged, read string }{
		{"oci-archive:" + archive + ":v1", archive, "the archive"},
		{"dir:" + filepath.Join(real, "x", "..", "layout"), dir, "blobs"}, // cleaned before it is opened
	} {
		var got []string
		err := PullOCI(context.Background(), PullOCIOptions{Image: tc.ref, Dest: filepath.Join(t.TempDir(), "web"),
			CheckSource: func(transport, p string) error { got = append(got, transport+" "+p); return nil }})
		if err != nil {
			t.Fatalf("%s: %v", tc.ref, err)
		}
		if len(got) != 1 || !strings.HasSuffix(got[0], " "+tc.judged) {
			t.Errorf("%s: judged %v, want %s", tc.ref, got, tc.judged)
		}
		args, _ := os.ReadFile(log)
		if !strings.Contains(string(args), ":/proc/self/fd/3") || strings.Contains(string(args), real) {
			t.Errorf("%s: skopeo args %q, want the open descriptor, never the path", tc.ref, args)
		}
		if b, _ := os.ReadFile(log + ".read"); strings.TrimSpace(string(b)) != tc.read {
			t.Errorf("%s: skopeo read %q through the descriptor, want %q", tc.ref, b, tc.read)
		}
		_ = os.Remove(log)
	}
}

// A source path that is (or became, after the daemon's check) a link, a
// FIFO or a device is not followed: nothing is read and skopeo never runs.
// A link in a parent is followed, but the object it reaches is what is
// judged.
func TestPullOCI_ASwappedSourceIsNotFollowed(t *testing.T) {
	fakeOCITools(t, false)
	log := fdSkopeo(t)
	base := t.TempDir()
	target := filepath.Join(base, "target.tar")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link.tar")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	devLink := filepath.Join(base, "zero.tar")
	if err := os.Symlink("/dev/zero", devLink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(base, "fifo.tar")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(base, "dirlink")
	if err := os.Symlink(base, dirLink); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{
		"oci-archive:" + link, "docker-archive:" + devLink, "docker-archive:" + fifo,
		"docker-archive:/dev/null", "oci:" + dirLink + ":v1", "dir:" + dirLink, "dir:" + target,
	} {
		done := make(chan error, 1)
		go func() {
			done <- PullOCI(context.Background(), PullOCIOptions{Image: ref, Dest: filepath.Join(t.TempDir(), "web"),
				CheckSource: func(string, string) error { return nil }})
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("a pull from %s was accepted", ref)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("a pull from %s blocked", ref)
		}
	}
	// A link in a parent reaches the file, and the file is what is judged.
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(base, alias); err != nil {
		t.Fatal(err)
	}
	var judged string
	err := PullOCI(context.Background(), PullOCIOptions{Image: "oci-archive:" + filepath.Join(alias, "target.tar"), Dest: filepath.Join(t.TempDir(), "web"),
		CheckSource: func(_, p string) error { judged = p; return errors.New("refused by the check") }})
	if err == nil || judged != target {
		t.Errorf("through a parent link: %v, judged %q, want the check to see %s and refuse", err, judged, target)
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Fatalf("skopeo ran for a refused source: %q", b)
	}
}

// The official image named docker ("docker:dind") is a registry image, as
// any name:tag: only "docker://" is the transport.
func TestParseOCISource_TheDockerImageByShortName(t *testing.T) {
	for _, ref := range []string{"docker:dind", "docker:27", "docker"} {
		src, err := ParseOCISource(ref)
		if err != nil || src.Transport != "docker" || src.Local || src.Ref != "docker://"+ref {
			t.Errorf("ParseOCISource(%q) = %+v, %v; want the registry image docker://%s", ref, src, err, ref)
		}
	}
}
