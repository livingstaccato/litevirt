package lxc

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/safename"
)

// N5: a rootfs of many small files, exported, laid down by the importer's
// extractor somewhere else (a migrate, a restore, a replica promotion), and
// exported again, gives the same archive byte for byte. Member order is the
// names' order, not the directory's, and every member keeps its archived
// mtime, so a replica of an unchanged tree after a move shares every
// content-defined chunk with the one before it.
func TestExportAfterImport_IsTheSameArchive(t *testing.T) {
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("no tar")
	}
	for _, sorted := range []bool{true, false} {
		t.Run(fmt.Sprintf("sort-name=%v", sorted), func(t *testing.T) {
			if sorted && !tarSortsByName() {
				t.Skip("this host's tar has no --sort=name")
			}
			restore := tarSortsByName
			tarSortsByName = func() bool { return sorted }
			defer func() { tarSortsByName = restore }()
			exportImportExport(t)
		})
	}
}

// exportImportExport builds a rootfs of many small files, symlinks, hardlinks
// and extended attributes, exports it, lays it down with the importer's
// extractor, and requires the second export to be the first, byte for byte.
func exportImportExport(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	root := filepath.Join(src, "web", "rootfs")
	rng := rand.New(rand.NewSource(5))
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	var files []string
	for i := 0; i < 3000; i++ {
		dir := filepath.Join(root, fmt.Sprintf("d%02d", rng.Intn(40)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, fmt.Sprintf("f%05d", rng.Intn(1<<20)))
		b := make([]byte, 64+rng.Intn(2048))
		rng.Read(b)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		at := base.Add(time.Duration(rng.Intn(1e6)) * time.Second)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	links := filepath.Join(root, "links")
	if err := os.MkdirAll(links, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		target := files[rng.Intn(len(files))]
		rel, _ := filepath.Rel(links, target)
		if err := os.Symlink(rel, filepath.Join(links, fmt.Sprintf("sym%02d", i))); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, filepath.Join(links, fmt.Sprintf("hard%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	xattrs := 0
	for i := 0; i < 20; i++ {
		if err := unix.Lsetxattr(files[i], "user.litevirt.test", []byte(fmt.Sprintf("v%d", i)), 0); err == nil {
			xattrs++
		}
	}
	if xattrs == 0 {
		t.Log("this filesystem stores no user xattrs: the archive carries none")
	}
	// Directory times last: creating the links moved them.
	_ = filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chtimes(p, base, base)
		}
		return nil
	})
	export := func(lxcpath string) []byte {
		var buf bytes.Buffer
		if err := (&LxcRunner{Lxcpath: lxcpath}).ExportContainer(context.Background(), "web", &buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	first := export(src)
	if err := safename.ExtractRootfsTar(bytes.NewReader(first), dst, "web"); err != nil {
		t.Fatal(err)
	}
	if second := export(dst); !bytes.Equal(first, second) {
		t.Fatalf("the archive of the laid-down tree differs from the archive it was laid down from (%d vs %d bytes): %s",
			len(first), len(second), firstDifference(first, second))
	}
}

// R2-n1: the version check behind the fallback.
func TestGnuTarAtLeast(t *testing.T) {
	for v, want := range map[string]bool{
		"tar (GNU tar) 1.34\nCopyright": true,
		"tar (GNU tar) 1.28":            true,
		"tar (GNU tar) 1.27.1":          false,
		"bsdtar 3.6.2 - libarchive":     false,
		"":                              false,
	} {
		if got := gnuTarAtLeast(v, 1, 28); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}

// firstDifference names the first archive member whose header or content
// differs.
func firstDifference(a, b []byte) string {
	ra, rb := tar.NewReader(bytes.NewReader(a)), tar.NewReader(bytes.NewReader(b))
	for {
		ha, ea := ra.Next()
		hb, eb := rb.Next()
		if ea != nil || eb != nil {
			return fmt.Sprintf("end: %v %v", ea, eb)
		}
		if ha.Name != hb.Name || !ha.ModTime.Equal(hb.ModTime) || ha.Mode != hb.Mode || ha.Size != hb.Size ||
			ha.Uid != hb.Uid || ha.Gid != hb.Gid || fmt.Sprint(ha.PAXRecords) != fmt.Sprint(hb.PAXRecords) {
			return fmt.Sprintf("%q mtime %v/%v mode %o/%o size %d/%d pax %v / %v", ha.Name, ha.ModTime, hb.ModTime, ha.Mode, hb.Mode, ha.Size, hb.Size, ha.PAXRecords, hb.PAXRecords)
		}
	}
}
