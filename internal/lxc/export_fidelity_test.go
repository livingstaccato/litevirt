package lxc

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/pbsstore"
)

// A container's rootfs survives backup→restore and migrate (both are
// ExportContainer → the repo → ImportContainer) with its setuid/setgid bits,
// ACLs and extended attributes, as LXC's own tooling keeps them. File
// capabilities ride the same path; setting one needs root, so the extraction
// half of that is pinned in internal/safename.
func TestExportImport_KeepsSetuidACLsAndXattrs(t *testing.T) {
	src := &LxcRunner{Lxcpath: filepath.Join(t.TempDir(), "src")}
	dst := &LxcRunner{Lxcpath: filepath.Join(t.TempDir(), "dst")}
	rootfs := filepath.Join(src.Lxcpath, "c1", "rootfs")
	mkRootfs(t, rootfs)
	if err := os.WriteFile(filepath.Join(src.Lxcpath, "c1", "config"), []byte("lxc.rootfs.path = dir:"+rootfs+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(rootfs, "usr", "passwd-ish")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	// An ACL granting uid 33 read, as setfacl -m u:33:r-x writes it.
	acl := []byte{2, 0, 0, 0, 1, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, 2, 0, 5, 0, 33, 0, 0, 0,
		4, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, 0x10, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, 0x20, 0, 5, 0, 0xff, 0xff, 0xff, 0xff}
	if err := unix.Lsetxattr(bin, "system.posix_acl_access", acl, 0); err != nil {
		t.Skipf("this filesystem takes no ACLs: %v", err)
	}
	if err := unix.Lsetxattr(bin, "user.litevirt-test", []byte("kept"), 0); err != nil {
		t.Skipf("this filesystem takes no user xattrs: %v", err)
	}
	sticky := filepath.Join(rootfs, "tmp")
	if err := os.Mkdir(sticky, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}

	// Through the backup repo, as BackupContainer/RestoreContainer and a
	// migrate's staging repo carry it.
	repo, err := pbsstore.Init(filepath.Join(t.TempDir(), "repo"))
	if err != nil {
		t.Fatal(err)
	}
	var tarball bytes.Buffer
	if err := src.ExportContainer(context.Background(), "c1", &tarball); err != nil {
		t.Fatal(err)
	}
	m, err := pbsstore.PushDisk(context.Background(), repo, &tarball, pbsstore.PushOptions{VMName: "c1", DiskName: "rootfs", Timestamp: "2026-10-08T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "c1.tar")
	if err := pbsstore.RestoreToFile(context.Background(), repo, m, staged, pbsstore.RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(staged)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := dst.ImportContainer(context.Background(), "c1", f); err != nil {
		t.Fatalf("import: %v", err)
	}

	got := filepath.Join(dst.Lxcpath, "c1", "rootfs", "usr", "passwd-ish")
	fi, err := os.Lstat(got)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != os.ModeSetuid|os.ModeSetgid {
		t.Errorf("restored mode %v lost setuid/setgid", fi.Mode())
	}
	if di, _ := os.Lstat(filepath.Join(dst.Lxcpath, "c1", "rootfs", "tmp")); di == nil || di.Mode()&os.ModeSticky == 0 {
		t.Errorf("restored /tmp lost its sticky bit: %v", di)
	}
	buf := make([]byte, 256)
	if n, err := unix.Lgetxattr(got, "system.posix_acl_access", buf); err != nil || !bytes.Equal(buf[:n], acl) {
		t.Errorf("restored ACL = %x (%v), want %x", buf[:max(n, 0)], err, acl)
	}
	if n, err := unix.Lgetxattr(got, "user.litevirt-test", buf); err != nil || string(buf[:n]) != "kept" {
		t.Errorf("restored user xattr = %q (%v)", buf[:max(n, 0)], err)
	}
}

// A container's directory is not traversable by other host users: a restored
// or created rootfs may hold setuid binaries and capabilities. It is 0770, as
// LXC makes it, owned by the container's mapped root when unprivileged (so the
// container can still reach its rootfs) and by root otherwise.
func TestContainerDir_NotTraversableByHostUsers(t *testing.T) {
	r, calls := secRunner(t)
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{Name: "p", Template: tpl}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(context.Background(), CreateOpts{Name: "u", Template: tpl, IDMap: &IDMap{Base: 1_000_000_000, Size: IDMapSize}}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"p", "u"} {
		fi, err := os.Stat(filepath.Join(r.Lxcpath, n))
		if err != nil || fi.Mode().Perm() != 0o770 {
			t.Errorf("%s dir: %v %v, want 0770", n, fi.Mode().Perm(), err)
		}
	}
	dirChowned := false
	for _, c := range *calls {
		if c.path == filepath.Join(r.Lxcpath, "u") && c.uid == 1_000_000_000 && c.gid == 1_000_000_000 {
			dirChowned = true
		}
		if c.path == filepath.Join(r.Lxcpath, "p") {
			t.Errorf("privileged container dir chowned: %+v", c)
		}
	}
	if !dirChowned {
		t.Errorf("unprivileged container dir not given to its mapped root: %+v", *calls)
	}
	// A restore lays down the directory the archive carried (0755 from an
	// earlier build) and narrows it.
	var tarball bytes.Buffer
	if err := r.ExportContainer(context.Background(), "p", &tarball); err != nil {
		t.Fatal(err)
	}
	r2 := &LxcRunner{Lxcpath: filepath.Join(t.TempDir(), "dst"), IDMappedRootfs: "off"}
	if err := os.Chmod(filepath.Join(r.Lxcpath, "p"), 0o755); err != nil {
		t.Fatal(err)
	}
	tarball.Reset()
	if err := r.ExportContainer(context.Background(), "p", &tarball); err != nil {
		t.Fatal(err)
	}
	if err := r2.ImportContainer(context.Background(), "p", &tarball); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(r2.Lxcpath, "p")); fi == nil || fi.Mode().Perm() != 0o770 {
		t.Errorf("restored dir mode %v, want 0770", fi.Mode().Perm())
	}
}
