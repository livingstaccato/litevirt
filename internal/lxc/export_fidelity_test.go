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
