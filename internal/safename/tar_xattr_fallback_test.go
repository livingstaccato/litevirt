package safename

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// aclBytes is a POSIX ACL xattr: user::rwx, user:33:rwx, group::r-x,
// mask::rwx, other::---.
func aclBytes() string {
	return string([]byte{2, 0, 0, 0,
		1, 0, 7, 0, 0xff, 0xff, 0xff, 0xff,
		2, 0, 7, 0, 33, 0, 0, 0,
		4, 0, 5, 0, 0xff, 0xff, 0xff, 0xff,
		0x10, 0, 7, 0, 0xff, 0xff, 0xff, 0xff,
		0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff})
}

func fallbackArchive(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range []*tar.Header{
		{Name: "ct/", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatPAX},
		{Name: "ct/log", Typeflag: tar.TypeReg, Mode: 0o770, Format: tar.FormatPAX, PAXRecords: map[string]string{
			"SCHILY.xattr.system.posix_acl_access": aclBytes(),
			"SCHILY.xattr.security.capability":     "capbytes",
			"SCHILY.xattr.user.k":                  "v",
		}},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &b
}

// A target filesystem that takes no ACLs or capabilities (ZFS acltype=off,
// NFS) does not fail the restore, as on main: what it takes is applied, what
// it refuses is dropped and reported, and a dropped ACL's group bits narrow to
// the owning group's own entry, so nobody the ACL did not grant gains access.
func TestExtractRootfsTar_FilesystemWithoutACLsOrCaps(t *testing.T) {
	var set []string
	restore := setLsetxattrForTest(func(p, name string, v []byte) error {
		if name == "user.k" {
			set = append(set, name)
			return nil
		}
		return unix.EOPNOTSUPP
	})
	defer restore()
	dest := t.TempDir()
	if err := ExtractRootfsTar(fallbackArchive(t), dest, "ct"); err != nil {
		t.Fatalf("restore onto a filesystem without ACLs or capabilities: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dest, "ct", "log"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o750 {
		t.Errorf("mode %o, want 750: the dropped ACL's group class must narrow to group::r-x", fi.Mode().Perm())
	}
	if len(set) != 1 {
		t.Errorf("attributes set = %v, want [user.k]", set)
	}
}

// Any other refusal (a permission error, an I/O error) still fails.
func TestExtractRootfsTar_OtherXattrErrorsStillFail(t *testing.T) {
	restore := setLsetxattrForTest(func(p, name string, v []byte) error {
		if name == "security.capability" {
			return syscall.EPERM
		}
		return nil
	})
	defer restore()
	err := ExtractRootfsTar(fallbackArchive(t), t.TempDir(), "ct")
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("EPERM on a capability: %v", err)
	}
}

// A directory's default ACL is applied after its contents, as GNU tar does:
// a file the archive recorded without an ACL does not inherit one.
func TestExtractRootfsTar_DefaultACLAppliedAfterChildren(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Lsetxattr(probe, "system.posix_acl_default", []byte(aclBytes()), 0); err != nil {
		t.Skipf("this filesystem takes no default ACLs: %v", err)
	}
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range []*tar.Header{
		{Name: "ct/", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatPAX},
		{Name: "ct/d/", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatPAX, PAXRecords: map[string]string{
			"SCHILY.xattr.system.posix_acl_default": aclBytes(),
		}},
		{Name: "ct/d/f", Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatPAX},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	dest := t.TempDir()
	if err := ExtractRootfsTar(&b, dest, "ct"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if n, err := unix.Lgetxattr(filepath.Join(dest, "ct", "d", "f"), "system.posix_acl_access", buf); err == nil && n > 0 {
		t.Fatalf("ct/d/f inherited an ACL the archive did not record: %x", buf[:n])
	}
	if n, err := unix.Lgetxattr(filepath.Join(dest, "ct", "d"), "system.posix_acl_default", buf); err != nil || n == 0 {
		t.Fatalf("ct/d's default ACL was not applied: %v", err)
	}
	if fi, _ := os.Lstat(filepath.Join(dest, "ct", "d", "f")); fi == nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("ct/d/f mode %v, want 644", fi.Mode())
	}
}
func TestExtractRootfsTarReport_ListsDroppedAttributes(t *testing.T) {
	restore := setLsetxattrForTest(func(p, name string, v []byte) error {
		if name == "user.k" {
			return nil
		}
		return unix.EOPNOTSUPP
	})
	defer restore()
	dropped, err := ExtractRootfsTarReport(fallbackArchive(t), t.TempDir(), "ct")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"ct/log system.posix_acl_access": true, "ct/log security.capability": true}
	if len(dropped) != len(want) {
		t.Fatalf("dropped = %v", dropped)
	}
	for _, d := range dropped {
		if !want[d] {
			t.Errorf("unexpected dropped entry %q (%v)", d, dropped)
		}
	}
}
