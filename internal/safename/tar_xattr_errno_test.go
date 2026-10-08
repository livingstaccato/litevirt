package safename

import (
	"archive/tar"
	"bytes"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// "This attribute cannot be stored here" degrades like ENOTSUP — dropped and
// reported — as main dropped every attribute: no xattr space (ENOSPC, E2BIG,
// ERANGE), an SELinux label the target policy does not know (EINVAL, EACCES),
// and IMA/EVM appraisal (EPERM). A real I/O error, and EPERM on a file
// capability, still fail.
func TestExtractRootfsTar_CannotStoreHereDegrades(t *testing.T) {
	for _, c := range []struct {
		attr    string
		errno   syscall.Errno
		dropped bool
	}{
		{"system.posix_acl_access", unix.ENOSPC, true},
		{"system.posix_acl_access", unix.E2BIG, true},
		{"system.posix_acl_access", unix.ERANGE, true},
		{"user.big", unix.ENOSPC, true},
		{"security.capability", unix.E2BIG, true},
		{"security.selinux", unix.EINVAL, true},
		{"security.selinux", unix.EACCES, true},
		{"security.ima", unix.EPERM, true},
		{"security.evm", unix.EPERM, true},
		{"security.capability", unix.EPERM, false},
		{"system.posix_acl_access", unix.EIO, false},
		{"security.selinux", unix.EIO, false},
		{"user.big", unix.EIO, false},
	} {
		t.Run(c.attr+"/"+c.errno.Error(), func(t *testing.T) {
			restore := setLsetxattrForTest(func(p, name string, v []byte) error {
				if name == c.attr {
					return c.errno
				}
				return nil
			})
			defer restore()
			var b bytes.Buffer
			tw := tar.NewWriter(&b)
			_ = tw.WriteHeader(&tar.Header{Name: "ct/", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatPAX})
			_ = tw.WriteHeader(&tar.Header{Name: "ct/f", Typeflag: tar.TypeReg, Mode: 0o770, Format: tar.FormatPAX,
				PAXRecords: map[string]string{"SCHILY.xattr." + c.attr: aclBytes()}})
			_ = tw.Close()
			dropped, err := ExtractRootfsTarReport(&b, t.TempDir(), "ct")
			if c.dropped {
				if err != nil || len(dropped) != 1 {
					t.Fatalf("got dropped=%v err=%v, want it dropped and reported", dropped, err)
				}
			} else if err == nil {
				t.Fatalf("a %v on %s did not fail the extraction (dropped=%v)", c.errno, c.attr, dropped)
			}
		})
	}
}
