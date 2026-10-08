package safename

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

type xattrCall struct{ path, name, value string }

// A rootfs archive's setuid/setgid/sticky bits and extended attributes are
// laid down: a file capability (security.capability), ACLs and user xattrs —
// after the owner, since chown clears setuid and capabilities. An attribute
// in no namespace a container's files use (trusted.*) is not taken from the
// archive.
func TestExtractRootfsTar_KeepsSpecialBitsAndXattrs(t *testing.T) {
	var calls []xattrCall
	var order []string
	restore := setLsetxattrForTest(func(p, name string, v []byte) error {
		calls = append(calls, xattrCall{p, name, string(v)})
		order = append(order, "xattr")
		return nil
	})
	defer restore()
	restoreChown := setLchownForTest(func(p string, uid, gid int) error {
		order = append(order, "chown")
		return nil
	})
	defer restoreChown()

	capV3 := string([]byte{1, 0, 0, 3, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xca, 0x9a, 0x3b})
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	add := func(h *tar.Header, body string) {
		h.Size = int64(len(body))
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	add(&tar.Header{Name: "ct/", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatPAX}, "")
	add(&tar.Header{Name: "ct/tmp/", Typeflag: tar.TypeDir, Mode: 0o1777, Format: tar.FormatPAX}, "")
	add(&tar.Header{Name: "ct/ping", Typeflag: tar.TypeReg, Mode: 0o6755, Uid: 1000000000, Gid: 1000000000, Format: tar.FormatPAX,
		PAXRecords: map[string]string{
			"SCHILY.xattr.security.capability":      capV3,
			"SCHILY.xattr.system.posix_acl_access":  "acl-bytes",
			"SCHILY.xattr.user.mime_type":           "x",
			"SCHILY.xattr.trusted.overlay.redirect": "/etc",
			"SCHILY.acl.access":                     "user::rwx",
		}}, "bin")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := ExtractRootfsTar(&b, dest, "ct"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(dest, "ct", "ping"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != os.ModeSetuid|os.ModeSetgid {
		t.Errorf("setuid/setgid dropped: %v", fi.Mode())
	}
	if di, _ := os.Lstat(filepath.Join(dest, "ct", "tmp")); di == nil || di.Mode()&os.ModeSticky == 0 {
		t.Errorf("sticky bit dropped: %v", di)
	}
	got := map[string]string{}
	for _, c := range calls {
		got[c.name] = c.value
	}
	for name, want := range map[string]string{"security.capability": capV3, "system.posix_acl_access": "acl-bytes", "user.mime_type": "x"} {
		if got[name] != want {
			t.Errorf("xattr %s = %q, want %q", name, got[name], want)
		}
	}
	if _, ok := got["trusted.overlay.redirect"]; ok {
		t.Error("a trusted.* attribute was taken from the archive")
	}
	// The file's own xattrs come after its chown (the last chown is the file's).
	last := -1
	for i, o := range order {
		if o == "chown" {
			last = i
		}
	}
	if last < 0 || last == len(order)-1 || order[len(order)-1] != "xattr" {
		t.Errorf("xattrs were not applied after the owner: %v", order)
	}
}
