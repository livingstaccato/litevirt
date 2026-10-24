package custody

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/secretfile"
	"golang.org/x/sys/unix"
)

var errCustodyMissing = errors.New("local custody file missing")

func custodyOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
func custodyDirectory(f *os.File, private bool) error {
	info, err := f.Stat()
	if err != nil || !info.IsDir() || !custodyOwned(info) {
		return ErrCustodyUnavailable
	}
	if private && info.Mode().Perm() != 0700 {
		return ErrCustodyCorrupt
	}
	if !private && info.Mode().Perm()&0022 != 0 {
		return ErrCustodyCorrupt
	}
	return nil
}
func custodyOpenDir(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, errCustodyMissing
	}
	if err != nil {
		return nil, ErrCustodyUnavailable
	}
	return os.NewFile(uintptr(fd), "custody-directory"), nil
}
func custodyParent(path string) (*os.File, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
		return nil, "", ErrCustodyCorrupt
	}
	path = filepath.Clean(path)
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", ErrCustodyUnavailable
	}
	current := os.NewFile(uintptr(fd), "custody-parent")
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := custodyOpenDir(current, part)
		current.Close()
		if err != nil {
			return nil, "", ErrCustodyUnavailable
		}
		current = next
	}
	if err = custodyDirectory(current, false); err != nil {
		current.Close()
		return nil, "", err
	}
	return current, filepath.Base(path), nil
}
func custodyNamedDir(parent *os.File, name string, held *os.File) bool {
	var expected, actual unix.Stat_t
	return unix.Fstat(int(held.Fd()), &expected) == nil && unix.Fstatat(int(parent.Fd()), name, &actual, unix.AT_SYMLINK_NOFOLLOW) == nil && actual.Mode&unix.S_IFMT == unix.S_IFDIR && expected.Dev == actual.Dev && expected.Ino == actual.Ino
}
func custodySameDir(a, b *os.File) bool {
	var x, y unix.Stat_t
	return unix.Fstat(int(a.Fd()), &x) == nil && unix.Fstat(int(b.Fd()), &y) == nil && x.Dev == y.Dev && x.Ino == y.Ino
}
func (s *LocalCustody) attached() error {
	if s.closed || custodyDirectory(s.root, true) != nil || custodyDirectory(s.parent, false) != nil {
		return ErrCustodyUnavailable
	}
	// A fresh no-follow walk also refuses a detached/replaced parent path.
	parent, name, err := custodyParent(s.path)
	if err != nil {
		return ErrCustodyUnavailable
	}
	defer parent.Close()
	if name != s.name || !custodySameDir(parent, s.parent) || !custodyNamedDir(parent, name, s.root) {
		return ErrCustodyUnavailable
	}
	return nil
}
func (s *LocalCustody) syncFile(f *os.File) error {
	if s.ops.syncFile != nil {
		return s.ops.syncFile(f)
	}
	return f.Sync()
}
func (s *LocalCustody) syncDir(f *os.File) error {
	if s.ops.syncDir != nil {
		return s.ops.syncDir(f)
	}
	return f.Sync()
}
func custodyRead(dir *os.File, name string) ([]byte, *os.File, error) {
	return custodyReadBounded(dir, name, custodyRecordMax)
}
func custodyReadBounded(dir *os.File, name string, limit int64) ([]byte, *os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil, errCustodyMissing
	}
	if err != nil {
		return nil, nil, ErrCustodyUnavailable
	}
	f := os.NewFile(uintptr(fd), "custody-record")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !custodyOwned(info) {
		f.Close()
		return nil, nil, ErrCustodyUnavailable
	}
	if info.Mode().Perm()&^0600 != 0 || info.Size() > limit {
		f.Close()
		return nil, nil, ErrCustodyCorrupt
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		f.Close()
		return nil, nil, ErrCustodyUnavailable
	}
	if int64(len(body)) > limit {
		f.Close()
		return nil, nil, ErrCustodyCorrupt
	}
	return body, f, nil
}
func custodyWrite(dir *os.File, name string, body []byte) error {
	// The path is an internal descriptor reference, never a caller-controlled
	// symlink. secretfile's temp+rename stays inside this pinned directory.
	path := fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), name)
	if secretfile.Write(path, body, 0600) != nil {
		return ErrCustodyUnavailable
	}
	return nil
}
func openCustody(path string, scope CustodyScope, ops custodyIO, create bool) (*LocalCustody, error) {
	if !scope.valid() {
		return nil, ErrCustodyCorrupt
	}
	parent, name, err := custodyParent(path)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			parent.Close()
		}
	}()
	if create {
		err = unix.Mkdirat(int(parent.Fd()), name, 0700)
		if errors.Is(err, unix.EEXIST) {
			return nil, ErrCustodyConflict
		}
		if err != nil {
			return nil, ErrCustodyUnavailable
		}
	}
	root, err := custodyOpenDir(parent, name)
	if err != nil {
		return nil, ErrCustodyUnavailable
	}
	defer func() {
		if !success {
			root.Close()
		}
	}()
	if err = custodyDirectory(root, true); err != nil {
		return nil, err
	}
	s := &LocalCustody{root: root, parent: parent, name: name, path: filepath.Clean(path), scope: scope, ops: ops}
	expected, _ := custodyEncode(s.record("scope", CustodyKeyRef{}, nil))
	if create {
		if err = custodyWrite(root, "scope", expected); err != nil {
			return nil, err
		}
	}
	body, file, err := custodyRead(root, "scope")
	if errors.Is(err, errCustodyMissing) {
		return nil, ErrCustodyRecoveryRequired
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	record, err := custodyDecode(body)
	if err != nil {
		return nil, err
	}
	if record.Purpose != "scope" || record.Scope != scope || record.Ref != (CustodyKeyRef{}) || record.Material != nil {
		return nil, ErrCustodyConflict
	}
	if !bytes.Equal(body, expected) {
		return nil, ErrCustodyCorrupt
	}
	// Re-sync after secretfile's descriptor chmod, then persist the directory
	// entry and the first-created custody root's entry in its parent.
	if s.syncFile(file) != nil || s.syncDir(root) != nil || s.syncDir(parent) != nil {
		return nil, ErrCustodyUnavailable
	}
	if err = s.attached(); err != nil {
		return nil, err
	}
	success = true
	return s, nil
}
func (s *LocalCustody) reserve(purpose string, ref CustodyKeyRef) (*os.File, string, error) {
	if !ref.valid() {
		return nil, "", ErrCustodyCorrupt
	}
	if err := s.attached(); err != nil {
		return nil, "", err
	}
	name, err := custodyName(s.record(purpose, ref, nil))
	if err != nil {
		return nil, "", err
	}
	err = unix.Mkdirat(int(s.root.Fd()), name, 0700)
	if errors.Is(err, unix.EEXIST) {
		return nil, "", ErrCustodyConflict
	}
	if err != nil {
		return nil, "", ErrCustodyUnavailable
	}
	dir, err := custodyOpenDir(s.root, name)
	if err != nil {
		return nil, "", ErrCustodyUnavailable
	}
	if err = custodyDirectory(dir, true); err != nil {
		dir.Close()
		return nil, "", err
	}
	// Make the reservation durable before generating any replacement material.
	if s.syncDir(s.root) != nil {
		dir.Close()
		return nil, "", ErrCustodyUnavailable
	}
	if !custodyNamedDir(s.root, name, dir) {
		dir.Close()
		return nil, "", ErrCustodyUnavailable
	}
	return dir, name, nil
}
func (s *LocalCustody) install(dir *os.File, name string, expected custodyRecord) error {
	body, err := custodyEncode(expected)
	if err != nil {
		return err
	}
	if err = custodyWrite(dir, "material", body); err != nil {
		return err
	}
	got, err := s.readKey(dir, name, expected.Purpose, expected.Ref)
	if err != nil {
		return err
	}
	if !hmac.Equal(got.Material, expected.Material) {
		return ErrCustodyConflict
	}
	return nil
}
func (s *LocalCustody) load(purpose string, ref CustodyKeyRef) (custodyRecord, error) {
	if !ref.valid() {
		return custodyRecord{}, ErrCustodyCorrupt
	}
	if err := s.attached(); err != nil {
		return custodyRecord{}, err
	}
	name, err := custodyName(s.record(purpose, ref, nil))
	if err != nil {
		return custodyRecord{}, err
	}
	dir, err := custodyOpenDir(s.root, name)
	if err != nil {
		return custodyRecord{}, ErrCustodyUnavailable
	}
	defer dir.Close()
	if err = custodyDirectory(dir, true); err != nil {
		return custodyRecord{}, err
	}
	return s.readKey(dir, name, purpose, ref)
}
func (s *LocalCustody) readKey(dir *os.File, name, purpose string, ref CustodyKeyRef) (custodyRecord, error) {
	fail := func(err error) (custodyRecord, error) { return custodyRecord{}, err }
	body, file, err := custodyRead(dir, "material")
	if errors.Is(err, errCustodyMissing) {
		return fail(ErrCustodyRecoveryRequired)
	}
	if err != nil {
		return fail(err)
	}
	defer file.Close()
	record, err := custodyDecode(body)
	if err != nil {
		return fail(err)
	}
	if record.Purpose != purpose || record.Scope != s.scope || record.Ref != ref {
		return fail(ErrCustodyConflict)
	}
	switch purpose {
	case custodyEqualityPurpose:
		if len(record.Material) != 32 {
			return fail(ErrCustodyCorrupt)
		}
	case custodyVoterPurpose:
		identity, err := age.ParseX25519Identity(string(record.Material))
		if err != nil || identity.String() != string(record.Material) {
			return fail(ErrCustodyCorrupt)
		}
	default:
		return fail(ErrCustodyCorrupt)
	}
	if s.syncFile(file) != nil || s.syncDir(dir) != nil || s.syncDir(s.root) != nil {
		return fail(ErrCustodyUnavailable)
	}
	if !custodyNamedDir(s.root, name, dir) {
		return fail(ErrCustodyUnavailable)
	}
	if err = s.attached(); err != nil {
		return fail(err)
	}
	return record, nil
}
