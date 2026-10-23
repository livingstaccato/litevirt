// Package endpointfile is the daemon's non-secret endpoint file,
// /run/litevirt/endpoint: what a local `lv` needs to dial this node's daemon
// (its gRPC port and PKI directory) without reading /etc/litevirt/config.yaml,
// which is root's and 0600 because it can hold inline secrets.
//
// The daemon writes it at start, 0644, atomically. It holds those two values
// and nothing else. A reader that finds it malformed does not trust any of it.
//
// It is a trust anchor all the same: its pki_dir names the CA a local lv
// verifies the daemon against, and lv then sends its bearer token. So the
// reader accepts only a regular file owned by root and writable by root
// alone, in a directory owned by root and writable by root alone, and the
// writer refuses to write into a directory that fails the same check.
package endpointfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// Path is where the daemon writes the file. A var so tests can move it.
var Path = "/run/litevirt/endpoint"

// maxSize bounds a read: the real file is two short lines.
const maxSize = 4096

// readerOwner is the uid Read requires of the file and its directory: root.
// A var only so a test, which cannot create root's files, can use its own.
var readerOwner = 0

// SetReaderOwnerForTest makes Read accept files owned by uid instead of
// root, and returns the function that restores it. Tests only.
func SetReaderOwnerForTest(uid int) (restore func()) {
	prev := readerOwner
	readerOwner = uid
	return func() { readerOwner = prev }
}

// Endpoint is the file's content.
type Endpoint struct {
	GRPCPort int    `yaml:"grpc_port"`
	PKIDir   string `yaml:"pki_dir"`
}

func (e Endpoint) validate() error {
	if e.GRPCPort < 1 || e.GRPCPort > 65535 {
		return fmt.Errorf("grpc_port %d is not a TCP port", e.GRPCPort)
	}
	if e.PKIDir == "" || !filepath.IsAbs(e.PKIDir) || strings.ContainsAny(e.PKIDir, "\n\r\x00") {
		return fmt.Errorf("pki_dir %q is not an absolute path", e.PKIDir)
	}
	return nil
}

// ownedSafely refuses fi (of path) unless it is what wantDir says (a
// directory, or a regular file), not a symlink, owned by uid, and writable by
// its owner alone.
func ownedSafely(path string, fi os.FileInfo, wantDir bool, uid int) error {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is a symlink", path)
	case wantDir && !fi.IsDir():
		return fmt.Errorf("%s is not a directory", path)
	case !wantDir && !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: its owner cannot be read", path)
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not %d", path, st.Uid, uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %04o)", path, fi.Mode().Perm())
	}
	return nil
}

// Write writes e to path atomically (a temp file beside it, renamed over
// it), mode 0644. A missing directory is created 0755; an existing one must
// be owned by this process's user and writable by it alone, or nothing is
// written.
func Write(path string, e Endpoint) error {
	if err := e.validate(); err != nil {
		return err
	}
	out, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o755); err == nil {
		// Not left to the umask: under a restrictive one (077) it would be
		// 0700, and no non-root lv could reach the file.
		if err := os.Chmod(dir, 0o755); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	dfi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if err := ownedSafely(dir, dfi, true, os.Geteuid()); err != nil {
		return fmt.Errorf("refusing to write the endpoint file: %w", err)
	}
	f, err := os.CreateTemp(dir, ".endpoint-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Read reads and checks the file at path. A missing file, or a missing
// directory, is an error satisfying errors.Is(err, fs.ErrNotExist); any other
// error means the file is there and must not be used: not root's, writable by
// someone else, a symlink, in such a directory, or malformed.
func Read(path string) (Endpoint, error) {
	dir := filepath.Dir(path)
	dfi, err := os.Lstat(dir)
	if err != nil {
		return Endpoint{}, err
	}
	if err := ownedSafely(dir, dfi, true, readerOwner); err != nil {
		return Endpoint{}, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return Endpoint{}, fmt.Errorf("%s is a symlink", path)
		}
		return Endpoint{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Endpoint{}, err
	}
	if err := ownedSafely(path, fi, false, readerOwner); err != nil {
		return Endpoint{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return Endpoint{}, err
	}
	if len(raw) > maxSize {
		return Endpoint{}, fmt.Errorf("larger than %d bytes", maxSize)
	}
	var e Endpoint
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		if errors.Is(err, io.EOF) {
			return Endpoint{}, errors.New("empty")
		}
		return Endpoint{}, err
	}
	if err := e.validate(); err != nil {
		return Endpoint{}, err
	}
	return e, nil
}
