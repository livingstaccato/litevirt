package lb

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/litevirt/litevirt/internal/safename"
)

// maxTLSFile caps a TLS certificate or key file. A real PEM chain is a few
// KiB; the cap keeps a path like /dev/zero from exhausting the daemon.
const maxTLSFile = 1 << 20

var (
	protectedMu   sync.RWMutex
	protectedDirs = []string{"/etc/litevirt/pki", "/var/lib/litevirt"}
)

// SetProtectedDirs names the directories holding litevirt's own key material
// (the PKI dir and the data dir). An LB never reads a TLS file inside one,
// whatever its spec says. The daemon sets them from its config at start.
func SetProtectedDirs(dirs ...string) {
	protectedMu.Lock()
	defer protectedMu.Unlock()
	protectedDirs = nil
	for _, d := range dirs {
		if d != "" {
			protectedDirs = append(protectedDirs, filepath.Clean(d))
		}
	}
}

// certDir is CertDir, a variable so tests can stand one up.
var certDir = CertDir

// beforeTLSOpen runs between resolving a TLS path and opening it (tests swap
// the path there).
var beforeTLSOpen = func() {}

// readTLSFile reads an LB's TLS certificate or key as root.
//
// The path may be a symlink (a Let's Encrypt live/ name is one): it is
// resolved, and every check applies to the file actually read:
//   - the path is clean and absolute;
//   - the resolved file is opened once, O_NOFOLLOW on its final component,
//     and the kernel's own name for the opened descriptor must be the
//     resolved path. A component swapped for a symlink between the resolve
//     and the open shows up there and is refused; everything after reads
//     the descriptor, never the path again;
//   - that name is never inside the PKI dir, the data dir or the LB config
//     dir (other LBs' combined PEMs);
//   - it is a regular file of at most maxTLSFile bytes, read non-blocking,
//     so a device or FIFO cannot exhaust or hang the apply;
//   - it is a regular file before it is opened (opening a device can act),
//     and the descriptor is one after;
//   - a path named inside CertDir needs CertDir and every directory below it
//     on the way to the file to be a real directory owned by this daemon's
//     user and writable by no one else: what a non-admin may name there, and
//     what any symlink there points at, was put there by root.
func (m *Manager) readTLSFile(path string) ([]byte, error) {
	if err := checkTLSPath(path); err != nil {
		return nil, err
	}
	if safename.Contains(certDir, path) {
		if err := checkCertDirs(certDir, filepath.Dir(path)); err != nil {
			return nil, err
		}
	}
	if err := m.checkNotProtected(path, path); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	// Never open what is not a regular file: opening some devices does
	// something (a watchdog arms). The descriptor is checked again below.
	if fi, err := os.Stat(resolved); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %s is not a regular file", path, resolved)
	}
	beforeTLSOpen()
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: changed to a symlink while it was opened", path)
		}
		return nil, err
	}
	defer f.Close()
	opened, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		return nil, fmt.Errorf("%s: cannot tell which file was opened: %w", path, err)
	}
	if opened != resolved {
		return nil, fmt.Errorf("%s: resolved to %s, but %s was opened (changed while it was opened)", path, resolved, opened)
	}
	if err := m.checkNotProtected(path, opened); err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %s is not a regular file", path, opened)
	}
	if fi.Size() > maxTLSFile {
		return nil, fmt.Errorf("%s: %d bytes, over the %d-byte limit", path, fi.Size(), maxTLSFile)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTLSFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxTLSFile {
		return nil, fmt.Errorf("%s: over the %d-byte limit", path, maxTLSFile)
	}
	return b, nil
}

// checkNotProtected refuses a TLS file named or resolved inside litevirt's
// own key material or the LB config dir.
func (m *Manager) checkNotProtected(path, real string) error {
	protectedMu.RLock()
	deny := append([]string{m.configDir}, protectedDirs...)
	protectedMu.RUnlock()
	for _, d := range deny {
		if safename.Contains(d, real) {
			if real == path {
				return fmt.Errorf("%s: inside %s, which holds litevirt's own keys; an LB never reads it", path, d)
			}
			return fmt.Errorf("%s: resolves to %s, inside %s, which holds litevirt's own keys; an LB never reads it", path, real, d)
		}
	}
	return nil
}

// checkCertDirs checks root and every directory below it down to dir (a
// directory inside root) with checkCertDir.
func checkCertDirs(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	cur := root
	if err := checkCertDir(cur); err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		if err := checkCertDir(cur); err != nil {
			return err
		}
	}
	return nil
}

// checkCertDir: a directory of CertDir is trusted only while it is a real
// directory owned by this daemon's user and not writable by group or others.
func checkCertDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be a directory owned by uid %d and writable by no one else (mode %v)", dir, os.Geteuid(), fi.Mode())
	}
	return nil
}
