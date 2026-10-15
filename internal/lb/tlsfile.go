package lb

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// readTLSFile reads an LB's TLS certificate or key as root, refusing anything
// that is not plainly an operator's file: a path that is not clean and
// absolute, a file inside litevirt's own key material or the LB config dir
// (other LBs' combined PEMs), a symlink, anything but a regular file, and a
// file over maxTLSFile. Opened non-blocking, so a FIFO cannot hang the apply.
func (m *Manager) readTLSFile(path string) ([]byte, error) {
	if err := checkTLSPath(path); err != nil {
		return nil, err
	}
	resolved := path
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		resolved = filepath.Join(dir, filepath.Base(path))
	}
	protectedMu.RLock()
	deny := append([]string{m.configDir}, protectedDirs...)
	protectedMu.RUnlock()
	for _, d := range deny {
		for _, p := range []string{path, resolved} {
			if safename.Contains(d, p) {
				return nil, fmt.Errorf("%s: inside %s, which holds litevirt's own keys; an LB never reads it", path, d)
			}
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: is a symlink; name the file itself", path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
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
