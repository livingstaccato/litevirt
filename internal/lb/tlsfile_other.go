//go:build !linux

package lb

import (
	"fmt"
	"os"
)

// openTLSForRead: an LB runs, and reads its TLS files, only on Linux.
func (m *Manager) openTLSForRead(path, _ string) (*os.File, error) {
	return nil, fmt.Errorf("%s: an LB reads TLS files only on Linux", path)
}
