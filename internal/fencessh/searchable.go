package fencessh

import (
	"errors"
	"fmt"
	"os"
)

// EnsureSearchableDir makes dir (the system config directory, /etc/litevirt)
// searchable by others without making it readable. The AuthorizedKeysCommand
// runs as nobody and cannot reach the ssh dir through a 0700 parent. A new
// directory is made 0711; an existing one only has the other-search bit ORed
// in: never a read bit, never a narrowing, never a child. The secrets beneath
// are guarded by their own modes.
func EnsureSearchableDir(dir string) error {
	fi, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o711); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		// MkdirAll's mode is masked by the umask.
		if err := os.Chmod(dir, 0o711); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if m := fi.Mode().Perm(); m&0o001 == 0 {
		if err := os.Chmod(dir, m|0o001); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	}
	return nil
}
