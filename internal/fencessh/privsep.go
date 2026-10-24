package fencessh

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// PrivsepDir is sshd's privilege separation directory on Debian and Ubuntu,
// which ssh.service creates as its RuntimeDirectory (root:root 0755). A root
// `sshd -T` refuses to run without it: "Missing privilege separation
// directory: /run/sshd". With socket-activated sshd (ssh.socket, Ubuntu
// 22.10 and later) nothing creates it after a reboot until a connection
// starts ssh.service, and the fence ssh evaluation failed until then (lab 2
// drill F2: 16 minutes on one node).
const PrivsepDir = "/run/sshd"

// ensurePrivsep runs before every `sshd -T` evaluation. A var for tests.
var ensurePrivsep = func() error {
	if os.Geteuid() != 0 {
		return nil // an unprivileged sshd -T does not use it
	}
	return ensurePrivsepDirAs(PrivsepDir, 0)
}

// ensurePrivsepDirAs makes dir a directory owned by owner, mode 0755, as
// systemd makes a RuntimeDirectory, when it does not exist. One that exists
// is never changed: it must be a directory (not a symlink) owned by owner and
// writable by no one else, which is what sshd itself requires of it, or it is
// refused with the reason.
func ensurePrivsepDirAs(dir string, owner int) error {
	err := os.Mkdir(dir, 0o755)
	switch {
	case err == nil:
		// Mkdir's mode is masked by the umask.
		if err := os.Chmod(dir, 0o755); err != nil {
			return fmt.Errorf("sshd's privilege separation directory %s: chmod 0755: %w", dir, err)
		}
		return nil
	case !errors.Is(err, os.ErrExist):
		return fmt.Errorf("create sshd's privilege separation directory %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("sshd's privilege separation directory %s: %w", dir, err)
	}
	const remedy = "litevirt does not change it; make it a directory owned by root and writable only by root " +
		"(ssh.service's RuntimeDirectory makes it root:root 0755)"
	if !fi.IsDir() {
		return fmt.Errorf("sshd's privilege separation directory %s is not a directory (%v); %s", dir, fi.Mode().Type(), remedy)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != owner {
		return fmt.Errorf("sshd's privilege separation directory %s is owned by uid %d, not %d; %s", dir, st.Uid, owner, remedy)
	}
	if m := fi.Mode().Perm(); m&0o022 != 0 {
		return fmt.Errorf("sshd's privilege separation directory %s is group- or world-writable (%#o); %s", dir, m, remedy)
	}
	return nil
}
