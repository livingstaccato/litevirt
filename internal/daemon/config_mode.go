package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// tightenOwnConfig makes the daemon's own config file owner-only at start
// (tightenConfigFileAs, as root). `lv host add` writes it 0600, because it can
// hold inline auth secrets, but a node upgraded in place kept the 0644 an
// older build wrote (lab 2 drill F4). Like the repair of /etc/litevirt
// (fencessh.EnsureSearchableDir), it only ever removes bits.
func (d *Daemon) tightenOwnConfig() {
	if d.cfg.ConfigPath == "" || os.Geteuid() != 0 {
		return
	}
	tightenConfigFileAs(d.cfg.ConfigPath, 0)
}

// tightenConfigFileAs removes the group and other permission bits from the
// config file at path when it is a regular file owned by owner, and logs once
// when it does: the owner's own bits are kept, and nothing is ever widened. A
// symlink is followed, and its target is what is checked and changed (the
// link is kept). Anything else (missing, not a regular file, owned by another
// user) is left as it is; one owned by another user is reported. Never fatal.
func tightenConfigFileAs(path string, owner int) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("config: could not resolve the config file to check its mode", "path", path, "error", err)
		}
		return
	}
	// The resolved file is opened without following a link and checked by its
	// descriptor, so what is changed is what was checked.
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		slog.Warn("config: could not open the config file to check its mode", "path", real, "error", err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	mode := fi.Mode().Perm()
	if mode&0o077 == 0 {
		return
	}
	if int(st.Uid) != owner {
		slog.Warn(fmt.Sprintf("config: the config file is readable by other users and owned by uid %d, not %d; "+
			"left as it is", st.Uid, owner), "path", real, "mode", modeString(mode))
		return
	}
	tight := mode &^ 0o077
	if err := f.Chmod(tight); err != nil {
		slog.Warn("config: could not make the config file owner-only", "path", real, "mode", modeString(mode), "error", err)
		return
	}
	slog.Warn("config: tightened the config file to owner-only; it can hold inline auth secrets",
		"path", real, "was", modeString(mode), "now", modeString(tight))
}

func modeString(m os.FileMode) string { return fmt.Sprintf("%04o", uint32(m)) }
