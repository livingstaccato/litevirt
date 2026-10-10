package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// CephLocator is a ceph VM disk's recorded identifier, parsed:
// "rbd:<pool>[/<ns>]/<image>[:opt=val…]", ':' and ';' inside a value escaped
// as "\:" and "\;". Every reader (the domain XML, delete, replication) parses
// it here, so none of them can split an escaped value differently.
type CephLocator struct {
	Spec  string            // "<pool>[/<ns>]/<image>"
	Pool  string            // "<pool>[/<ns>]"
	Image string            // "<image>"
	Opts  map[string]string // option → unescaped value
	Order []string          // option keys in the order they appear
}

// ParseCephLocator parses an "rbd:" disk locator; ok is false for any other
// path and for one with no pool or no image.
func ParseCephLocator(path string) (CephLocator, bool) {
	body, isRBD := strings.CutPrefix(path, "rbd:")
	if !isRBD {
		return CephLocator{}, false
	}
	parts := splitUnescaped(body, ':')
	l := CephLocator{Spec: parts[0], Opts: map[string]string{}}
	i := strings.LastIndexByte(l.Spec, '/')
	if i <= 0 || i == len(l.Spec)-1 {
		return CephLocator{}, false
	}
	l.Pool, l.Image = l.Spec[:i], l.Spec[i+1:]
	for _, opt := range parts[1:] {
		k, v, ok := strings.Cut(opt, "=")
		if !ok {
			continue
		}
		v = strings.ReplaceAll(v, `\;`, ";")
		v = strings.ReplaceAll(v, `\:`, ":")
		if _, dup := l.Opts[k]; !dup {
			l.Order = append(l.Order, k)
		}
		l.Opts[k] = v
	}
	return l, true
}

// splitUnescaped splits s at every sep not preceded by a backslash.
func splitUnescaped(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// IsDefaultCephConf reports whether conf is the ceph.conf qemu and the rbd
// CLI read when none is named (/etc/ceph/ceph.conf, however spelled).
func IsDefaultCephConf(conf string) bool {
	return conf != "" && filepath.Clean(conf) == DefaultCephConf()
}

// rbd exits with the errno of what failed (rbd.cc: return std::abs(r)).
const (
	rbdEPERM  = 1
	rbdENOENT = 2
	rbdEACCES = 13
	rbdEEXIST = 17
)

// rbdErrno is the errno a failed rbd command exited with, or -1 when the
// command did not run to an exit status (a cancelled context, no binary).
func rbdErrno(err error) int {
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return -1
}

// rbdEBUSY is rbd's exit status for an image another client still watches —
// a killed rbd's for up to the OSD watch timeout (30 s by default).
const rbdEBUSY = 16

// rbdBusyBudget is how long a rollback keeps retrying an rm that rbd refuses
// as watched: past the 30 s a dead client's watch lasts, with margin.
const rbdBusyBudget = 60 * time.Second

// cephSleep waits d, or until ctx ends (false). Tests advance a fake clock.
var cephSleep = func(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// volumeRunner is what the zfs and lvm-thin drivers run their tools with.
var volumeRunner cmdRunner = realCmd

// OverrideVolumeRunnerForTest replaces how the zfs and lvm-thin drivers run
// zfs, lvcreate and the rest, for tests in other packages; it returns the
// restore.
func OverrideVolumeRunnerForTest(run func(ctx context.Context, name string, args ...string) ([]byte, error)) func() {
	prev := volumeRunner
	volumeRunner = run
	return func() { volumeRunner = prev }
}
