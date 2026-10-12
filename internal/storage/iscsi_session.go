package storage

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// iSCSI sessions after a reboot. An iscsi pool's LUN appears as a
// /dev/disk/by-path device only while this host has a session to the pool's
// target through its portal. litevirt logs in when a pool is created
// (Prepare), but a host reboot drops every session, and the node records are
// commonly node.startup = manual, so nothing logs back in. EnsureISCSISession
// is what the daemon runs, at start and periodically, for every iscsi pool of
// the host (and before a VM with an iSCSI disk starts on it).
//
// It never writes a node record. The record is the operator's (or the one a
// pool create's discovery made), and it holds the session's settings: the
// CHAP credentials among them, which is how a CHAP target is logged in to
// without a secret on litevirt's command lines or in its logs. A login goes
// through the record as it is; only when the target has no record at all is
// a discovery run, and that one adds records only (-o new): a plain
// sendtargets discovery would reset existing records from iscsid.conf.
// node.startup is left as the operator set it.

// The bounds of the iscsiadm calls a session check makes. A login to a
// portal that does not answer otherwise waits out iscsid's own retries.
const (
	iscsiListTimeout     = 15 * time.Second
	iscsiDiscoverTimeout = 30 * time.Second
	iscsiLoginTimeout    = 60 * time.Second
)

// EnsureISCSISession makes sure this host has a session to an iscsi pool's
// target through the pool's portal (the driver's default when none is
// stored), logging in when it has none. loggedIn reports that a login was
// made. The error is the reason the pool has no session.
func EnsureISCSISession(ctx context.Context, cfg Config) (loggedIn bool, err error) {
	if !strings.EqualFold(cfg.Driver, "iscsi") {
		return false, fmt.Errorf("pool driver %q has no iSCSI session", cfg.Driver)
	}
	return ensureISCSISession(ctx, iscsiRun, cfg.Source, iscsiPortalOf(cfg.Options))
}

// iscsiPortalOf is the portal an iscsi pool's commands use: its option, or
// the driver's default.
func iscsiPortalOf(opts map[string]string) string {
	if p := opts["portal"]; p != "" {
		return p
	}
	return "127.0.0.1"
}

func ensureISCSISession(ctx context.Context, run cmdRunner, target, portal string) (bool, error) {
	if target == "" {
		return false, fmt.Errorf("iscsi pool has no target")
	}
	up, err := iscsiSessionUp(ctx, run, target, portal)
	if err != nil {
		return false, err
	}
	if up {
		return false, nil
	}
	out, err := iscsiLogin(ctx, run, target, portal)
	if err != nil && strings.Contains(string(out), "No records found") {
		// No record of this target through this portal: add one (and only
		// new ones) from the portal's sendtargets, then log in.
		dctx, cancel := context.WithTimeout(ctx, iscsiDiscoverTimeout)
		dout, derr := run(dctx, "iscsiadm", "-m", "discovery", "-t", "st", "-p", portal, "-o", "new")
		cancel()
		if derr != nil {
			return false, fmt.Errorf("no session to iSCSI target %s through %s, no node record of it, and discovery failed: %w: %s",
				target, portal, derr, trimISCSIOutput(dout))
		}
		out, err = iscsiLogin(ctx, run, target, portal)
	}
	if err != nil && !strings.Contains(string(out), "already present") {
		return false, fmt.Errorf("no session to iSCSI target %s through %s, and the login failed: %w: %s",
			target, portal, err, trimISCSIOutput(out))
	}
	return true, nil
}

func iscsiLogin(ctx context.Context, run cmdRunner, target, portal string) ([]byte, error) {
	lctx, cancel := context.WithTimeout(ctx, iscsiLoginTimeout)
	defer cancel()
	return run(lctx, "iscsiadm", "-m", "node", "-T", target, "-p", portal, "--login")
}

// iscsiSessionUp reports whether `iscsiadm -m session` lists a session to
// target through portal. A target compares case-insensitively; a portal by
// address and port, the port 3260 when the pool's spelling has none. A pool
// whose portal is a host name (kept when it did not resolve at create) is
// matched by its target alone: the session lists the address.
func iscsiSessionUp(ctx context.Context, run cmdRunner, target, portal string) (bool, error) {
	lctx, cancel := context.WithTimeout(ctx, iscsiListTimeout)
	defer cancel()
	out, err := run(lctx, "iscsiadm", "-m", "session")
	if err != nil {
		if strings.Contains(string(out), "No active sessions") {
			return false, nil
		}
		return false, fmt.Errorf("cannot list this host's iSCSI sessions: %w: %s", err, trimISCSIOutput(out))
	}
	want, _ := NormalizeISCSIPortal(portal, nil)
	byName := !portalIsAddress(want)
	for _, line := range strings.Split(string(out), "\n") {
		// tcp: [1] 10.0.0.5:3260,1 iqn.2003-01.org.example:store (non-flash)
		f := strings.Fields(line)
		if len(f) < 4 || !strings.EqualFold(f[3], target) {
			continue
		}
		got, _, _ := strings.Cut(f[2], ",")
		if byName || strings.EqualFold(got, want) {
			return true, nil
		}
	}
	return false, nil
}

// portalIsAddress reports whether a host:port portal names an IP address.
func portalIsAddress(hostport string) bool {
	h := hostport
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.HasSuffix(h, "]") {
		h = h[:i]
	}
	h = strings.Trim(h, "[]")
	return net.ParseIP(h) != nil
}

// trimISCSIOutput is iscsiadm's output on one line, cut short: it is a
// reason shown to operators, never a secret (iscsiadm prints no CHAP value).
func trimISCSIOutput(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}
