package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Prepare logs this host in to the pool's target through its portal. It runs
// on a pool create and on every VM disk create, move or replicate on the pool.
//
// It never rewrites a node record the target accepts. The record holds the
// session's settings, CHAP among them, and an operator may have set them on
// the record by hand. Earlier builds ran a plain sendtargets discovery first,
// which rewrote every record of the portal from iscsid.conf and deleted the
// ones the portal no longer returned. Prepare now goes in this order:
//
//  1. It logs in through the record as it is. A record that works is used
//     unchanged, and nothing else is run.
//  2. When that fails, an add-only discovery (-o new) makes the records the
//     portal returns and this host has none of. This covers a target with
//     no record yet, a target on a new portal, and a target that now answers
//     with a new portal group tag (the new-tag record sits beside the stale
//     one). Existing records are not touched. Then it logs in again. A
//     session that is listed afterwards counts, even if one of the target's
//     records failed.
//  3. When the target itself refused the existing record (an authorization
//     failure or a non-retryable login failure), the record's settings are
//     what failed. The case the old rewrite rescued is CHAP rotated in
//     iscsid.conf, with the record still holding the old secret. So this
//     target's record at this portal alone is refreshed from iscsid.conf:
//     deleted, made again by the add-only discovery, and logged in through.
//     Before that, the record's files are saved. If the refreshed record is
//     refused too, they are put back as they were. A record is therefore
//     changed only when the target refused it and accepted iscsid.conf's
//     settings, and the refresh is logged as a warning.
//
// No secret is put on a command line or in a log. The saved record is held in
// memory only, and written back to the node database it came from.
func (d *iscsiDriver) Prepare(ctx context.Context) error {
	portal := iscsiPortalOf(d.opts)
	run := d.run
	if run == nil {
		run = realCmd
	}

	out, err := prepareLogin(ctx, run, d.target, portal)
	if loginDone(out, err) {
		slog.Info("iSCSI target connected", "target", d.target)
		return nil
	}
	hadRecord := !strings.Contains(string(out), "No records found")

	if dout, derr := discoverNewRecords(ctx, run, portal); derr != nil {
		return fmt.Errorf("iscsi discovery %s: %w: %s", portal, derr, dout)
	}
	out, err = prepareLogin(ctx, run, d.target, portal)
	if loginDone(out, err) || sessionListed(ctx, run, d.target, portal) {
		slog.Info("iSCSI target connected", "target", d.target)
		return nil
	}
	if hadRecord && iscsiLoginRefused(out, err) {
		return d.refreshRefusedRecord(ctx, run, portal, out, err)
	}
	return fmt.Errorf("iscsi login %s: %w: %s", d.target, err, out)
}

func prepareLogin(ctx context.Context, run cmdRunner, target, portal string) ([]byte, error) {
	return run(ctx, "iscsiadm", "-m", "node", "-T", target, "-p", portal, "--login")
}

// discoverNewRecords is a sendtargets discovery that only adds records: -o
// new makes a record for each target and portal group the portal returns
// that has none, and changes or deletes no existing record.
func discoverNewRecords(ctx context.Context, run cmdRunner, portal string) ([]byte, error) {
	return run(ctx, "iscsiadm", "-m", "discovery", "-t", "st", "-p", portal, "-o", "new")
}

// loginDone is a login that left a session: it succeeded, or the session was
// already there.
func loginDone(out []byte, err error) bool {
	return err == nil || strings.Contains(string(out), "already")
}

func sessionListed(ctx context.Context, run cmdRunner, target, portal string) bool {
	up, err := iscsiSessionUp(ctx, run, target, portal)
	return err == nil && up
}

// iscsiLoginRefused reports a login the target answered and refused:
// iscsiadm's 24 (authorization failure) or 19 (a non-retryable login
// failure). A portal that did not answer, or a timeout, is not a refusal.
// Only a refusal says the record's settings are what failed.
func iscsiLoginRefused(out []byte, err error) bool {
	if err == nil {
		return false
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && (ee.ExitCode() == 24 || ee.ExitCode() == 19) {
		return true
	}
	s := string(out)
	return strings.Contains(s, "authorization failure") || strings.Contains(s, "non-retryable iSCSI login failure")
}

// refreshRefusedRecord remakes this target's record at portal from
// iscsid.conf after the target refused it, and logs in through the new
// record. When the new record is refused too, the saved record is put back.
func (d *iscsiDriver) refreshRefusedRecord(ctx context.Context, run cmdRunner, portal string, refusedOut []byte, refusedErr error) error {
	refused := fmt.Sprintf("iscsi login %s: %v: %s", d.target, refusedErr, trimISCSIOutput(refusedOut))
	saved, serr := saveISCSIRecords(d.target)
	if serr != nil {
		slog.Warn("iSCSI target refused this host's node record; refreshing it from iscsid.conf, with no copy to put back",
			"target", d.target, "portal", portal, "why_no_copy", serr)
	} else {
		slog.Warn("iSCSI target refused this host's node record; refreshing it from iscsid.conf, and putting it back if that is refused too",
			"target", d.target, "portal", portal)
	}
	fail := func(what string) error {
		if saved == nil {
			return fmt.Errorf("%s; the record was refreshed from iscsid.conf and %s (it could not be saved beforehand: %v)", refused, what, serr)
		}
		if rerr := saved.restore(); rerr != nil {
			slog.Error("iSCSI node record could not be put back after a refused refresh", "target", d.target, "portal", portal, "err", rerr)
			return fmt.Errorf("%s; the record was refreshed from iscsid.conf and %s, and putting it back failed: %v", refused, what, rerr)
		}
		return fmt.Errorf("%s; the record was refreshed from iscsid.conf and %s, so it was put back as it was", refused, what)
	}

	if out, err := run(ctx, "iscsiadm", "-m", "node", "-o", "delete", "-T", d.target, "-p", portal); err != nil &&
		!strings.Contains(string(out), "No records found") {
		return fail(fmt.Sprintf("its delete failed: %v: %s", err, trimISCSIOutput(out)))
	}
	if out, err := discoverNewRecords(ctx, run, portal); err != nil {
		return fail(fmt.Sprintf("the discovery failed: %v: %s", err, trimISCSIOutput(out)))
	}
	out, err := prepareLogin(ctx, run, d.target, portal)
	if loginDone(out, err) || sessionListed(ctx, run, d.target, portal) {
		slog.Warn("iSCSI node record refreshed from iscsid.conf after the target refused it; any setting made on the record by hand "+
			"(CHAP, node.startup) is now iscsid.conf's", "target", d.target, "portal", portal)
		return nil
	}
	return fail(fmt.Sprintf("the login through it failed too: %v: %s", err, trimISCSIOutput(out)))
}

// iscsiNodeDBDirs are where open-iscsi keeps its node records: /etc/iscsi
// on Debian, Ubuntu and SUSE, /var/lib/iscsi on RHEL and Fedora.
var iscsiNodeDBDirs = []string{"/etc/iscsi/nodes", "/var/lib/iscsi/nodes"}

// savedISCSIRecords is a copy of a target's node records as open-iscsi stores
// them (<db>/<target>/<portal>,<tpgt>/<iface>, or a file per portal in older
// layouts), taken from every node database that has the target.
type savedISCSIRecords struct {
	trees []savedTree
}

type savedTree struct {
	root    string
	entries []savedEntry // in walk order: a directory before what is in it
}

type savedEntry struct {
	rel  string
	dir  bool
	mode fs.FileMode
	data []byte
}

// saveISCSIRecords copies every node record of target. The error says why
// there is no copy: the target has no record in any node database litevirt
// knows, or an entry is not a plain file or directory.
func saveISCSIRecords(target string) (*savedISCSIRecords, error) {
	var s savedISCSIRecords
	for _, db := range iscsiNodeDBDirs {
		ents, err := os.ReadDir(db)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() || !strings.EqualFold(e.Name(), target) {
				continue
			}
			root := filepath.Join(db, e.Name())
			tree := savedTree{root: root}
			werr := filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				info, err := de.Info()
				if err != nil {
					return err
				}
				switch {
				case info.IsDir():
					tree.entries = append(tree.entries, savedEntry{rel: rel, dir: true, mode: info.Mode().Perm()})
				case info.Mode().IsRegular():
					b, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					tree.entries = append(tree.entries, savedEntry{rel: rel, mode: info.Mode().Perm(), data: b})
				default:
					return fmt.Errorf("%s is not a plain file", path)
				}
				return nil
			})
			if werr != nil {
				return nil, fmt.Errorf("copy the node records of %s: %w", target, werr)
			}
			s.trees = append(s.trees, tree)
		}
	}
	if len(s.trees) == 0 {
		return nil, fmt.Errorf("no node record of %s under %s", target, strings.Join(iscsiNodeDBDirs, " or "))
	}
	return &s, nil
}

// restore writes the saved records back and removes what was added under the
// target since, so the target's records are as they were.
func (s *savedISCSIRecords) restore() error {
	var errs []error
	for _, t := range s.trees {
		keep := make(map[string]bool, len(t.entries))
		for _, e := range t.entries {
			keep[e.rel] = true
			p := filepath.Join(t.root, e.rel)
			if e.dir {
				if err := os.MkdirAll(p, e.mode); err != nil {
					errs = append(errs, err)
				} else if err := os.Chmod(p, e.mode); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			if err := os.WriteFile(p, e.data, e.mode); err != nil {
				errs = append(errs, err)
			} else if err := os.Chmod(p, e.mode); err != nil {
				errs = append(errs, err)
			}
		}
		var extra []string
		_ = filepath.WalkDir(t.root, func(path string, de fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, rerr := filepath.Rel(t.root, path)
			if rerr != nil || keep[rel] {
				return nil
			}
			extra = append(extra, path)
			if de.IsDir() {
				return filepath.SkipDir
			}
			return nil
		})
		sort.Sort(sort.Reverse(sort.StringSlice(extra)))
		for _, p := range extra {
			if err := os.RemoveAll(p); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
