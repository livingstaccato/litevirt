package cloudinit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/randid"
)

// Which VM a seed belongs to.
//
// A seed is name-keyed (<data_dir>/cloudinit/<name>.iso), and it outlives its
// VM on a host the VM left without a delete reaching it: a failover's old
// host, a --keep-disks delete. A VM created again under the name and started
// on such a host — a failover, a migration, a start — reused the file it found
// there, and booted the deleted VM's user-data: its SSH keys, its passwords,
// its network-config.
//
// So every seed litevirt writes is stamped with the identity of the VM it was
// written for, in a file beside it (<seed>.owner), and a seed is reused only
// for that VM; any other is generated again from the VM's own spec. The
// identity is the spec's uuid: minted by the server for every create and
// every clone, before the seed is written, and carried in the VM's row.
//
// A seed written before this release has no stamp, and nothing proves whose
// it is: it is generated again from the VM's own spec, and stamped. The
// instance-id is the VM's name either way, so a guest that already booted
// from it does not run its first-boot modules again.

// seedOwnerSuffix names the stamp beside a seed.
const seedOwnerSuffix = ".owner"

// SeedOwnerPath is where the stamp of the seed at iso is.
func SeedOwnerPath(iso string) string { return iso + seedOwnerSuffix }

// StampSeed records that the seed at iso was written for the VM whose spec
// uuid is owner. An empty owner (a VM from before stable uuids) removes the
// stamp, so the seed is judged as an unstamped one.
func StampSeed(iso, owner string) error {
	stamp := SeedOwnerPath(iso)
	if owner == "" {
		if err := os.Remove(stamp); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	// The sweep of stale seed temporaries (sweepStaleSeedTemps) covers this
	// name too. Durable: the stamp's bytes reach the disk before the rename
	// makes it the stamp, and the rename before this returns — a power cut
	// otherwise leaves an empty stamp (lab 2, abort proof, surprise 1).
	tmp := filepath.Join(filepath.Dir(iso), "."+filepath.Base(iso)+"."+randid.New()+".tmp")
	if err := writeSynced(tmp, []byte(owner+"\n")); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := renameFile(tmp, stamp); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(stamp))
}

// fileSync and dirSync are (*os.File).Sync, and renameFile is os.Rename, each
// reported to a test's ObserveSeedWrites; a test may also replace them.
var (
	fileSync   = func(f *os.File) error { return observed("sync", f.Name(), f.Sync()) }
	dirSync    = func(f *os.File) error { return observed("syncdir", f.Name(), f.Sync()) }
	renameFile = func(from, to string) error { return observed("rename", to, os.Rename(from, to)) }
)

// seedWriteObserver is the observer ObserveSeedWrites sets; nil outside it.
var seedWriteObserver atomic.Pointer[func(step, path string)]

// observed reports step on path to the observer when it succeeded, and
// returns err.
func observed(step, path string, err error) error {
	if f := seedWriteObserver.Load(); f != nil && err == nil {
		(*f)(step, path)
	}
	return err
}

// ObserveSeedWrites records, until t ends, each step of a durable seed write
// on a path under dir: "sync <file>" (a file's bytes reached the disk),
// "rename <to>" (it took its name), "syncdir <dir>" (the name reached the
// disk). The returned func reads what was recorded so far. Outside a test
// binary it panics.
func ObserveSeedWrites(t TestingT, dir string) func() []string {
	t.Helper()
	if !testing.Testing() {
		panic("cloudinit.ObserveSeedWrites called outside a test")
	}
	var (
		mu    sync.Mutex
		steps []string
	)
	f := func(step, path string) {
		if path != dir && !strings.HasPrefix(path, dir+string(filepath.Separator)) {
			return
		}
		mu.Lock()
		steps = append(steps, step+" "+path)
		mu.Unlock()
	}
	seedWriteObserver.Store(&f)
	t.Cleanup(func() { seedWriteObserver.CompareAndSwap(&f, nil) })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(steps)
	}
}

// syncFile syncs the file at p, so its bytes survive a power cut.
func syncFile(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	if err := fileSync(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeSynced writes b to a new file at p, mode 0600, and syncs it.
func writeSynced(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := fileSync(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syncDir syncs directory dir, so a rename in it survives a power cut.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return dirSync(d)
}

// RemoveSeed removes the seed at iso, its stamp and its stale mark.
func RemoveSeed(iso string) error {
	err := os.Remove(iso)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, p := range []string{SeedOwnerPath(iso), SeedStalePath(iso)} {
		if serr := os.Remove(p); serr != nil && !os.IsNotExist(serr) {
			return serr
		}
	}
	return nil
}

// seedStaleSuffix names the stale mark beside a seed.
const seedStaleSuffix = ".stale"

// SeedStalePath is where the stale mark of the seed at iso is.
func SeedStalePath(iso string) string { return iso + seedStaleSuffix }

// MarkSeedStale records that the seed at iso could not be brought up to date
// with the VM's NICs (a failed rebuild after an attach or detach, before a
// start, or for a migration), so it may not list NICs the VM has, although
// the domain beside it does. A later rebuild that succeeds (RebuildISO, or
// the seed written again) removes the mark. Until then the seed's names are
// read as possibly stale (Prior.Stale): a NIC it does not list may have been
// named elsewhere.
func MarkSeedStale(iso string) error {
	return os.WriteFile(SeedStalePath(iso), nil, 0o600)
}

// SeedMarkedStale reports whether the seed at iso carries a stale mark.
func SeedMarkedStale(iso string) bool {
	_, err := os.Lstat(SeedStalePath(iso))
	return err == nil
}

// seedTriedKey marks a context whose start has already tried the VM's seed.
type seedTriedKey struct{}

// WithSeedTriedForStart returns ctx marked as a start whose caller has already
// tried to bring the VM's seed on this host up to date for it (the
// reconciler, which rewrites the VM's own seed before it defines the domain).
// The start hook (grpcapi's PrepareHardwareForStart) then does not try a stale
// seed again, so one failed rebuild is one warning.
func WithSeedTriedForStart(ctx context.Context) context.Context {
	return context.WithValue(ctx, seedTriedKey{}, true)
}

// SeedTriedForStart reports whether ctx is marked by WithSeedTriedForStart.
func SeedTriedForStart(ctx context.Context) bool {
	tried, _ := ctx.Value(seedTriedKey{}).(bool)
	return tried
}

// clearSeedStale removes the stale mark of the seed at iso. Best effort: a
// mark left behind only has the seed's names read as possibly stale.
func clearSeedStale(iso string) { _ = os.Remove(SeedStalePath(iso)) }

// SeedOwner returns the stamp of the seed at iso: ok=false when it has none.
// A stamp that is there but empty or unreadable (a stamp written before
// stamps were synced, cut short by a power loss, can be empty or hold zeroed
// blocks) is ok with owner "": its owner is not known, and a caller must not
// read it as another VM's. A stamp is a uuid, so anything but printable
// ASCII in it is unreadable.
func SeedOwner(iso string) (owner string, ok bool, err error) {
	b, err := os.ReadFile(SeedOwnerPath(iso))
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	owner = strings.TrimSpace(string(b))
	if strings.IndexFunc(owner, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0 {
		return "", true, nil
	}
	return owner, true, nil
}

// SeedIsFor reports whether the seed at iso exists and is stamped as written
// for the VM whose spec uuid is owner. An unstamped seed, a VM with no uuid,
// or anything unreadable answers no, and the caller writes the seed again.
func SeedIsFor(iso, owner string) bool {
	fi, err := os.Stat(iso)
	if err != nil || !fi.Mode().IsRegular() || owner == "" {
		return false
	}
	stamp, stamped, err := SeedOwner(iso)
	return err == nil && stamped && stamp == owner
}

// SpecUUID is the uuid of a VM spec stored as JSON, "" when it has none.
func SpecUUID(specJSON string) string {
	var s struct {
		UUID string `json:"uuid"`
	}
	if json.Unmarshal([]byte(specJSON), &s) != nil {
		return ""
	}
	return s.UUID
}
