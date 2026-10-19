package lxc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
)

// ErrOCIItemExists is a pull into a Dest that already holds an unpacked
// bundle, without PullOCIOptions.Replace.
var ErrOCIItemExists = errors.New("an OCI image is already unpacked there")

// ImageGenFile is the file in a pulled bundle that names the pull it came
// from: a fresh random generation on every pull. A container created from the
// bundle records it (Container.ImageGen), so content replaced behind an
// unchanged path is told apart from the image the container was built from.
// A bundle pulled before generations were written has none ("").
const ImageGenFile = ".litevirt-image-gen"

// unpackDirName is the directory in the item's parent where a replacing pull
// stages: "<item>+<random>" for the new bundle, and that name plus oldPlus
// for the old one while the two are swapped (replaceBundle). A pull refuses
// an item name with "+" (safename's charset has none, and PullOCI checks an
// absolute dest too), so nothing in or named like this directory is a new
// item; an item an earlier build let an Admin name with "+" is still
// recovered by its name (stagedItem, safeItemName). RecoverOCILibrary and
// recoverItem touch nothing else.
const (
	unpackDirName = ".litevirt+unpack"
	oldPlus       = "+old"
)

// stageUnpack makes the directory a replacing pull of dest unpacks into.
func stageUnpack(dest string) (string, error) {
	dir := filepath.Join(filepath.Dir(dest), unpackDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("stage the unpack of %s: %w", dest, err)
	}
	stage, err := os.MkdirTemp(dir, filepath.Base(dest)+"+")
	if err != nil {
		return "", fmt.Errorf("stage the unpack of %s: %w", dest, err)
	}
	return stage, nil
}

func writeImageGen(bundle string) error {
	if err := os.WriteFile(filepath.Join(bundle, ImageGenFile), []byte(randid.New()+"\n"), 0o644); err != nil {
		return fmt.Errorf("record the image generation in %s: %w", bundle, err)
	}
	return nil
}

// ReadImageGen is the generation of the bundle at dir ("" when it has none
// or it cannot be read).
func ReadImageGen(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, ImageGenFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// BundleDir is the bundle directory a rootfs template path names: the
// path itself, or its parent when it names the bundle's rootfs/.
func BundleDir(abs string) string {
	if filepath.Base(abs) == "rootfs" {
		return filepath.Dir(abs)
	}
	return abs
}

var ociItemLocks sync.Map // bundle dir → *sync.Mutex

// lockItemFile takes an exclusive flock on dest's lock file,
// <parent>/.litevirt+unpack/<item>.lock, waiting for it: the lock another
// process (lv ct pull --local beside the daemon) takes too, so only one
// touches the item's staging entries at a time. It returns the release.
func lockItemFile(ctx context.Context, dest string) (func(), error) {
	dir := filepath.Join(filepath.Dir(dest), unpackDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("lock %s: %w", dest, err)
	}
	path := filepath.Join(dir, filepath.Base(dest)+lockSuffix)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", dest, err)
	}
	for {
		ok, err := flockTry(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("lock %s: %w", dest, err)
		}
		if ok && lockAtPath(f, path) {
			return func() { _ = f.Close() }, nil
		}
		if ok {
			// The file was removed (an item's lock is cleaned up once the
			// item is gone) while this waited on it: lock the file now at
			// the path instead, unless the caller has given up.
			_ = f.Close()
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("lock %s: %w", dest, err)
			}
			if f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600); err != nil {
				return nil, fmt.Errorf("lock %s: %w", dest, err)
			}
			continue
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("lock %s: %w", dest, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// tryLockItem takes item's lock in the staging directory dir without
// waiting: ok is false while another process holds it.
func tryLockItem(dir, item string) (release func(), ok bool) {
	f, err := os.OpenFile(filepath.Join(dir, item+lockSuffix), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false
	}
	if got, err := flockTry(f); err != nil || !got || !lockAtPath(f, filepath.Join(dir, item+lockSuffix)) {
		_ = f.Close()
		return nil, false
	}
	return func() { _ = f.Close() }, true
}

// lockAtPath is lockIsAtPath; a test replaces it.
var lockAtPath = lockIsAtPath

// lockIsAtPath reports whether the locked file f is still the file at path:
// a lock on a file removed from it locks nothing.
func lockIsAtPath(f *os.File, path string) bool {
	held, err := f.Stat()
	if err != nil {
		return false
	}
	now, err := os.Stat(path)
	return err == nil && os.SameFile(held, now)
}

// removeItemLock unlinks item's lock file in the staging directory dir when
// the item does not exist at parent and nobody holds its lock: it is taken
// without waiting, and the file is unlinked only while held.
func removeItemLock(dir, parent, item string) {
	if _, err := os.Lstat(filepath.Join(parent, item)); !errors.Is(err, os.ErrNotExist) {
		return
	}
	release, ok := tryLockItem(dir, item)
	if !ok {
		return
	}
	defer release()
	if err := os.Remove(filepath.Join(dir, item+lockSuffix)); err == nil {
		slog.Info("oci library: removed the lock of an item that no longer exists", "item", item)
	}
}

// ErrSourceRefused is a pull source refused as named (a transport, path or
// kind it may not read), and ErrStagingSpace a pull refused for the space it
// would leave free: errors.Is tells the caller a refusal from a failure.
var (
	ErrSourceRefused = errors.New("oci: source refused")
	ErrStagingSpace  = errors.New("oci: not enough space")
)

// refusal is a refusal's message, which unwraps to its kind.
type refusal struct {
	msg  string
	kind error
	err  error
}

func (r *refusal) Error() string { return r.msg }
func (r *refusal) Unwrap() []error {
	if r.err == nil {
		return []error{r.kind}
	}
	return []error{r.kind, r.err}
}

func refused(format string, args ...any) error {
	e := fmt.Errorf(format, args...)
	return &refusal{msg: e.Error(), kind: ErrSourceRefused, err: errors.Unwrap(e)}
}

func spaceRefused(format string, args ...any) error {
	e := fmt.Errorf(format, args...)
	return &refusal{msg: e.Error(), kind: ErrStagingSpace, err: errors.Unwrap(e)}
}

// lockSuffix names an item's lock file in the staging directory; recovery
// leaves those alone.
const lockSuffix = ".lock"

// LockOCIItem serialises, in this daemon, everything that reads or replaces
// the bundle at dir (a replacing pull, a create copying it, a fetch judging
// it), so a create never copies a bundle half replaced. It returns the unlock.
func LockOCIItem(dir string) func() {
	m, _ := ociItemLocks.LoadOrStore(canonPath(dir), &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// IsBundle reports whether dir holds an unpacked OCI bundle: umoci's
// config.json beside a rootfs. A directory holding only one of them is not
// one (umoci refuses it, and nothing in it is removed).
func IsBundle(dir string) (bool, error) {
	for _, f := range []string{"config.json", "rootfs"} {
		if _, err := os.Lstat(filepath.Join(dir, f)); errors.Is(err, os.ErrNotExist) {
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("read dest: %w", err)
		}
	}
	return true, nil
}

// replaceBundle puts the bundle unpacked at stage in dest's place, and
// removes the bundle dest held. Both are on dest's filesystem (the staging
// directory is in dest's parent), so each step is a
// rename; if the second fails, the old bundle is put back. A crash between
// the two leaves the old bundle at stage+oldPlus, which
// RecoverOCILibrary puts back.
func replaceBundle(stage, dest string) error {
	old := stage + oldPlus
	if err := os.Rename(dest, old); err != nil {
		return fmt.Errorf("replace %s: set the old image aside: %w", dest, err)
	}
	if err := os.Rename(stage, dest); err != nil {
		if rerr := os.Rename(old, dest); rerr != nil {
			return fmt.Errorf("replace %s: %w; and putting the old image back failed: %v (it is at %s)", dest, err, rerr, old)
		}
		return fmt.Errorf("replace %s: %w; the old image was kept", dest, err)
	}
	if err := os.RemoveAll(old); err != nil {
		return fmt.Errorf("pulled into %s, but removing the old image at %s failed: %w", dest, old, err)
	}
	return nil
}

// RecoverOCILibrary finishes, at daemon start, what a crash left of a
// replacing pull in the OCI library lib (its unpackDirName), item by item.
// An item whose lock another process holds (lv ct pull --local, running
// now) is left alone: its entries are live. For any other item, the lock is
// taken, any process still working in one of its entries is stopped (the
// dead daemon's tools), and the entries are recovered (recoverStaged).
func RecoverOCILibrary(lib string) error {
	dir := filepath.Join(lib, unpackDirName)
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	items := map[string]bool{}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), lockSuffix) {
			items[stagedItem(e.Name())] = true
		}
	}
	var errs []error
	for item := range items {
		if item == "" {
			continue // not an entry a pull made
		}
		release, ok := tryLockItem(dir, item)
		if !ok {
			slog.Info("oci library: a pull of this item is running in another process; its staging is left to it", "item", item)
			continue
		}
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), lockSuffix) && stagedItem(e.Name()) == item {
				stopWorkersIn(filepath.Join(dir, e.Name()))
			}
		}
		if err := recoverStaged(dir, lib, item); err != nil {
			errs = append(errs, err)
		}
		release()
	}
	// The lock of an item that no longer exists, and that nobody holds now.
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if item, ok := strings.CutSuffix(e.Name(), lockSuffix); ok && safeItemName(item) && !hasStaged(ents, item) {
				removeItemLock(dir, lib, item)
			}
		}
	}
	return errors.Join(errs...)
}

// hasStaged reports whether ents (a staging directory) still hold an entry
// of item.
func hasStaged(ents []os.DirEntry, item string) bool {
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), lockSuffix) && stagedItem(e.Name()) == item {
			return true
		}
	}
	return false
}

// recoverItem finishes, under dest's item lock, what a crash left of an
// earlier replacing pull of dest: PullOCI runs it first, so an item outside
// the library, which the start-up recovery does not read, is recovered too.
func recoverItem(dest string) error {
	return recoverStaged(filepath.Join(filepath.Dir(dest), unpackDirName), filepath.Dir(dest), filepath.Base(dest))
}

// recoverStaged recovers the entries of the staging directory dir whose
// items live in parent, only item's when item is not "": an old bundle set
// aside whose item is missing goes back in its place (the swap never
// finished); one whose item is there is removed (it finished); a staged
// unpack is removed. When several old bundles of one missing item remain,
// the first in name order goes back and the rest are removed.
func recoverStaged(dir, parent, item string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, lockSuffix) {
			continue // an item's lock (lockItemFile), not a leftover
		}
		it := stagedItem(n)
		if item != "" && it != item {
			continue
		}
		p := filepath.Join(dir, n)
		if strings.HasSuffix(n, oldPlus) && it != "" && safeItemName(it) {
			if _, serr := os.Lstat(filepath.Join(parent, it)); errors.Is(serr, os.ErrNotExist) {
				slog.Warn("oci library: a replacing pull was interrupted; putting the old image back", "item", it)
				if rerr := os.Rename(p, filepath.Join(parent, it)); rerr != nil {
					errs = append(errs, rerr)
				}
				continue
			}
		}
		if rerr := removeStaged(p); rerr != nil {
			errs = append(errs, rerr)
		} else {
			slog.Info("oci library: removed what an interrupted pull left", "path", p)
		}
	}
	return errors.Join(errs...)
}

// removeStaged removes a staging entry, retrying briefly while a process
// being stopped releases it.
func removeStaged(p string) error {
	var err error
	for i := 0; i < 10; i++ {
		if err = os.RemoveAll(p); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// stagedItem is the item a staging entry belongs to: its name with the
// known suffixes ("+old", then "+<random>") stripped from the end.
func stagedItem(n string) string {
	n = strings.TrimSuffix(n, oldPlus)
	if i := strings.LastIndex(n, "+"); i > 0 {
		return n[:i]
	}
	return ""
}

// safeItemName reports whether item can be put back as a library item: a
// safe name (safename), allowing the "+" an Admin's absolute --dest could
// carry before pulls refused it.
func safeItemName(item string) bool {
	return item != unpackDirName && safename.ValidateName(strings.ReplaceAll(item, "+", "_")) == nil
}

// RootfsReferences names the containers in this runner's store whose config
// points lxc.rootfs.path at dir or anything under it. A container created
// by v1.0.5 to v1.1.0 from a library item used the item's rootfs in place,
// so the item cannot be replaced while one exists. A config that cannot be
// read is named too: it cannot be shown not to.
func (r *LxcRunner) RootfsReferences(dir string) ([]string, error) {
	lit, res := filepath.Clean(dir), canonPath(dir)
	under := func(p, d string) bool { return p == d || strings.HasPrefix(p, d+string(filepath.Separator)) }
	ents, err := os.ReadDir(r.lxcpath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		// Only the fetch stage is not a container: earlier releases allowed
		// container names starting with ".", and one may use an item in place.
		if !e.IsDir() || e.Name() == fetchDirName {
			continue
		}
		cfg := filepath.Join(r.lxcpath(), e.Name(), "config")
		ref, err := configRootfsPath(cfg)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			out = append(out, e.Name())
			continue
		}
		// Literal or resolved, either side: a path literally under the item
		// that resolves out of it still runs from the item's tree.
		if ref == "" {
			continue
		}
		if refsItem(ref, lit, res, under) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// refsItem reports whether ref runs from the item's tree: ref, or any of
// its ancestors, literal or resolved, is under the literal or resolved item
// path. The ancestors catch a path that reaches the item through an alias
// and leaves it again through a link inside the image.
func refsItem(ref, lit, res string, under func(p, d string) bool) bool {
	for p := ref; ; p = filepath.Dir(p) {
		rp := canonPath(p)
		if under(p, lit) || under(p, res) || under(rp, lit) || under(rp, res) {
			return true
		}
		if filepath.Dir(p) == p {
			return false
		}
	}
}

// configRootfsPath is the directory a container config's lxc.rootfs.path
// names ("dir:" stripped), cleaned; "" when it names none.
func configRootfsPath(cfg string) (string, error) {
	f, err := os.Open(cfg)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok || strings.TrimSpace(k) != "lxc.rootfs.path" {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.TrimPrefix(v, "dir:")
		if v == "" {
			return "", nil
		}
		return filepath.Clean(v), nil
	}
	return "", sc.Err()
}

// canonPath is p with every symlink resolved, so two paths to one directory
// (a symlinked data directory) compare equal; for a path that does not exist
// yet, its nearest existing parent is resolved and the rest kept.
func canonPath(p string) string {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p
	}
	return filepath.Join(canonPath(parent), filepath.Base(p))
}
