package lxc

import (
	"bufio"
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
// replacing pull in the OCI library lib (its unpackDirName), item by item
// (recoverStaged). Nothing outside unpackDirName is touched.
func RecoverOCILibrary(lib string) error {
	dir := filepath.Join(lib, unpackDirName)
	if _, err := os.Lstat(dir); err == nil {
		stopWorkersIn(dir) // at start: whatever works there was the dead daemon's
	}
	return recoverStaged(dir, lib, "")
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
