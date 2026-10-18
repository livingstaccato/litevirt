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

	"github.com/litevirt/litevirt/internal/randid"
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

// unpackInfix names the directory a replacing pull unpacks into, beside the
// item: ".<item>.unpack-<random>"; the old bundle is set aside as that name
// plus oldSuffix while the two are swapped (replaceBundle).
const (
	unpackInfix = ".unpack-"
	oldSuffix   = ".old"
)

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
	m, _ := ociItemLocks.LoadOrStore(filepath.Clean(dir), &sync.Mutex{})
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
// removes the bundle dest held. Both are in one directory, so each step is a
// rename; if the second fails, the old bundle is put back. A crash between
// the two leaves the old bundle at stage+oldSuffix, which
// RecoverOCILibrary puts back.
func replaceBundle(stage, dest string) error {
	old := stage + oldSuffix
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
// replacing pull in the OCI library lib: an old bundle set aside whose item
// is missing goes back in its place (the swap never finished), one whose
// item is there is removed (it finished), and an unpack directory is
// removed. Nothing else in lib is touched.
func RecoverOCILibrary(lib string) error {
	ents, err := os.ReadDir(lib)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() || !strings.HasPrefix(n, ".") || !strings.Contains(n, unpackInfix) {
			continue
		}
		item := strings.TrimPrefix(n[:strings.LastIndex(n, unpackInfix)], ".")
		p := filepath.Join(lib, n)
		if strings.HasSuffix(n, oldSuffix) {
			if _, serr := os.Lstat(filepath.Join(lib, item)); errors.Is(serr, os.ErrNotExist) && item != "" {
				slog.Warn("oci library: a replacing pull was interrupted; putting the old image back", "item", item)
				if rerr := os.Rename(p, filepath.Join(lib, item)); rerr != nil {
					errs = append(errs, rerr)
				}
				continue
			}
		}
		if rerr := os.RemoveAll(p); rerr != nil {
			errs = append(errs, rerr)
		}
	}
	return errors.Join(errs...)
}

// RootfsReferences names the containers in this runner's store whose config
// points lxc.rootfs.path at dir or anything under it. A container created
// by v1.0.5 to v1.1.0 from a library item used the item's rootfs in place,
// so the item cannot be replaced while one exists. A config that cannot be
// read is named too: it cannot be shown not to.
func (r *LxcRunner) RootfsReferences(dir string) ([]string, error) {
	dir = filepath.Clean(dir)
	ents, err := os.ReadDir(r.lxcpath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
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
		if ref != "" && (ref == dir || strings.HasPrefix(ref, dir+string(filepath.Separator))) {
			out = append(out, e.Name())
		}
	}
	return out, nil
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
