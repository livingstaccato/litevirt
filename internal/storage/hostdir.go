package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// A container can be handed a host DIRECTORY to read: a rootfs template is
// copied whole into the new container, and a local OCI layout is unpacked into
// one. Whoever names that directory reads everything under it from inside the
// container, so it is judged like a file a VM is given to read
// (CheckReadFile), plus one rule a file never needs: a directory that CONTAINS
// a protected place hands that place over too — "/" contains /etc, and the
// parent of the data directory contains state.db.

// OCILibraryDir is the directory under the data directory where `lv ct pull`
// stages OCI images by bare name. Each entry is one library item, which a
// container may be created from.
const OCILibraryDir = "oci"

// CheckReadDir refuses a host directory no container may be given as a rootfs
// template or OCI source: a relative or unclean path, anything under or
// containing a secret system directory, the daemon's PKI directory, its data
// directory (configured or default) or a directory containing it, inside it
// the daemon's own state, disks/ apart from disks/uploads/ and the roots of
// pools/ and mounts/ (dataDirReadDirRefusal: another child is an ordinary
// host path), and a user-data root (/home, /root, /run) itself, a home directory itself, or a
// link into a dot-directory the path does not name. The path is judged as
// written and after resolving symlinks, and must exist as a directory.
func CheckReadDir(p, dataDir, pkiDir string) error {
	return checkReadDir(p, dataDir, pkiDir, "", "")
}

// CheckTemplateDir is CheckReadDir for a container's rootfs template, which
// may also come from inside the LXC store lxcStore: LXC's own template cache,
// or another container's rootfs an Admin names. The store itself (every
// container at once) and ownDir, the directory of the container being made,
// are refused. Who may name a host path at all is the caller's to decide
// (storage.hostpath): this is the backstop. A VM is still never given a file
// in the store (CheckReadFile).
func CheckTemplateDir(p, dataDir, pkiDir, lxcStore, ownDir string) error {
	return checkReadDir(p, dataDir, pkiDir, lxcStore, ownDir)
}

func checkReadDir(p, dataDir, pkiDir, lxcStore, ownDir string) error {
	if err := checkReadPathLexical(p); err != nil {
		return err
	}
	for _, cand := range pathForms(p) {
		if lxcStore != "" {
			if inStore, err := judgeLXCStore(p, cand, lxcStore, ownDir); err != nil {
				return err
			} else if inStore {
				continue
			}
		}
		if err := refuseReadDir(p, cand, dataDir, pkiDir); err != nil {
			return err
		}
	}
	fi, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%q does not exist on this host", p)
		}
		return fmt.Errorf("%q: %w", p, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%q is not a directory", p)
	}
	return nil
}

func refuseReadDir(p, cand, dataDir, pkiDir string) error {
	if cand == "/" {
		return fmt.Errorf("%q is the filesystem root", p)
	}
	for _, root := range secretRoots {
		for _, r := range pathForms(root) {
			if within(r, cand) {
				return fmt.Errorf("%q is under %s, which holds host secrets or live system state", p, root)
			}
			if within(cand, r) {
				return fmt.Errorf("%q contains %s, which holds host secrets or live system state", p, root)
			}
		}
	}
	if pkiDir != "" {
		for _, d := range pathForms(pkiDir) {
			if within(d, cand) || within(cand, d) {
				return fmt.Errorf("%q overlaps the daemon's PKI directory %s", p, pkiDir)
			}
		}
	}
	for _, dd := range dataDirsToJudge(dataDir) {
		for _, d := range pathForms(dd) {
			if within(cand, d) {
				return fmt.Errorf("%q is the daemon's data directory %s or contains it", p, dd)
			}
			if err := dataDirReadDirRefusal(p, d, cand, dd); err != nil {
				return err
			}
		}
	}
	for _, root := range userDataRoots {
		for _, r := range pathForms(root) {
			if within(cand, r) {
				return fmt.Errorf("%q is or contains %s, where people keep their own files", p, root)
			}
			if filepath.Dir(cand) == r && filepath.Base(r) == "home" {
				return fmt.Errorf("%q is a whole home directory", p)
			}
			if within(r, cand) {
				if c := introducedDotComponent(p, cand); c != "" {
					return fmt.Errorf("%q is a link into %s, a dot-directory under a home or runtime directory, where keys and tokens live", p, c)
				}
			}
		}
	}
	return nil
}

// dataDirReadDirRefusal judges a directory cand strictly inside the data
// directory d by the rule pools and file reads use: content under pools/<x>,
// mounts/<x>, disks/uploads/ and the OCI library passes; the rest of disks/,
// the roots of pools/ and mounts/, and the daemon's own state (dataDirOwned)
// are refused; any other child (a main-era <data_dir>/rc5pool) is an ordinary
// host path.
func dataDirReadDirRefusal(p, d, cand, dataDir string) error {
	first, depth, ok := dataDirChild(d, cand)
	if !ok || inPoolArea(d, cand) || inDiskUploads(d, cand) || inOCILibrary(d, cand) {
		return nil
	}
	switch {
	case first == dataDirDisks:
		return fmt.Errorf("%q is inside disks/ in the daemon's data directory %s, which holds every VM's disks; of disks/ only disks/uploads/ holds content a container may be given", p, dataDir)
	case slices.Contains(dataDirPoolAreas, first) && depth == 1:
		return fmt.Errorf("%q is the root of the daemon's %s/ area in its data directory %s, which holds every pool there; name a directory inside one pool", p, first, dataDir)
	case dataDirChildOwned(first):
		return fmt.Errorf("%q is the daemon's own state (%s in its data directory %s)", p, first, dataDir)
	}
	return nil
}

// inOCILibrary reports whether p is strictly inside <dataDir>/oci.
func inOCILibrary(dataDir, p string) bool {
	lib := filepath.Join(dataDir, OCILibraryDir)
	return within(lib, p) && filepath.Clean(p) != lib
}

// OCILibraryItem reports whether p names an OCI library item a non-admin may
// create a container from: exactly <dataDir>/oci/<name> or its rootfs/, as
// written AND as resolved — a deeper path is inside an image's own rootfs,
// whose links the image chose.
func OCILibraryItem(p, dataDir string) bool {
	if dataDir == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return false
	}
	lib := filepath.Join(dataDir, OCILibraryDir)
	item := func(c string) bool {
		rel, err := filepath.Rel(lib, c)
		if err != nil || rel == "." || rel == ".." || len(rel) > 2 && rel[:3] == "../" {
			return false
		}
		dir, base := filepath.Split(rel)
		switch {
		case dir == "":
			return base != ""
		case base == "rootfs":
			parent := filepath.Clean(dir)
			return parent != "." && filepath.Dir(parent) == "."
		}
		return false
	}
	if !item(p) {
		return false
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		libR, lerr := filepath.EvalSymlinks(lib)
		if lerr != nil {
			return false
		}
		rel, rerr := filepath.Rel(lib, p)
		if rerr != nil || filepath.Join(libR, rel) != r {
			return false
		}
	}
	return true
}

// judgeLXCStore reports whether cand is strictly inside the LXC store (and so
// judged here, not as a secret root), refusing the store itself, anything
// containing it, and the container's own directory.
func judgeLXCStore(p, cand, store, ownDir string) (bool, error) {
	for _, s := range pathForms(store) {
		if within(cand, s) {
			return false, fmt.Errorf("%q is or contains the LXC container store %s", p, store)
		}
		if !within(s, cand) {
			continue
		}
		if ownDir != "" {
			for _, o := range pathForms(ownDir) {
				if within(o, cand) || within(cand, o) {
					return false, fmt.Errorf("%q is the directory of the container being made", p)
				}
			}
		}
		return true, nil
	}
	return false, nil
}

// SetSecretRootsForTest replaces the secret roots and returns what restores
// them, so a test can stand a temporary directory in for /var/lib/lxc.
func SetSecretRootsForTest(roots []string) (restore func()) {
	old := secretRoots
	secretRoots = roots
	return func() { secretRoots = old }
}
