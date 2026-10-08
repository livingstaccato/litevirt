package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// containing a secret system directory, the daemon's PKI directory, or its
// data directory (apart from pool content and the OCI library), and a
// user-data root (/home, /root, /run) itself, a home directory itself, or a
// link into a dot-directory the path does not name. The path is judged as
// written and after resolving symlinks, and must exist as a directory.
func CheckReadDir(p, dataDir, pkiDir string) error {
	if err := checkReadPathLexical(p); err != nil {
		return err
	}
	for _, cand := range pathForms(p) {
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
	if dataDir != "" {
		for _, d := range pathForms(dataDir) {
			if within(cand, d) {
				return fmt.Errorf("%q is the daemon's data directory %s or contains it", p, dataDir)
			}
			if within(d, cand) && !inPoolArea(d, cand) && !inDiskUploads(d, cand) && !inOCILibrary(d, cand) {
				return fmt.Errorf("%q is inside the daemon's data directory %s; only its pools/, mounts/, disks/uploads/ and %s/ hold content a container may be given", p, dataDir, OCILibraryDir)
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
