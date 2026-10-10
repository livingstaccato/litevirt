package filerestore

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// volume is one filesystem the agent serves. Paths are relative to the
// volume root ("" is the root). Neither implementation ever follows a
// symlink: a symlink is reported as one, and a path through one is refused.
type volume interface {
	fstype() string
	// list returns the entries of directory rel (at most max of them, with
	// truncated set when there were more).
	list(rel string, max int) (entries []Entry, truncated bool, err error)
	// walk calls fn for rel and, when rel is a directory, everything below
	// it, parents before children. name is the path relative to the volume
	// root. open is non-nil for a regular file.
	walk(rel string, fn walkFunc) error
}

type walkFunc func(name string, e Entry, open func() (io.ReadCloser, error)) error

var errNotDir = errors.New("not a directory")

// ── a mounted filesystem ────────────────────────────────────────────────

// dirVolume serves a directory: inside the restore VM, the read-only
// mount point of one guest filesystem. (Tests serve a temp dir.)
type dirVolume struct {
	root string
	fs   string
}

func (v *dirVolume) fstype() string { return v.fs }

// resolve maps rel to a path under the volume root, refusing any component
// on the way down that is a symlink or not a directory.
func (v *dirVolume) resolve(rel string) (string, error) {
	p := v.root
	if rel == "" {
		return p, nil
	}
	parts := strings.Split(rel, "/")
	for i, c := range parts {
		if !ValidName(c) {
			return "", fmt.Errorf("%w: component %q", ErrBadPath, c)
		}
		p = filepath.Join(p, c)
		if i == len(parts)-1 {
			break
		}
		st, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			return "", fmt.Errorf("%s: path goes through a symlink; symlinks are not followed", "/"+strings.Join(parts[:i+1], "/"))
		}
		if !st.IsDir() {
			return "", fmt.Errorf("%s: %w", "/"+strings.Join(parts[:i+1], "/"), errNotDir)
		}
	}
	return p, nil
}

func entryFromInfo(name, full string, st fs.FileInfo) Entry {
	e := Entry{Name: name, Size: st.Size(), Mode: uint32(st.Mode().Perm()), MTime: st.ModTime().Unix()}
	switch m := st.Mode(); {
	case m.IsRegular():
		e.Type = TypeFile
	case m.IsDir():
		e.Type, e.Size = TypeDir, 0
	case m&fs.ModeSymlink != 0:
		e.Type, e.Size = TypeSymlink, 0
		if t, err := os.Readlink(full); err == nil {
			e.Target = t
		}
	default:
		e.Type, e.Size = TypeOther, 0
	}
	return e
}

func (v *dirVolume) list(rel string, max int) ([]Entry, bool, error) {
	p, err := v.resolve(rel)
	if err != nil {
		return nil, false, err
	}
	st, err := os.Lstat(p)
	if err != nil {
		return nil, false, err
	}
	if !st.IsDir() {
		return nil, false, fmt.Errorf("/%s: %w", rel, errNotDir)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(max + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	truncated := len(names) > max
	if truncated {
		names = names[:max]
	}
	sort.Strings(names)
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		full := filepath.Join(p, n)
		st, err := os.Lstat(full)
		if err != nil {
			continue
		}
		out = append(out, entryFromInfo(n, full, st))
	}
	return out, truncated, nil
}

func (v *dirVolume) walk(rel string, fn walkFunc) error {
	p, err := v.resolve(rel)
	if err != nil {
		return err
	}
	// WalkDir never follows symlinks, the root included (it Lstats it).
	return filepath.WalkDir(p, func(full string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if full == p {
				return werr
			}
			// An unreadable directory below the selection is left out,
			// not the whole archive.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		r, err := filepath.Rel(v.root, full)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(r)
		if name == "." {
			name = ""
		}
		st, err := os.Lstat(full)
		if err != nil {
			return nil // vanished or unreadable: skip
		}
		e := entryFromInfo(path.Base(name), full, st)
		var open func() (io.ReadCloser, error)
		if e.Type == TypeFile {
			open = func() (io.ReadCloser, error) {
				// O_NOFOLLOW: a symlink swapped in since the Lstat is refused.
				return os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			}
		}
		return fn(name, e, open)
	})
}

// ── a container archive ─────────────────────────────────────────────────

// tarNode is one entry of an indexed archive.
type tarNode struct {
	e        Entry
	off      int64 // data offset in the archive (regular files)
	children map[string]*tarNode
}

// tarVolume serves a tar archive (a container backup) from a random-access
// device: inside the restore VM, the backup disk itself. It is indexed once
// by a sequential scan; extraction then reads each file's data in place.
type tarVolume struct {
	dev  io.ReaderAt
	root *tarNode
}

func (v *tarVolume) fstype() string { return "tar" }

// maxTarIndex bounds the index (memory in the restore VM).
const maxTarIndex = 4_000_000

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Seek lets tar.Reader skip file data without reading it (it seeks when it
// can), so indexing reads headers, not the whole archive.
func (c *countingReader) Seek(off int64, whence int) (int64, error) {
	s, ok := c.r.(io.Seeker)
	if !ok {
		return 0, errors.New("not seekable")
	}
	pos, err := s.Seek(off, whence)
	if err == nil {
		c.n = pos
	}
	return pos, err
}

// indexTar builds the tree of an archive of size bytes on dev. A container
// archive is "<name>/config" plus "<name>/rootfs/…"; when every entry is
// under one top directory holding a rootfs/, the volume root is that
// rootfs, which is what a caller of `/rootfs/etc/hosts` means.
func indexTar(dev io.ReaderAt, size int64) (*tarVolume, string, error) {
	cr := &countingReader{r: io.NewSectionReader(dev, 0, size)}
	tr := tar.NewReader(cr)
	root := &tarNode{e: Entry{Type: TypeDir}, children: map[string]*tarNode{}}
	count := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if count == 0 {
				return nil, "", fmt.Errorf("not a tar archive: %w", err)
			}
			break // a damaged tail: serve what was indexed
		}
		if count++; count > maxTarIndex {
			break
		}
		name := strings.Trim(path.Clean("/"+h.Name), "/")
		if name == "" || name == "." {
			continue
		}
		parts := strings.Split(name, "/")
		ok := true
		for _, c := range parts {
			if !ValidName(c) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		n := root
		for _, c := range parts[:len(parts)-1] {
			child := n.children[c]
			if child == nil {
				child = &tarNode{e: Entry{Name: c, Type: TypeDir, Mode: 0o755}, children: map[string]*tarNode{}}
				n.children[c] = child
			}
			if child.e.Type != TypeDir {
				ok = false
				break
			}
			n = child
		}
		if !ok {
			continue
		}
		leaf := parts[len(parts)-1]
		e := Entry{Name: leaf, Mode: uint32(h.Mode) & 0o7777, MTime: h.ModTime.Unix()}
		node := &tarNode{}
		sparse := h.Typeflag == tar.TypeGNUSparse
		for k := range h.PAXRecords {
			if strings.HasPrefix(k, "GNU.sparse.") {
				sparse = true
			}
		}
		switch {
		case sparse:
			// A sparse entry's data in the archive is not its content laid
			// out in order; it cannot be read in place.
			e.Type = TypeOther
		case h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA:
			e.Type, e.Size = TypeFile, h.Size
			node.off = cr.n // tar.Reader has consumed the header(s), nothing of the data
		case h.Typeflag == tar.TypeDir:
			e.Type = TypeDir
			if old := n.children[leaf]; old != nil && old.e.Type == TypeDir {
				old.e = Entry{Name: leaf, Type: TypeDir, Mode: e.Mode, MTime: e.MTime}
				continue
			}
			node.children = map[string]*tarNode{}
		case h.Typeflag == tar.TypeSymlink:
			e.Type, e.Target = TypeSymlink, h.Linkname
		case h.Typeflag == tar.TypeLink:
			// A hard link shares its target's data.
			if t := lookupTar(root, strings.Trim(path.Clean("/"+h.Linkname), "/")); t != nil && t.e.Type == TypeFile {
				e.Type, e.Size = TypeFile, t.e.Size
				node.off = t.off
			} else {
				e.Type = TypeOther
			}
		default:
			e.Type = TypeOther
		}
		node.e = e
		n.children[leaf] = node
	}
	vol := &tarVolume{dev: dev, root: root}
	if len(root.children) == 1 {
		for _, top := range root.children {
			if rf := top.children["rootfs"]; rf != nil && rf.e.Type == TypeDir {
				vol.root = rf
				return vol, "rootfs", nil
			}
		}
	}
	return vol, "archive", nil
}

func lookupTar(root *tarNode, rel string) *tarNode {
	n := root
	if rel == "" {
		return n
	}
	for _, c := range strings.Split(rel, "/") {
		if n.e.Type != TypeDir {
			return nil
		}
		if n = n.children[c]; n == nil {
			return nil
		}
	}
	return n
}

// resolve walks rel, refusing a path through a symlink.
func (v *tarVolume) resolve(rel string) (*tarNode, error) {
	n := v.root
	if rel == "" {
		return n, nil
	}
	parts := strings.Split(rel, "/")
	for i, c := range parts {
		if n.e.Type == TypeSymlink {
			return nil, fmt.Errorf("/%s: path goes through a symlink; symlinks are not followed", strings.Join(parts[:i], "/"))
		}
		if n.e.Type != TypeDir {
			return nil, fmt.Errorf("/%s: %w", strings.Join(parts[:i], "/"), errNotDir)
		}
		if n = n.children[c]; n == nil {
			return nil, fmt.Errorf("/%s: %w", rel, os.ErrNotExist)
		}
	}
	return n, nil
}

func sortedChildren(n *tarNode) []*tarNode {
	out := make([]*tarNode, 0, len(n.children))
	for _, c := range n.children {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].e.Name < out[j].e.Name })
	return out
}

func (v *tarVolume) list(rel string, max int) ([]Entry, bool, error) {
	n, err := v.resolve(rel)
	if err != nil {
		return nil, false, err
	}
	if n.e.Type != TypeDir {
		return nil, false, fmt.Errorf("/%s: %w", rel, errNotDir)
	}
	kids := sortedChildren(n)
	truncated := len(kids) > max
	if truncated {
		kids = kids[:max]
	}
	out := make([]Entry, 0, len(kids))
	for _, c := range kids {
		out = append(out, c.e)
	}
	return out, truncated, nil
}

func (v *tarVolume) walk(rel string, fn walkFunc) error {
	n, err := v.resolve(rel)
	if err != nil {
		return err
	}
	var visit func(name string, n *tarNode) error
	visit = func(name string, n *tarNode) error {
		var open func() (io.ReadCloser, error)
		if n.e.Type == TypeFile {
			off, size := n.off, n.e.Size
			open = func() (io.ReadCloser, error) {
				return io.NopCloser(io.NewSectionReader(v.dev, off, size)), nil
			}
		}
		e := n.e
		if name == "" {
			e.Name = ""
		}
		if err := fn(name, e, open); err != nil {
			return err
		}
		if n.e.Type == TypeDir {
			for _, c := range sortedChildren(n) {
				child := c.e.Name
				if name != "" {
					child = name + "/" + c.e.Name
				}
				if err := visit(child, c); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(rel, n)
}
