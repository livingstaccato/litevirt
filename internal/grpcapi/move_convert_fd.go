package grpcapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// heldConvert is what convertImageWith hands qemu-img, opened by this
// process with no link followed and judged through the descriptors: every
// file of the source chain, top first, with the format each is read as, and
// the destination. qemu-img is given them as /proc/self/fd/N (ExtraFiles),
// never by name, and the descriptors stay open for its whole run, so a name
// swapped for a link after the checks cannot make it read or write another
// file.
//
// qemu-img follows a qcow2 layer's backing file by NAME, and resolves a
// relative one against the directory of the name it opened the layer by. A
// /proc/self/fd/N name has no such directory, and a by-name backing is the
// very gap closed here, so the source is a json: filename naming every
// layer explicitly ("backing": {"driver": …, "file": {"filename":
// "/proc/self/fd/M"}}, and so on down the chain, the last qcow2 layer
// "backing": null): qemu-img then opens no file by any name a header holds,
// even one written into it in place after the checks. Which file each
// descriptor is was judged here: its backing name, read from the open file
// above it and resolved as precheckChain resolves it, must be exactly the
// backing precheckChain accepted.
type heldConvert struct {
	layers  []*os.File
	formats []string
	dst     *os.File
	// dstDir is the destination's directory, held open; dstCreated: the
	// destination was made by this call (removeCreated takes it back).
	dstDir     *os.File
	dstCreated bool
}

func (h *heldConvert) close() {
	for _, f := range h.layers {
		f.Close()
	}
	if h.dst != nil {
		h.dst.Close()
	}
	if h.dstDir != nil {
		h.dstDir.Close()
	}
}

// removeCreated removes the destination when this call made it, through its
// held directory (unlinkat), and only while that name is still the file it
// made: a refused copy leaves nothing it created. A destination its caller
// made is the caller's.
func (h *heldConvert) removeCreated() {
	if !h.dstCreated || h.dst == nil || h.dstDir == nil {
		return
	}
	name := filepath.Base(h.dst.Name())
	fi, err := h.dst.Stat()
	if err != nil {
		return
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(h.dstDir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint64(sys.Dev) != uint64(st.Dev) || uint64(sys.Ino) != uint64(st.Ino) {
		return
	}
	_ = unix.Unlinkat(int(h.dstDir.Fd()), name, 0)
}

// openConvertTop opens the source's top layer and the destination before
// anything judges them by name: the source no-follow and regular; the
// destination, beneath its directory held open, a file the caller made,
// no-follow, regular and with no other name (a hard link planted at it
// would let the copy write another file), or made here (O_EXCL, owner-only)
// when it is not there yet.
func openConvertTop(src, srcFormat, dst string) (*heldConvert, error) {
	top, _, err := openRegularNoFollow(src)
	if err != nil {
		return nil, fmt.Errorf("source %s: %w", src, err)
	}
	h := &heldConvert{layers: []*os.File{top}, formats: []string{srcFormat}}
	fail := func(err error) (*heldConvert, error) {
		h.removeCreated()
		h.close()
		return nil, err
	}
	dir := filepath.Dir(dst)
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(fmt.Errorf("destination directory %s: %w", dir, err))
	}
	h.dstDir = os.NewFile(uintptr(dfd), dir)
	name := filepath.Base(dst)
	fd, err := unix.Openat(dfd, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		fd, err = unix.Openat(dfd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(diskmode.File))
		h.dstCreated = err == nil
	}
	if err != nil {
		return fail(fmt.Errorf("destination %s: %w", dst, err))
	}
	h.dst = os.NewFile(uintptr(fd), dst)
	fi, err := h.dst.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return fail(fmt.Errorf("destination %s is not a regular file", dst))
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); !ok || sys.Nlink != 1 {
		return fail(fmt.Errorf("destination %s has another name (a hard link); it is not written", dst))
	}
	return h, nil
}

// openBackings opens the rest of a qcow2 source's chain through the top
// layer already held: each layer's header is judged through its descriptor
// (precheckQcow2HeaderFile), its backing name resolved as precheckChain
// resolves it, and that must be accepted[i]; the backing is then opened
// no-follow, regular, and the kernel's name for the open file must be
// exactly that accepted path (no directory on the way swapped since). A raw
// backing ends the chain.
func (h *heldConvert) openBackings(src string, accepted []string) error {
	path := src
	for i := 0; ; i++ {
		f := h.layers[len(h.layers)-1]
		info, err := precheckQcow2HeaderFile(path, f)
		if err != nil {
			return err
		}
		if info.BackingFile == "" {
			if i != len(accepted) {
				return fmt.Errorf("%s names no backing file, where its checks accepted %d more", path, len(accepted)-i)
			}
			return nil
		}
		if i >= len(accepted) {
			return fmt.Errorf("%s names backing file %q, which its checks did not accept", path, info.BackingFile)
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		resolved, err := filepath.EvalSymlinks(b)
		if err != nil || resolved != accepted[i] {
			return fmt.Errorf("%s: backing file %q is not the one its checks accepted (%s)", path, info.BackingFile, accepted[i])
		}
		if info.BackingFormat != "qcow2" && info.BackingFormat != "raw" {
			return fmt.Errorf("%s names backing file %q with format %q", path, info.BackingFile, info.BackingFormat)
		}
		if backingOpenHook != nil {
			backingOpenHook(resolved)
		}
		bf, _, err := openRegularNoFollow(resolved)
		if err != nil {
			return fmt.Errorf("backing %s: %w", resolved, err)
		}
		h.layers = append(h.layers, bf)
		h.formats = append(h.formats, info.BackingFormat)
		// Named by exactly the path the checks accepted: resolved is fully
		// resolved, so a directory on the way swapped for a link since then
		// gives the open file another name (namedBy alone resolves the path
		// again, now, and would agree with the swap).
		if named, err := os.Readlink(procFDPrefix + strconv.Itoa(int(bf.Fd()))); err != nil || named != resolved {
			return fmt.Errorf("backing %s changed while it was opened (now %q)", resolved, named)
		}
		if err := namedBy(bf, resolved); err != nil {
			return err
		}
		if info.BackingFormat == "raw" {
			if i+1 != len(accepted) {
				return fmt.Errorf("raw backing %s ends the chain, where its checks accepted %d more", resolved, len(accepted)-i-1)
			}
			return nil
		}
		path = resolved
	}
}

// namedBy refuses unless f is still the file the path resolved names: the
// kernel's name for the open file (/proc/self/fd/N) is p resolved through
// symlinks now, and p's final component is not a link. Off Linux there is
// no /proc, and it refuses.
func namedBy(f *os.File, p string) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	li, err := os.Lstat(p)
	if err != nil || !os.SameFile(fi, li) {
		return fmt.Errorf("%s changed while it was opened", p)
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return fmt.Errorf("%s changed while it was opened (%v)", p, err)
	}
	named, err := os.Readlink(procFDPrefix + strconv.Itoa(int(f.Fd())))
	if err != nil || named != r {
		return fmt.Errorf("%s changed while it was opened (now %q)", p, named)
	}
	return nil
}

// verifyNamed re-checks, after every by-name check, that the source's top
// layer and the destination are still the files those names lead to.
func (h *heldConvert) verifyNamed(src, dst string) error {
	if err := namedBy(h.layers[0], src); err != nil {
		return err
	}
	return namedBy(h.dst, dst)
}

// qemuImgArgs is the qemu-img convert argv for h, with the descriptors it
// takes as ExtraFiles (the child's fd 3 onwards, in that order). The source
// is a json: filename naming the whole chain, each layer's file a
// descriptor, and the last qcow2 layer "backing": null: a backing name
// written into its header in place after the checks is not opened either.
// (A data file cannot be pinned this way; one is refused by the header
// checks, precheckQcow2HeaderFile.)
func (h *heldConvert) qemuImgArgs(forceShare bool) ([]string, []*os.File) {
	fd := func(i int) string { return "/proc/self/fd/" + strconv.Itoa(3+i) }
	var src map[string]any
	for i := len(h.formats) - 1; i >= 0; i-- {
		layer := map[string]any{
			"driver": h.formats[i],
			"file":   map[string]any{"driver": "file", "filename": fd(i)},
		}
		if h.formats[i] == "qcow2" {
			if src != nil {
				layer["backing"] = src
			} else {
				layer["backing"] = nil
			}
		}
		src = layer
	}
	spec, err := json.Marshal(src)
	if err != nil {
		panic(err) // maps of strings: cannot fail
	}
	args := []string{"convert"}
	if forceShare {
		args = append(args, "-U")
	}
	args = append(args, "-p", "json:"+string(spec), "-O", "qcow2", fd(len(h.layers)))
	files := append(append([]*os.File{}, h.layers...), h.dst)
	return args, files
}

// assertStandalone is qcow2.AssertStandalone of what qemu-img wrote, read
// through the destination's descriptor.
func (h *heldConvert) assertStandalone() error {
	head := make([]byte, 4096)
	n, err := h.dst.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("read image header: %w", err)
	}
	return qcow2.AssertStandaloneHeader(head[:n])
}

// backingOpenHook runs in openBackings after a backing's name is resolved
// and judged, just before it is opened (tests: swap a directory on its path
// there).
var backingOpenHook func(resolved string)

// qemuImgRunHook runs after convertImageWith's checks and just before
// qemu-img starts (tests: swap a name it was judged by there).
var qemuImgRunHook func()

func runQemuImgRunHook() {
	if qemuImgRunHook != nil {
		qemuImgRunHook()
	}
}
