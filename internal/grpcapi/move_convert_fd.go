package grpcapi

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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
// very gap closed here, so every backing is named explicitly in
// --image-opts (backing.driver, backing.file.filename=/proc/self/fd/M, and so
// on down the chain): qemu-img then opens no file by any name the header
// holds. Which file each descriptor is was judged here: its backing name,
// read from the open file above it and resolved as precheckChain resolves
// it, must be exactly the backing precheckChain accepted.
type heldConvert struct {
	layers  []*os.File
	formats []string
	dst     *os.File
}

func (h *heldConvert) close() {
	for _, f := range h.layers {
		f.Close()
	}
	if h.dst != nil {
		h.dst.Close()
	}
}

// openConvertTop opens the source's top layer and the destination before
// anything judges them by name: the source no-follow and regular; the
// destination, a file the caller made, no-follow and regular, or made here
// (O_EXCL, owner-only) when it is not there yet.
func openConvertTop(src, srcFormat, dst string) (*heldConvert, error) {
	top, _, err := openRegularNoFollow(src)
	if err != nil {
		return nil, fmt.Errorf("source %s: %w", src, err)
	}
	h := &heldConvert{layers: []*os.File{top}, formats: []string{srcFormat}}
	out, err := os.OpenFile(dst, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		out, err = os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, diskmode.File)
	}
	if err != nil {
		h.close()
		return nil, fmt.Errorf("destination %s: %w", dst, err)
	}
	h.dst = out
	if fi, err := out.Stat(); err != nil || !fi.Mode().IsRegular() {
		h.close()
		return nil, fmt.Errorf("destination %s is not a regular file", dst)
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
// takes as ExtraFiles (the child's fd 3 onwards, in that order).
func (h *heldConvert) qemuImgArgs(forceShare bool) ([]string, []*os.File) {
	fd := func(i int) string { return "/proc/self/fd/" + strconv.Itoa(3+i) }
	var opts []string
	prefix := ""
	for i, f := range h.formats {
		opts = append(opts,
			prefix+"driver="+f,
			prefix+"file.driver=file",
			prefix+"file.filename="+fd(i))
		prefix += "backing."
	}
	args := []string{"convert"}
	if forceShare {
		args = append(args, "-U")
	}
	args = append(args, "-p", "--image-opts", strings.Join(opts, ","), "-O", "qcow2", fd(len(h.layers)))
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
