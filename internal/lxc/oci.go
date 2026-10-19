package lxc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// PullOCIOptions controls an OCI → LXC rootfs conversion.
type PullOCIOptions struct {
	// Image is the OCI reference, either a remote ("docker.io/library/alpine:3.19")
	// or a local OCI directory ("oci:/var/lib/litevirt/oci/alpine:3.19").
	Image string
	// Dest is the rootfs directory umoci will populate. Created if missing.
	Dest string
	// Tag overrides the default tag selection. Empty = use the image
	// reference's natural tag.
	Tag string
	// Username / Password authenticate the skopeo pull against a private
	// registry. Empty = anonymous. Passed to skopeo as --src-creds (an exec
	// arg, not a temp authfile, so there is nothing to leak on crash). Only
	// applied when the source is a remote (docker://) registry.
	Username string
	Password string
	// Replace lets the pull replace a bundle already at Dest; without it
	// such a pull fails with ErrOCIItemExists.
	Replace bool
	// CheckSource judges a local source: called with its transport and the
	// path of the object PullOCI opened (symlinks resolved), before
	// anything reads it. nil judges nothing (lv ct pull --local, as root).
	CheckSource func(transport, path string) error
	// Publish runs once the pulled image is in place at Dest, under the
	// item's locks, so what it records about the item (its owner) is
	// recorded with the content it describes: nothing that takes the lock
	// sees one without the other. Its error is the pull's.
	Publish func() error
}

// PullOCI extracts an OCI image's flattened rootfs to disk via umoci.
// Two binaries are required: skopeo (to copy the image into a local
// OCI layout) and umoci (to unpack it). The hosts ship both in their
// container-runtime package set.
//
// Conversion runs in two stages, through a layout of this pull's own in
// the item's staging directory, removed when the pull ends:
//
//  1. skopeo copy &lt;image&gt; oci:&lt;staged layout&gt;:&lt;tag&gt;
//  2. umoci unpack --image &lt;tmp&gt;:&lt;tag&gt; --rootless &lt;dest&gt;
//
// We choose --rootless so containers can run unprivileged when the
// host config supports user namespaces.
//
// Every pull writes a fresh image generation into the bundle
// (ImageGenFile), which a container created from it records, so a
// later change of the content behind the same path is seen as a new image.
//
// A Dest that already holds an unpacked bundle (IsBundle) is refused with
// ErrOCIItemExists unless opts.Replace is set, as umoci refused it before.
// With Replace the image is unpacked into a fresh directory beside Dest,
// which then takes Dest's place (replaceBundle); a pull that fails leaves
// the existing bundle as it was. The caller decides who may replace an item
// and that no container references it (RootfsReferences). The item's lock
// (LockOCIItem) is held throughout, so no create copies it half replaced.
func PullOCI(ctx context.Context, opts PullOCIOptions) (err error) {
	if opts.Image == "" {
		return errors.New("oci: image required")
	}
	if opts.Dest == "" {
		return errors.New("oci: dest required")
	}
	// One spelling of the item: "/x/web/" is "/x/web", whose lock and
	// staging live beside it, never inside the bundle.
	opts.Dest = filepath.Clean(opts.Dest)
	// The source as skopeo will read it: a registry image, or a local one
	// at the path the caller judged (ParseOCISource). Anything else is
	// refused before anything is touched.
	src, err := ParseOCISource(opts.Image)
	if err != nil {
		return err
	}
	// A local source is opened here, once, and skopeo reads it through that
	// descriptor (/proc/self/fd/3): what it reads is the object judged now,
	// whatever happens to the path afterwards.
	var srcFile *os.File
	if src.Local {
		if srcFile, err = openLocalSource(src, opts.CheckSource); err != nil {
			return err
		}
		defer srcFile.Close()
	}
	if err := requireBinary("skopeo"); err != nil {
		return err
	}
	if err := requireBinary("umoci"); err != nil {
		return err
	}
	// "+" is the separator of the staging names (unpackDirName): no item
	// may carry one, whatever path names it.
	if strings.Contains(filepath.Base(opts.Dest), "+") {
		return refused("oci: dest %q: an item name may not contain '+'", opts.Dest)
	}
	unlock := LockOCIItem(opts.Dest)
	defer unlock()
	release, err := lockItemFile(ctx, opts.Dest)
	if err != nil {
		return err
	}
	defer release()
	// A pull that fails leaves no trace of an item it was the first to make:
	// the directory it created, while still empty, and then (still holding
	// it) the item's lock file. Run before the lock is released.
	created := false
	defer func() {
		if err == nil {
			return
		}
		// A first pull never put anything at Dest (it unpacks beside it);
		// only its lock file is left to go.
		if _, serr := os.Lstat(opts.Dest); errors.Is(serr, os.ErrNotExist) {
			_ = os.Remove(filepath.Join(filepath.Dir(opts.Dest), unpackDirName, filepath.Base(opts.Dest)+lockSuffix))
		}
	}()
	if err := recoverItem(opts.Dest); err != nil {
		return fmt.Errorf("oci: finish an interrupted pull of %s first: %w", opts.Dest, err)
	}
	exists, err := IsBundle(opts.Dest)
	if err != nil {
		return err
	}
	if exists && !opts.Replace {
		return fmt.Errorf("%w: %s", ErrOCIItemExists, opts.Dest)
	}
	if exists {
		if h := OCIItemPinnedBy(opts.Dest); h != "" {
			return fmt.Errorf("%w: %s (into container %s); retry once it is done", ErrOCIItemPinned, opts.Dest, h)
		}
	}
	// Where umoci unpacks: a fresh directory beside the item, which then
	// takes its place (replaceBundle) or becomes it (a first pull, renamed
	// in only when it succeeded, so a failure leaves no partial item). A
	// An empty directory at Dest (an earlier build's failed first pull left
	// one) counts as no item: the rename replaces it. A non-empty directory
	// that holds no bundle (foreign) is unpacked into as before, and never
	// removed.
	_, serr := os.Lstat(opts.Dest)
	created = errors.Is(serr, os.ErrNotExist) || isEmptyDir(opts.Dest)
	bundle := opts.Dest
	if exists || created {
		if err := os.MkdirAll(filepath.Dir(opts.Dest), 0750); err != nil {
			return fmt.Errorf("mkdir dest parent: %w", err)
		}
		stage, err := stageUnpack(opts.Dest)
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(stage) }()
		bundle = stage
	}
	// The copy goes through a layout of this pull's own, in the staging
	// directory, removed when the pull ends: <dest>.oci, which earlier
	// builds used, is the operator's (it may be this pull's own local
	// source) and is never written or removed.
	tmpLayout, err := stageUnpack(opts.Dest)
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpLayout) }()
	tag := opts.Tag
	if tag == "" {
		// An oci: source's reference is a tag; an archive's selects an image
		// in it (an index, a repo:tag), which is no tag of the layout.
		tag = "latest"
		switch {
		case src.Transport == "oci" && src.Reference != "":
			tag = src.Reference
		case !src.Local:
			tag = parseOCITag(opts.Image)
		}
	}

	// Stage 1: skopeo into a local OCI directory layout. The "docker://"
	// prefix tells skopeo to fetch from a registry; "oci:" works for
	// local OCI dirs.
	srcRef, remote := src.Ref, !src.Local
	var passFD *os.File
	switch {
	case src.Transport == "oci" || src.Transport == "dir":
		// A directory is read through the descriptor (fd 3 in skopeo).
		srcRef, passFD = src.Transport+":/proc/self/fd/3", srcFile
	case src.Local:
		// containers/image resolves an archive's path to a name and opens
		// that name, so a descriptor path does not pin it: skopeo reads a
		// copy, made from the descriptor that was judged into this pull's
		// own staging directory (0700, root's).
		archStage, err := stageUnpack(opts.Dest)
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(archStage) }()
		fi, err := srcFile.Stat()
		if err != nil {
			return fmt.Errorf("oci: %s source: %w", src.Transport, err)
		}
		if err := checkStagingSpace(archStage, uint64(fi.Size()), src.Transport); err != nil {
			return err
		}
		copyPath := filepath.Join(archStage, "source.tar")
		if err := copyFromFile(ctx, srcFile, copyPath); err != nil {
			return fmt.Errorf("oci: copy the %s source: %w", src.Transport, err)
		}
		srcRef = src.Transport + ":" + copyPath
	}
	if src.Local && src.Reference != "" {
		srcRef += ":" + src.Reference
	}
	dstRef := fmt.Sprintf("oci:%s:%s", tmpLayout, tag)
	args := []string{"copy"}
	// Credentials only make sense for a remote registry source; a local
	// "oci:" layout has nothing to authenticate to. Args go through the exec
	// slice (not a shell), so a password with shell metacharacters is safe.
	if opts.Username != "" && remote {
		args = append(args, "--src-creds", opts.Username+":"+opts.Password)
	}
	// "--" ends the options: no reference is ever read as a flag.
	args = append(args, "--", srcRef, dstRef)
	copyCmd := dieWithDaemon(exec.CommandContext(ctx, "skopeo", args...))
	if passFD != nil {
		copyCmd.ExtraFiles = []*os.File{passFD} // fd 3 in skopeo
	}
	if out, err := combinedOutputPinned(copyCmd); err != nil {
		return fmt.Errorf("skopeo copy: %w: %s", err, out)
	}

	// Stage 2: umoci unpack flattens the layers into a usable rootfs.
	if out, err := combinedOutputPinned(dieWithDaemon(exec.CommandContext(ctx,
		"umoci", "unpack", "--rootless", "--image", fmt.Sprintf("%s:%s", tmpLayout, tag),
		bundle,
	))); err != nil {
		return fmt.Errorf("umoci unpack: %w: %s", err, out)
	}
	if err := writeImageGen(bundle); err != nil {
		return err
	}
	switch {
	case exists:
		if err := replaceBundle(bundle, opts.Dest); err != nil {
			return err
		}
	case created:
		if err := os.Chmod(bundle, 0o750); err != nil {
			return fmt.Errorf("oci: %w", err)
		}
		// rename(2) replaces an empty directory at Dest (os.Rename would
		// refuse any directory there) and fails if Dest is not empty.
		if err := syscall.Rename(bundle, opts.Dest); err != nil {
			return fmt.Errorf("oci: put the pulled image in place at %s: %w", opts.Dest, err)
		}
	}
	if opts.Publish != nil {
		if err := opts.Publish(); err != nil {
			return fmt.Errorf("oci: the image is in place at %s, but %w", opts.Dest, err)
		}
	}
	return nil
}

// combinedOutputPinned is cmd.CombinedOutput on a pinned thread (runPinned).
func combinedOutputPinned(cmd *exec.Cmd) (out []byte, err error) {
	err = runPinned(func() error {
		var e error
		out, e = cmd.CombinedOutput()
		return e
	})
	return out, err
}

// parseOCITag extracts the ":<tag>" portion of an image reference, or
// returns "latest" if absent. Handles registry-with-port edge cases.
//
//	"alpine"                            → "latest"
//	"alpine:3.19"                       → "3.19"
//	"docker.io/library/alpine:3.19"     → "3.19"
//	"registry.local:5000/team/img:v1"   → "v1"
//	"registry.local:5000/team/img"      → "latest"
func parseOCITag(ref string) string {
	// Strip any scheme prefix.
	if i := strings.Index(ref, "://"); i >= 0 {
		ref = ref[i+3:]
	}
	// Path-aware split: only count the LAST ':' if the segment after
	// it contains no '/' (otherwise it's the registry port).
	last := strings.LastIndex(ref, ":")
	if last < 0 {
		return "latest"
	}
	if strings.ContainsAny(ref[last:], "/") {
		return "latest"
	}
	return ref[last+1:]
}

// RegistryHost extracts the registry hostname from an IMAGE REFERENCE (the pull
// path), using the same scheme-strip + path-aware handling as parseOCITag.
// Returns "" for a local "oci:" layout (which has no registry, so no credential
// applies). Follows Docker's canonical disambiguation: the first path component
// is the registry iff it contains '.' or ':' or is "localhost"; otherwise the
// reference is a Docker Hub short name and the registry defaults to docker.io.
//
//	"alpine"                          → "docker.io"
//	"alpine:3.19"                     → "docker.io"
//	"library/alpine"                  → "docker.io"
//	"docker.io/library/alpine:3.19"   → "docker.io"
//	"ghcr.io/org/x"                   → "ghcr.io"
//	"docker://ghcr.io/org/x"          → "ghcr.io"
//	"registry:5000/team/img:v1"       → "registry:5000"
//	"localhost:5000/x"                → "localhost:5000"
//	"oci:/var/lib/litevirt/oci/x:1"   → ""
func RegistryHost(ref string) string {
	// A local source (any local transport) never authenticates, and a
	// refused one has no registry.
	if src, err := ParseOCISource(ref); err != nil || src.Local {
		return ""
	}
	// Strip any scheme prefix (e.g. "docker://").
	if i := strings.Index(ref, "://"); i >= 0 {
		ref = ref[i+3:]
	}
	first := ref
	if i := strings.Index(ref, "/"); i >= 0 {
		first = ref[:i]
	} else {
		// No '/': a bare "name" or "name:tag" — always Docker Hub.
		return "docker.io"
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return canonicalRegistry(first)
	}
	return "docker.io"
}

// NormalizeRegistry canonicalizes a REGISTRY HOST argument — what a user passes
// to `lv registry add <registry>` or stores a credential against — as opposed
// to a full image reference (use RegistryHost for that). It strips any scheme
// and trailing path so a full reference's host can be recovered, and folds the
// Docker Hub aliases onto "docker.io" so a credential stored here matches what
// RegistryHost derives from a pulled image.
//
//	"ghcr.io"                         → "ghcr.io"
//	"docker.io"                       → "docker.io"
//	"index.docker.io"                 → "docker.io"
//	"registry:5000"                   → "registry:5000"
//	"https://ghcr.io"                 → "ghcr.io"
//	"docker.io/library/alpine"        → "docker.io"
//	"oci:/var/lib/.../x:1"            → ""
func NormalizeRegistry(reg string) string {
	if strings.HasPrefix(reg, "oci:") {
		return ""
	}
	if i := strings.Index(reg, "://"); i >= 0 {
		reg = reg[i+3:]
	}
	if i := strings.Index(reg, "/"); i >= 0 {
		reg = reg[:i]
	}
	return canonicalRegistry(strings.TrimSpace(reg))
}

// canonicalRegistry folds the several Docker Hub hostnames onto the single
// canonical "docker.io" so credentials and pulls agree on one key.
func canonicalRegistry(host string) string {
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	}
	return host
}

// requireBinary errors if the named binary is not on PATH. Useful so
// PullOCI fails fast instead of mid-download.
func requireBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required binary %q not found in PATH", name)
	}
	return nil
}

// RootfsPath returns the canonical rootfs location for a container
// stored under <lxcpath>/<name>/rootfs. Used by callers that pull an
// OCI image first and then hand the path to Create() as a Template.
func RootfsPath(lxcpath, name string) string {
	if lxcpath == "" {
		lxcpath = "/var/lib/lxc"
	}
	return filepath.Join(lxcpath, name, "rootfs")
}

// OCISource is a pull's source reference, read the way skopeo reads it
// (ParseOCISource).
type OCISource struct {
	// Transport is "docker" (a registry), or one of the local transports
	// "oci", "dir", "oci-archive" and "docker-archive".
	Transport string
	// Path is a local transport's directory (oci, dir) or archive file
	// (oci-archive, docker-archive), absolute and cleaned; "" for docker.
	Path string
	// Reference is what follows the path of an oci or archive source
	// (its tag or index), "" when none.
	Reference string
	// Local is true for every transport that reads this host.
	Local bool
	// Ref is the reference to hand skopeo: a registry image with docker://,
	// a local one rebuilt from Transport, Path and Reference, so skopeo
	// reads exactly the path that was judged.
	Ref string
}

// localTransports are the transports a pull may read from this host;
// refusedTransports the other skopeo transports, which it never uses.
var (
	localTransports   = map[string]bool{"oci": true, "dir": true, "oci-archive": true, "docker-archive": true}
	refusedTransports = map[string]bool{"docker-daemon": true, "containers-storage": true, "ostree": true, "sif": true, "tarball": true, "atomic": true}
)

// errOCISourceForms names the sources a pull accepts.
const errOCISourceForms = `a registry image ("name[:tag]" or "docker://registry/name[:tag]"), or a local ` +
	`"oci:<dir>[:tag]", "dir:<dir>", "oci-archive:<file>[:tag]" or "docker-archive:<file>[:ref]"`

// ParseOCISource reads ref as skopeo does: the transport is the name before
// the first ":", when that is a transport's name, and a local transport's
// path ends at the next ":" (dir: has no reference, so its whole remainder
// is the path). A reference with no transport name is a registry image.
// Transports other than docker and the local ones, a relative path, and a
// reference starting with "-" are refused.
func ParseOCISource(ref string) (OCISource, error) {
	if ref == "" {
		return OCISource{}, errors.New("oci: image required")
	}
	if strings.HasPrefix(ref, "-") {
		return OCISource{}, refused("oci: image %q: want %s", ref, errOCISourceForms)
	}
	name, rest, ok := strings.Cut(ref, ":")
	switch {
	case !ok:
		return OCISource{Transport: "docker", Ref: "docker://" + ref}, nil
	case name == "docker" && strings.HasPrefix(rest, "//"):
		if len(rest) == 2 {
			return OCISource{}, refused("oci: image %q: want %s", ref, errOCISourceForms)
		}
		return OCISource{Transport: "docker", Ref: ref}, nil
	case localTransports[name]:
		p, reference := rest, ""
		if name != "dir" {
			p, reference, _ = strings.Cut(rest, ":")
		}
		if !strings.HasPrefix(p, "/") {
			return OCISource{}, refused("oci: image %q: a local source needs an absolute path; want %s", ref, errOCISourceForms)
		}
		p = filepath.Clean(p)
		out := name + ":" + p
		if reference != "" {
			out += ":" + reference
		}
		return OCISource{Transport: name, Path: p, Reference: reference, Local: true, Ref: out}, nil
	case refusedTransports[name]:
		return OCISource{}, refused("oci: image %q: transport %q is not one a pull reads; want %s", ref, name, errOCISourceForms)
	default:
		// "name:tag", "registry:5000/name": a registry image.
		return OCISource{Transport: "docker", Ref: "docker://" + ref}, nil
	}
}

// openLocalSource opens a local source's path as a reference only, without
// following a link at its own name (openNoFollow: no device driver's open
// runs, and a FIFO cannot block), refuses anything but a directory (oci:,
// dir:) or a regular file (the archives), judges the object at the path it
// really is (check, when set; a path that cannot be read back is refused),
// and only then opens that same object for reading.
func openLocalSource(src OCISource, check func(transport, path string) error) (*os.File, error) {
	wantDir := src.Transport == "oci" || src.Transport == "dir"
	ref, err := openSourceRef(src.Path, wantDir)
	if err != nil {
		switch {
		case errors.Is(err, syscall.ELOOP):
			return nil, refused("oci: %s source %q is a symbolic link; name what it points to", src.Transport, src.Path)
		case errors.Is(err, syscall.ENOTDIR):
			return nil, refused("oci: %s source %q is not a directory", src.Transport, src.Path)
		case errors.Is(err, os.ErrNotExist), errors.Is(err, os.ErrPermission):
			return nil, refused("oci: %s source: %w", src.Transport, err)
		}
		// The host could not open what was named (an I/O error, no
		// memory): a failure, not a refusal of the request.
		return nil, fmt.Errorf("oci: %s source: %w", src.Transport, err)
	}
	defer ref.Close()
	fi, err := ref.Stat()
	if err != nil {
		return nil, fmt.Errorf("oci: %s source: %w", src.Transport, err)
	}
	switch {
	case wantDir && !fi.IsDir():
		return nil, refused("oci: %s source %q is not a directory", src.Transport, src.Path)
	case !wantDir && !fi.Mode().IsRegular():
		return nil, refused("oci: %s source %q is not a regular file", src.Transport, src.Path)
	}
	judged, err := openedFilePath(ref)
	if err != nil {
		return nil, refused("oci: %s source: %w", src.Transport, err)
	}
	if check != nil {
		if err := check(src.Transport, judged); err != nil {
			return nil, err
		}
	}
	f, err := reopenRead(ref, wantDir)
	if err != nil {
		return nil, fmt.Errorf("oci: %s source: %w", src.Transport, err)
	}
	return f, nil
}

// copyFromFile copies what src reads into a new file at dst (0600), honouring
// ctx between chunks.
func copyFromFile(ctx context.Context, src *os.File, dst string) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for {
		if err := ctx.Err(); err != nil {
			_ = out.Close()
			return err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				_ = out.Close()
				return werr
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			_ = out.Close()
			return rerr
		}
	}
	return out.Close()
}

// stagingSpace reports a directory's filesystem free space (for an
// unprivileged writer, as root keeps its own reserve) and size; a test
// replaces it.
var stagingSpace = stagingStatfs

// spareReserve is what a copy into the staging directory must leave free on
// its filesystem, which the data directory, and state.db, share: a tenth of
// it, at most 4 GiB.
func spareReserve(total uint64) uint64 { return min(total/10, 4<<30) }

// checkStagingSpace refuses a copy of size bytes into dir, an item's
// staging entry (<parent>/.litevirt+unpack/<entry>), when it would leave less
// than spareReserve free on the filesystem holding the item's parent (the
// data directory's, for a library pull).
func checkStagingSpace(dir string, size uint64, what string) error {
	holder := filepath.Dir(filepath.Dir(dir))
	avail, total, err := stagingSpace(dir)
	if err != nil {
		return fmt.Errorf("oci: cannot tell the free space for the %s copy in %s: %w", what, dir, err)
	}
	if reserve := spareReserve(total); size+reserve > avail {
		return spaceRefused("oci: the %s source needs %d bytes copied into %s, and %d bytes are free there; "+
			"%d must stay free on the filesystem holding %s, so it was not pulled", what, size, dir, avail, reserve, holder)
	}
	return nil
}

// openSourceRef is openNoFollow; a test replaces it.
var openSourceRef = openNoFollow

// isEmptyDir reports whether p is a directory with nothing in it (not a
// link to one).
func isEmptyDir(p string) bool {
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() {
		return false
	}
	ents, err := os.ReadDir(p)
	return err == nil && len(ents) == 0
}
