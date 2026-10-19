package lxc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
}

// PullOCI extracts an OCI image's flattened rootfs to disk via umoci.
// Two binaries are required: skopeo (to copy the image into a local
// OCI layout) and umoci (to unpack it). The hosts ship both in their
// container-runtime package set.
//
// Conversion runs in two stages so we can resume a failed unpack
// without re-downloading the layers:
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
func PullOCI(ctx context.Context, opts PullOCIOptions) error {
	if opts.Image == "" {
		return errors.New("oci: image required")
	}
	if opts.Dest == "" {
		return errors.New("oci: dest required")
	}
	// One spelling of the item: "/x/web/" is "/x/web", whose lock and
	// staging live beside it, never inside the bundle.
	opts.Dest = filepath.Clean(opts.Dest)
	if err := requireBinary("skopeo"); err != nil {
		return err
	}
	if err := requireBinary("umoci"); err != nil {
		return err
	}
	// "+" is the separator of the staging names (unpackDirName): no item
	// may carry one, whatever path names it.
	if strings.Contains(filepath.Base(opts.Dest), "+") {
		return fmt.Errorf("oci: dest %q: an item name may not contain '+'", opts.Dest)
	}
	unlock := LockOCIItem(opts.Dest)
	defer unlock()
	release, err := lockItemFile(ctx, opts.Dest)
	if err != nil {
		return err
	}
	defer release()
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
	if err := os.MkdirAll(opts.Dest, 0750); err != nil {
		return fmt.Errorf("mkdir dest: %w", err)
	}
	// Where umoci unpacks: Dest itself when it holds no bundle yet (new, or
	// an empty or foreign directory umoci unpacks into as before), else a
	// fresh directory beside it that then replaces it.
	bundle := opts.Dest
	if exists {
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
		tag = parseOCITag(opts.Image)
	}

	// Stage 1: skopeo into a local OCI directory layout. The "docker://"
	// prefix tells skopeo to fetch from a registry; "oci:" works for
	// local OCI dirs.
	// A local "oci:<dir>[:tag]" source is read from that directory as is
	// (the caller has judged the directory); anything else without a
	// transport is a registry reference.
	srcRef := opts.Image
	remote := false
	switch {
	case strings.HasPrefix(srcRef, "oci:"):
	case strings.Contains(srcRef, "://"):
		remote = strings.HasPrefix(srcRef, "docker://")
	default:
		srcRef, remote = "docker://"+srcRef, true
	}
	dstRef := fmt.Sprintf("oci:%s:%s", tmpLayout, tag)
	args := []string{"copy"}
	// Credentials only make sense for a remote registry source; a local
	// "oci:" layout has nothing to authenticate to. Args go through the exec
	// slice (not a shell), so a password with shell metacharacters is safe.
	if opts.Username != "" && remote {
		args = append(args, "--src-creds", opts.Username+":"+opts.Password)
	}
	args = append(args, srcRef, dstRef)
	if out, err := combinedOutputPinned(dieWithDaemon(exec.CommandContext(ctx, "skopeo", args...))); err != nil {
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
	if exists {
		return replaceBundle(bundle, opts.Dest)
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
	// A local OCI layout reference ("oci:/path:tag") never authenticates.
	if strings.HasPrefix(ref, "oci:") {
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
