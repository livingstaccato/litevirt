package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/randid"
)

// cephDriver provisions Ceph RBD images via the rbd CLI. We deliberately
// shell out instead of vendoring go-ceph (CGO) so the default litevirtd
// binary stays CGO-free; a separate -tags ceph build will replace this
// with native bindings if needed.
type cephDriver struct {
	pool string
	opts map[string]string // keyring, conf, id, mon_host, …
	run  cmdRunner         // nil → cephRunner; overridable in tests
	// scratch is the directory an image is converted to raw in before it is
	// imported ("" → the system temp dir). The daemon's data dir, not /tmp,
	// which is often a small tmpfs.
	scratch string
}

// cephRunner is what a driver with no runner of its own runs commands with.
var cephRunner cmdRunner = realCmd

// OverrideCephRunnerForTest replaces how ceph drivers built by New run rbd and
// qemu-img, for tests in other packages; it returns the restore.
func OverrideCephRunnerForTest(run func(ctx context.Context, name string, args ...string) ([]byte, error)) func() {
	prev := cephRunner
	cephRunner = run
	return func() { cephRunner = prev }
}

func (d *cephDriver) String() string { return "ceph" }

func (d *cephDriver) runner() cmdRunner {
	if d.run != nil {
		return d.run
	}
	return cephRunner
}

// rbd runs an rbd subcommand through the driver's runner (real exec by default).
func (d *cephDriver) rbd(ctx context.Context, args ...string) ([]byte, error) {
	return d.runner()(ctx, "rbd", args...)
}

func (d *cephDriver) Prepare(ctx context.Context) error {
	if out, err := d.rbd(ctx, d.rbdArgs("ls", "--", d.pool)...); err != nil {
		return fmt.Errorf("ceph pool %q not accessible: %w: %s", d.pool, err, out)
	}
	return nil
}

// Base images. A root disk built on an image is a copy-on-write clone of that
// image imported once into the pool — as Proxmox does with templates on rbd:
// the image is converted to raw, imported as lvimage+<name>+<digest>, given a
// protected snapshot, and every VM's root disk is an `rbd clone` of that
// snapshot. The name carries the image content's digest, so a refreshed image
// is a new base and the clones of the old one keep theirs.
//
// "+" is not in the VM, disk or image name charset (safename), so no VM disk
// ("<vm>-<disk>") can ever be named like a base, and DeleteDisk can refuse to
// remove one by its name alone.
const (
	cephBasePrefix = "lvimage+"
	cephBaseSnap   = "base"
)

// cephBaseLocks serializes, per base, the imports this host runs; across hosts
// the import's private name and the rename into place decide.
var cephBaseLocks sync.Map // base spec → *sync.Mutex

// CephBaseImageName is the rbd image an image's content is imported as.
func CephBaseImageName(image, digest string) string {
	if len(digest) > 16 {
		digest = digest[:16]
	}
	return cephBasePrefix + image + "+" + digest
}

// IsCephBaseImage reports whether an rbd image name is an imported base.
func IsCephBaseImage(name string) bool { return strings.HasPrefix(name, cephBasePrefix) }

func (d *cephDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	imageName := fmt.Sprintf("%s-%s", opts.VMName, opts.DiskName)
	sizeMiB := opts.SizeBytes / (1024 * 1024)
	if sizeMiB == 0 {
		sizeMiB = 1024
	}

	// The locator — the identity and monitors the domain will name — is built
	// before anything is allocated: a pool whose conf names no monitors, or
	// whose paths cannot be carried in a locator, fails here and leaves no
	// image behind.
	path, err := d.diskLocator(imageName)
	if err != nil {
		return "", err
	}
	dest := fmt.Sprintf("%s/%s", d.pool, imageName)

	// Clone and create are ALTERNATIVES, not a sequence. `rbd clone` allocates
	// the destination itself and refuses one that already exists, so creating
	// the image first made every image-backed VM creation on ceph fail with
	// "(17) File exists" — and then roll the image back, leaving no trace of
	// why. The local and nfs drivers branch the same way.
	switch {
	case opts.SourceImage == "":
		args := d.rbdArgs("create",
			"--size", fmt.Sprintf("%d", sizeMiB),
			"--image-feature", "layering",
			"--", dest,
		)
		if out, err := d.rbd(ctx, args...); err != nil {
			return "", fmt.Errorf("rbd create %s: %w: %s", imageName, err, out)
		}
	case filepath.IsAbs(opts.SourceImage):
		// An image store file: imported once per content per pool, then cloned.
		base, err := d.ensureBase(ctx, opts)
		if err != nil {
			return "", err
		}
		if err := d.cloneFromImage(ctx, base, imageName); err != nil {
			return "", fmt.Errorf("ceph clone %s from %s: %w", imageName, base, err)
		}
		// A clone is the size of its base; a bigger disk asked for is grown
		// (never shrunk). The clone is this call's own: a failure removes it.
		if opts.SizeBytes > 0 {
			if err := d.growTo(ctx, dest, opts.SizeBytes); err != nil {
				if out, rerr := d.rbd(ctx, d.rbdArgs("rm", "--", dest)...); rerr != nil {
					slog.Warn("ceph: could not remove a clone whose resize failed", "image", dest, "error", rerr, "output", strings.TrimSpace(string(out)))
				}
				return "", err
			}
		}
	case strings.Contains(opts.SourceImage, "@"):
		// A named protected snapshot (pool/image@snap).
		if err := d.cloneFromImage(ctx, opts.SourceImage, imageName); err != nil {
			// Nothing was allocated before the clone, so there is nothing to roll
			// back: a failed clone leaves no image behind.
			return "", fmt.Errorf("ceph clone %s from %s: %w", imageName, opts.SourceImage, err)
		}
	default:
		// rbd can only clone a SNAPSHOT. Refuse a bare image name before
		// allocating anything rather than let rbd fail with a message that
		// reads like a permissions problem.
		return "", fmt.Errorf(
			"%w: ceph clone source must be an image store file or name a protected snapshot (pool/image@snap), got %q",
			ErrUnimplemented, opts.SourceImage)
	}

	slog.Info("Ceph RBD disk created", "image", imageName, "pool", d.pool)
	return path, nil
}

// diskLocator is the identifier a disk on this pool is recorded and attached
// by: "rbd:<pool>/<image>", then the client identity its domain authenticates
// as (id, keyring), the pool's conf, and the monitors (mon_host) — the pool's
// own mon_host option, or the ones its conf names. libvirt's
// <disk type='network'> carries the monitors as <host> elements and the
// identity as <auth> naming the pool's ceph secret (libvirt.CephSecretUUID);
// see internal/libvirt/disk_backing.go.
func (d *cephDriver) diskLocator(imageName string) (string, error) {
	path := fmt.Sprintf("rbd:%s/%s", d.pool, imageName)
	for _, k := range []string{"conf", "keyring"} {
		if v := d.opts[k]; strings.ContainsAny(v, ":\\") {
			return "", fmt.Errorf("ceph %s %q cannot be carried in a disk locator (it contains ':' or '\\')", k, v)
		}
	}
	if auth, ok := CephAuthOf(d.opts); ok {
		path += ":id=" + auth.ID + ":keyring=" + auth.Keyring
	}
	conf := d.opts["conf"]
	if conf != "" {
		path += ":conf=" + conf
	}
	var mons []string
	if mh := strings.TrimSpace(d.opts["mon_host"]); mh != "" {
		mons = ParseMonHost(mh)
	} else if conf != "" {
		m, err := CephMonHosts(conf)
		if err != nil {
			return "", fmt.Errorf("ceph pool %q: %w", d.pool, err)
		}
		if len(m) == 0 && filepath.Clean(conf) != DefaultCephConf() {
			// qemu reads only the default conf by itself; the monitors of any
			// other have to be in the domain.
			return "", fmt.Errorf("ceph conf %s names no mon_host, so a VM disk cannot find the cluster; set mon_host there or as a pool option", conf)
		}
		mons = m
	}
	if len(mons) > 0 {
		esc := make([]string, len(mons))
		for i, m := range mons {
			esc[i] = strings.ReplaceAll(m, ":", `\:`)
		}
		path += ":mon_host=" + strings.Join(esc, `\;`)
	}
	return path, nil
}

// ensureBase returns the protected snapshot of opts.SourceImage's content in
// this pool, importing it first if it is not there.
func (d *cephDriver) ensureBase(ctx context.Context, opts DiskOptions) (string, error) {
	name := opts.SourceImageName
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(opts.SourceImage), filepath.Ext(opts.SourceImage))
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
	}
	digest := opts.SourceImageDigest
	if digest == "" {
		var err error
		if digest, err = fileSHA256(opts.SourceImage); err != nil {
			return "", fmt.Errorf("ceph base image: hash %s: %w", opts.SourceImage, err)
		}
	}
	baseName := CephBaseImageName(name, digest)
	baseRef := d.pool + "/" + baseName
	spec := baseRef + "@" + cephBaseSnap

	mu, _ := cephBaseLocks.LoadOrStore(spec, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()

	if _, err := d.rbd(ctx, d.rbdArgs("info", "--", spec)...); err == nil {
		return spec, nil
	}

	tmpDir, err := os.MkdirTemp(d.scratch, ".litevirt-rbd-import-")
	if err != nil {
		return "", fmt.Errorf("ceph base image: scratch dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	raw := filepath.Join(tmpDir, "image.raw")
	// The format is stated, never probed: a store image is qcow2.
	if out, err := d.runner()(ctx, "qemu-img", "convert", "-f", "qcow2", "-O", "raw", opts.SourceImage, raw); err != nil {
		return "", fmt.Errorf("ceph base image: convert %s to raw: %w: %s", opts.SourceImage, err, out)
	}

	// Imported under a private name, snapshotted and protected, and only then
	// renamed into place: a base that exists is always complete, and a crash
	// leaves only a name sweepIncoming removes.
	d.sweepIncoming(ctx, baseRef, time.Now())
	incoming := fmt.Sprintf("%s%s%d-%s", baseRef, incomingMarker, time.Now().Unix(), randid.New()[:12])
	removeIncoming := func(protected bool) {
		if protected {
			_, _ = d.rbd(ctx, d.rbdArgs("snap", "unprotect", "--", incoming+"@"+cephBaseSnap)...)
		}
		_, _ = d.rbd(ctx, d.rbdArgs("snap", "rm", "--", incoming+"@"+cephBaseSnap)...)
		_, _ = d.rbd(ctx, d.rbdArgs("rm", "--", incoming)...)
	}
	if out, err := d.rbd(ctx, d.rbdArgs("import", "--image-feature", "layering", "--", raw, incoming)...); err != nil {
		removeIncoming(false)
		return "", fmt.Errorf("ceph base image: rbd import: %w: %s", err, out)
	}
	if out, err := d.rbd(ctx, d.rbdArgs("snap", "create", "--", incoming+"@"+cephBaseSnap)...); err != nil {
		removeIncoming(false)
		return "", fmt.Errorf("ceph base image: rbd snap create: %w: %s", err, out)
	}
	if out, err := d.rbd(ctx, d.rbdArgs("snap", "protect", "--", incoming+"@"+cephBaseSnap)...); err != nil {
		removeIncoming(false)
		return "", fmt.Errorf("ceph base image: rbd snap protect: %w: %s", err, out)
	}
	if out, err := d.rbd(ctx, d.rbdArgs("rename", "--", incoming, baseRef)...); err != nil {
		removeIncoming(true)
		// Another host imported the same content first: use its base.
		if _, ierr := d.rbd(ctx, d.rbdArgs("info", "--", spec)...); ierr == nil {
			return spec, nil
		}
		return "", fmt.Errorf("ceph base image: rbd rename into place: %w: %s", err, out)
	}
	slog.Info("ceph: image imported as a base", "image", name, "base", spec)
	return spec, nil
}

// growTo grows an image to sizeBytes (whole MiB, rounded up) when it is smaller.
func (d *cephDriver) growTo(ctx context.Context, ref string, sizeBytes int64) error {
	out, err := d.rbd(ctx, d.rbdArgs("info", "--format", "json", "--", ref)...)
	if err != nil {
		return fmt.Errorf("rbd info %s: %w: %s", ref, err, out)
	}
	var info struct {
		Size int64 `json:"size"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return fmt.Errorf("rbd info %s: %w", ref, err)
	}
	if sizeBytes <= info.Size {
		return nil
	}
	mib := (sizeBytes + (1<<20 - 1)) >> 20
	if out, err := d.rbd(ctx, d.rbdArgs("resize", "--size", strconv.FormatInt(mib, 10), "--", ref)...); err != nil {
		return fmt.Errorf("rbd resize %s: %w: %s", ref, err, out)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// rbdSpecOf splits a disk locator into its image spec ("pool[/ns]/image"),
// the pool part and the image name.
func rbdSpecOf(path string) (spec, pool, image string, ok bool) {
	body, isRBD := strings.CutPrefix(path, "rbd:")
	if !isRBD {
		return "", "", "", false
	}
	spec, _, _ = strings.Cut(body, ":")
	i := strings.LastIndexByte(spec, '/')
	if i <= 0 || i == len(spec)-1 {
		return "", "", "", false
	}
	return spec, spec[:i], spec[i+1:], true
}

// DeleteDisk removes the disk's own rbd image, and nothing else: never an
// image outside this pool, never an imported base (other VMs' disks are its
// clones), and never one with snapshots (rbd refuses that itself, so a clone
// made from one of its snapshots is not orphaned). A disk already gone is not
// an error.
func (d *cephDriver) DeleteDisk(ctx context.Context, path string) error {
	spec, pool, imageName, ok := rbdSpecOf(path)
	if !ok {
		return fmt.Errorf("cannot parse Ceph image name from %q", path)
	}
	if d.pool != "" && pool != d.pool {
		return fmt.Errorf("ceph disk %q is not in pool %q; not removing it", path, d.pool)
	}
	if IsCephBaseImage(imageName) {
		return fmt.Errorf("ceph image %q is an imported base other disks are cloned from; not removing it", spec)
	}
	out, err := d.rbd(ctx, d.rbdArgs("rm", "--", spec)...)
	if err != nil {
		if rbdNotFound(out) {
			return nil
		}
		return fmt.Errorf("rbd rm %s: %w: %s", imageName, err, out)
	}
	return nil
}

// rbdNotFound reports whether rbd's output says the image does not exist.
func rbdNotFound(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "No such file or directory") || strings.Contains(s, "(2)")
}

func (d *cephDriver) cloneFromImage(ctx context.Context, sourceImage, destImage string) error {
	args := d.rbdArgs("clone", "--", sourceImage, fmt.Sprintf("%s/%s", d.pool, destImage))
	out, err := d.rbd(ctx, args...)
	if err != nil {
		return fmt.Errorf("rbd clone: %w: %s", err, out)
	}
	return nil
}

// CloneDisk copies a VM's disk on this pool into a new image for another VM
// (opts.VMName, opts.DiskName) with `rbd deep cp`: the copy is the clone's
// own, independent of its source (a root disk's copy stays a clone of the
// same imported base, which deep cp preserves), and nothing is copied
// through the host. It returns the copy's locator.
func (d *cephDriver) CloneDisk(ctx context.Context, srcPath string, opts DiskOptions) (string, error) {
	srcSpec, _, _, ok := rbdSpecOf(srcPath)
	if !ok {
		return "", fmt.Errorf("ceph clone source %q is not an rbd disk", srcPath)
	}
	imageName := fmt.Sprintf("%s-%s", opts.VMName, opts.DiskName)
	path, err := d.diskLocator(imageName)
	if err != nil {
		return "", err
	}
	dest := d.pool + "/" + imageName
	if out, err := d.rbd(ctx, d.rbdArgs("deep", "cp", "--", srcSpec, dest)...); err != nil {
		// deep cp creates the destination; one that failed part-way is this
		// call's own, and is removed. One that already existed (File exists)
		// is someone else's and is left alone.
		if !strings.Contains(string(out), "File exists") && !strings.Contains(string(out), "(17)") {
			_, _ = d.rbd(ctx, d.rbdArgs("rm", "--", dest)...)
		}
		return "", fmt.Errorf("rbd deep cp %s → %s: %w: %s", srcSpec, dest, err, out)
	}
	slog.Info("Ceph RBD disk cloned", "src", srcSpec, "dest", dest)
	return path, nil
}

// DiskCloner is a driver that copies a disk inside its own backend.
type DiskCloner interface {
	CloneDisk(ctx context.Context, srcPath string, opts DiskOptions) (string, error)
}

// AsDiskCloner returns d's backend-side copy, or nil when it has none.
func AsDiskCloner(d Driver) DiskCloner {
	c, _ := d.(DiskCloner)
	return c
}

// rbdArgs prepends authentication options to rbd command args.
func (d *cephDriver) rbdArgs(subArgs ...string) []string {
	args := []string{}
	if id := d.opts["id"]; id != "" {
		args = append(args, "--id", id)
	}
	if conf := d.opts["conf"]; conf != "" {
		args = append(args, "--conf", conf)
	}
	if keyring := d.opts["keyring"]; keyring != "" {
		args = append(args, "--keyring", keyring)
	}
	return append(args, subArgs...)
}

// Replicate implements native Ceph send/recv via
// `rbd export-diff | rbd import-diff`. SrcRef is "<pool>/<image>"
// (or "<pool>/<image>@<snap>"); DstRef is "<pool>/<image>" on the
// destination cluster. Cross-cluster replication uses SSHTarget,
// matching ZFS.
func (d *cephDriver) Replicate(ctx context.Context, opts ReplicateOptions) (err error) {
	if opts.SrcRef == "" || opts.DstRef == "" {
		return fmt.Errorf("ceph replicate: src and dst refs required")
	}
	// The source side runs as the source pool's cluster and identity, the
	// destination side as the destination's: never one cluster's
	// credentials against the other's names.
	src := d
	if opts.SrcOptions != nil {
		src = &cephDriver{opts: opts.SrcOptions, run: d.run}
	}
	snap := opts.SnapshotName
	if snap == "" {
		snap = "litevirt-" + nowSnapTag()
	}
	srcSnapSpec := opts.SrcRef + "@" + snap

	// A full copy is export | import, and import CREATES the destination,
	// refusing one that exists; it is checked first too, before anything is
	// sent or snapshotted. An incremental (export-diff | import-diff) applies
	// onto an existing image, so it is only ever run against one this
	// replication created earlier — the caller's choice, never a full copy's.
	if !opts.Incremental {
		if _, ierr := d.rbd(ctx, d.rbdArgs("info", "--", opts.DstRef)...); ierr == nil {
			return fmt.Errorf("ceph replicate → %s: %w", opts.DstRef, ErrDestinationExists)
		}
	}
	if out, serr := src.rbd(ctx, src.rbdArgs("snap", "create", "--", srcSnapSpec)...); serr != nil {
		return fmt.Errorf("rbd snap create %s: %w: %s", srcSnapSpec, serr, out)
	}
	// The per-call snapshot is the copy's point in time only: always removed.
	defer func() {
		if out, rerr := src.rbd(ctx, src.rbdArgs("snap", "rm", "--", srcSnapSpec)...); rerr != nil && err == nil {
			err = fmt.Errorf("rbd snap rm %s: %w: %s", srcSnapSpec, rerr, out)
		}
	}()

	// A full copy is imported under a fresh name of its own, recorded, and
	// only then renamed to DstRef (rbd rename refuses an existing name). Every
	// cleanup removes only that fresh image — one this call created — never
	// DstRef: an import that failed because an image of that name appeared in
	// between (created by someone else) must not delete it.
	recvRef := opts.DstRef
	if !opts.Incremental {
		d.sweepIncoming(ctx, opts.DstRef, time.Now())
		recvRef = fmt.Sprintf("%s%s%d-%s", opts.DstRef, incomingMarker, time.Now().Unix(), randid.New()[:12])
	}
	var sendArgs, recvArgs []string
	if opts.Incremental {
		sendArgs = src.rbdArgs("export-diff", "--from-snap", "litevirt-replicate-prev", "--", srcSnapSpec, "-")
		recvArgs = d.rbdArgs("import-diff", "--", "-", recvRef)
	} else {
		sendArgs = src.rbdArgs("export", "--", srcSnapSpec, "-")
		recvArgs = d.rbdArgs("import", "--", "-", recvRef)
	}
	removeIncoming := func() {
		if !opts.Incremental {
			_, _ = d.rbd(ctx, d.rbdArgs("rm", "--", recvRef)...)
		}
	}

	if _, perr := pipeCmds(ctx, opts.SSHTarget, "rbd", sendArgs, "rbd", recvArgs); perr != nil {
		removeIncoming() // a partial image this copy created is not left unrecorded
		return fmt.Errorf("ceph replicate %s → %s: %w", opts.SrcRef, opts.DstRef, perr)
	}
	for _, k := range sortedKeys(opts.Record) {
		if out, merr := d.rbd(ctx, d.rbdArgs("image-meta", "set", "--", recvRef, "litevirt."+k, opts.Record[k])...); merr != nil {
			removeIncoming()
			return fmt.Errorf("ceph replicate → %s: record %s: %w: %s", opts.DstRef, k, merr, out)
		}
	}
	if !opts.Incremental {
		if out, rerr := d.rbd(ctx, d.rbdArgs("rename", "--", recvRef, opts.DstRef)...); rerr != nil {
			removeIncoming()
			return fmt.Errorf("ceph replicate → %s: place the copy: %w: %s", opts.DstRef, rerr, out)
		}
	}
	return nil
}

// CreateRBDSnapshot creates and protects a snapshot of an RBD image.
// Exposed as a package-level helper because snapshot handlers manage
// lifetime independently of any Driver instance.
func CreateRBDSnapshot(ctx context.Context, pool, imageName, snapName string, opts map[string]string) error {
	d := &cephDriver{pool: pool, opts: opts}
	spec := fmt.Sprintf("%s/%s@%s", pool, imageName, snapName)
	args := d.rbdArgs("snap", "create", spec)
	out, err := exec.CommandContext(ctx, "rbd", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rbd snap create %s: %w: %s", spec, err, out)
	}
	protectArgs := d.rbdArgs("snap", "protect", spec)
	out, err = exec.CommandContext(ctx, "rbd", protectArgs...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already protected") {
		return fmt.Errorf("rbd snap protect %s: %w: %s", spec, err, out)
	}
	slog.Info("RBD snapshot created", "pool", pool, "image", imageName, "snap", snapName)
	return nil
}

// CloneRBDSnapshot clones a protected snapshot into a new RBD image.
func CloneRBDSnapshot(ctx context.Context, pool, srcImage, snapName, destImage string, opts map[string]string) error {
	d := &cephDriver{pool: pool, opts: opts}
	src := fmt.Sprintf("%s/%s@%s", pool, srcImage, snapName)
	dst := fmt.Sprintf("%s/%s", pool, destImage)
	args := d.rbdArgs("clone", "--image-feature", "layering", src, dst)
	out, err := exec.CommandContext(ctx, "rbd", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rbd clone %s → %s: %w: %s", src, dst, err, out)
	}
	slog.Info("RBD snapshot cloned", "src", src, "dest", dst)
	return nil
}

// DeleteRBDSnapshot unprotects (best-effort) and removes an RBD snapshot.
func DeleteRBDSnapshot(ctx context.Context, pool, imageName, snapName string, opts map[string]string) error {
	d := &cephDriver{pool: pool, opts: opts}
	spec := fmt.Sprintf("%s/%s@%s", pool, imageName, snapName)
	unprotectArgs := d.rbdArgs("snap", "unprotect", spec)
	exec.CommandContext(ctx, "rbd", unprotectArgs...).CombinedOutput()
	args := d.rbdArgs("snap", "rm", spec)
	out, err := exec.CommandContext(ctx, "rbd", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rbd snap rm %s: %w: %s", spec, err, out)
	}
	slog.Info("RBD snapshot deleted", "pool", pool, "image", imageName, "snap", snapName)
	return nil
}

// CephImageName extracts the image name from an "rbd:" path.
//
//	"rbd:litevirt/vm1-root:conf=/etc/ceph/ceph.conf" → "vm1-root"
func CephImageName(path string) string { return cephImageName(path) }

// CephPoolName extracts the pool name from an "rbd:" path.
func CephPoolName(path string) string {
	s := strings.TrimPrefix(path, "rbd:")
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func cephImageName(path string) string {
	s := strings.TrimPrefix(path, "rbd:")
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	imgParts := strings.SplitN(parts[1], ":", 2)
	return imgParts[0]
}

// incomingMarker names a full copy's image while it is received, before it is
// renamed into place: <dst>.litevirt-incoming-<unix seconds>-<random>.
const incomingMarker = ".litevirt-incoming-"

// incomingMaxAge is how old an incoming image is before a later copy into
// the same pool removes it as the leftover of a crash between import and
// rename. No copy runs that long without finishing.
const incomingMaxAge = 24 * time.Hour

// sweepIncoming removes, in dstRef's pool, incoming images a crashed copy
// left (incomingMarker, older than incomingMaxAge). Only names this driver
// mints are touched; a failure to list is ignored.
func (d *cephDriver) sweepIncoming(ctx context.Context, dstRef string, now time.Time) {
	pool, _, ok := strings.Cut(dstRef, "/")
	if !ok || pool == "" {
		return
	}
	out, err := d.rbd(ctx, d.rbdArgs("ls", "--", pool)...)
	if err != nil {
		return
	}
	for _, name := range strings.Fields(string(out)) {
		_, rest, ok := strings.Cut(name, incomingMarker)
		if !ok {
			continue
		}
		secs, _, ok := strings.Cut(rest, "-")
		if !ok {
			continue
		}
		t, err := strconv.ParseInt(secs, 10, 64)
		if err != nil || now.Sub(time.Unix(t, 0)) < incomingMaxAge {
			continue
		}
		if _, err := d.rbd(ctx, d.rbdArgs("rm", "--", pool+"/"+name)...); err == nil {
			slog.Info("ceph: removed an incoming image a crashed copy left", "image", pool+"/"+name)
		}
	}
}
