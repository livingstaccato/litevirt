// Package lxc is litevirt's LXC + OCI container runtime. It mirrors
// the VM lifecycle surface (Create / Start / Stop / Delete / Console /
// Exec / List) so a single gRPC service plus shared schedulers can
// host both kinds of workload.
//
// We shell out to the system's lxc-* binaries rather than vendor
// go-lxc; this keeps the litevirtd binary CGO-free and matches how
// Proxmox's pve-container is implemented. The binaries are part of
// the host bootstrap (`apt install lxc` or equivalent).
//
// split:
//
//	1.4.A (this file): Runtime interface + production Runner +
//	                   Container struct + create/start/stop/delete.
//	1.4.B: OCI image pull → LXC rootfs (umoci shell-out).
//	1.4.C: Networking — veth attach into existing bridges/VXLANs.
//	1.4.D: Compose workloads schema + CLI + UI + docs.
package lxc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

// ErrStatsUnavailable is returned by Stats when live cgroup usage can't be read
// (e.g. a cgroup-v1-only host, or the container has no cgroup yet). Callers (the
// metrics collector) skip the usage sample via errors.Is rather than logging.
var ErrStatsUnavailable = errors.New("container cgroup stats unavailable")

// ErrContainerNotFound is returned (wrapped) by Delete when lxc-destroy reports
// the container does not exist. The fail-closed DeleteContainer handler tests it
// with errors.Is to treat deletion as idempotent (a runtime that's already gone
// is success) — without string-matching command output up in the gRPC layer.
var ErrContainerNotFound = errors.New("container not found")

// ContainerStats is a point-in-time cgroup-v2 usage sample for a container.
type ContainerStats struct {
	CPUUsageUsec uint64 // cumulative CPU time (cpu.stat usage_usec)
	MemBytes     int64  // current memory usage (memory.current)
}

// State is the libvirt-style lifecycle state, mirrored for parity with
// the existing VM domain states so the UI can render both with the
// same components.
type State string

const (
	StateUnknown  State = ""
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateStopping State = "stopping"
	StateError    State = "error"
)

// Container describes one LXC container as known to litevirt.
type Container struct {
	Name      string
	State     State
	RootFS    string            // path to the container's rootfs (file or dir)
	CPULimit  int               // cap in cores; 0 = unlimited
	MemoryMiB int               // hard cap; 0 = unlimited
	Network   []NetworkAttach   // veth attachments, each into an existing bridge
	Labels    map[string]string // free-form metadata used by compose / UI
	Image     string            // origin image name (oci://… or alpine:3.19)
	// ImageGen is the generation of the library item a container was
	// copied from (ImageGenFile), "" for any other source.
	ImageGen string
}

// NetworkAttach describes one container NIC.
type NetworkAttach struct {
	Name   string // unique within a container (eth0, eth1, …)
	Bridge string // host bridge to attach to (br0, vxlan-prod, …)
	IP     string // optional static IP; empty = DHCP / RA
	MAC    string // optional fixed MAC; empty = OS-generated
	Veth   string // optional deterministic host-side veth name (lxc.net.N.veth.pair); ≤15 bytes
	// Gateway is an optional bare IPv4 default gateway (lxc.net.N.ipv4.gateway),
	// also written into the guest's ifupdown stanza for a static NIC.
	Gateway string
}

// ExecResult captures the outcome of lxc-attach.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runtime is the shell-out boundary. Production wires LxcRunner; tests
// inject a fake.
type Runtime interface {
	// Create allocates a new container (rootfs + config) but does not
	// start it. The caller is responsible for populating the rootfs;
	// CreateOpts.Template can be "download" to use lxc-templates' own
	// pull mechanism, or a path to an already-extracted rootfs.
	Create(ctx context.Context, opts CreateOpts) (*Container, error)
	// Start brings a stopped container up.
	Start(ctx context.Context, name string) error
	// Stop performs a clean shutdown (SIGTERM with a kill timeout).
	Stop(ctx context.Context, name string, timeoutSec int) error
	// Delete removes a stopped container and its rootfs.
	Delete(ctx context.Context, name string) error
	// Exec runs a command inside a running container.
	Exec(ctx context.Context, name string, argv []string) (ExecResult, error)
	// State queries lxc-info for the current state.
	State(ctx context.Context, name string) (State, error)
	// IP returns the container's primary IPv4 address (lxc-info -iH), or ""
	// if it has none yet. Used to discover a running container's address for
	// load balancer backends.
	IP(ctx context.Context, name string) (string, error)
	// List enumerates every container known to LXC on this host.
	List(ctx context.Context) ([]string, error)
	// Limits reads the container's configured cgroup limits back from its
	// on-disk config — the runtime's own truth, not the cluster DB's opinion.
	// 0 means unlimited for that dimension. The runtime-inventory collector
	// reports these so capacity accounting can charge runtime-only containers
	// and flag uncapped ones.
	Limits(ctx context.Context, name string) (cpuLimit int, mem MemoryLimit, err error)
	// Freeze suspends every process in a running container (lxc-freeze) so its
	// rootfs can be read consistently (backup/snapshot quiesce). Pair with
	// Unfreeze; a no-op-ish error on an already-frozen/stopped container is fine.
	Freeze(ctx context.Context, name string) error
	// Unfreeze resumes a frozen container (lxc-unfreeze). Always call it (defer)
	// after Freeze so a failed backup never leaves the container suspended.
	Unfreeze(ctx context.Context, name string) error
	// RootFSPath returns the host filesystem path of the container's root
	// (lxc.rootfs.path), the directory tree backup/snapshot/clone operate on.
	RootFSPath(name string) (string, error)
	// ExportContainer writes a tar stream of the container's on-disk directory
	// (its config + rootfs) to w. Quiesce with Freeze first for a consistent
	// read. The stream is self-contained: ImportContainer rebuilds the container
	// from it alone, even on a different host.
	ExportContainer(ctx context.Context, name string, w io.Writer) error
	// ImportContainer rebuilds a container's on-disk directory from a tar stream
	// produced by ExportContainer, then rewrites the config's rootfs path so it
	// is valid at this host's lxcpath. The container is left stopped.
	ImportContainer(ctx context.Context, name string, r io.Reader) error
	// ContainerExists reports whether the on-disk container dir exists (independent of
	// any DB row) — used by the crash-idempotent restore resume path.
	ContainerExists(name string) (bool, error)
	// RevertContainer replaces an EXISTING container's on-disk dir from a
	// snapshot tar (in-place snapshot revert — clobbers). The container must be
	// stopped first.
	RevertContainer(ctx context.Context, name string, r io.Reader) error
	// CloneContainer makes a full copy of src's on-disk dir as dst and gives it
	// a fresh identity (new hostname/uts.name, regenerated NIC MAC(s), reset
	// machine-id). The src should be stopped/frozen for a consistent copy.
	CloneContainer(ctx context.Context, src, dst string) error
	// Stats returns a live cgroup-v2 usage sample (host-local, no RPC). Returns
	// ErrStatsUnavailable when usage can't be read (cgroup-v1 host, no cgroup yet).
	Stats(ctx context.Context, name string) (ContainerStats, error)
}

// CreateOpts collects parameters for Runtime.Create.
type CreateOpts struct {
	Name string
	// Template selects how the rootfs is populated:
	//   - "download": lxc-create's download template (uses Distro/Release/Arch).
	//   - a rootfs path ("rootfs:<path>", an absolute path, or "./relative"):
	//     an already-extracted rootfs (e.g. from `lv ct pull` / umoci). We
	//     synthesise an LXC config that points at it — lxc-create has no way to
	//     adopt a pre-existing rootfs. A directory holding an OCI/umoci bundle
	//     (a "rootfs/" subdir) is descended into automatically.
	//   - any other bare name (e.g. "busybox"): passed to `lxc-create -t`.
	Template string
	// Distro / Release / Arch are forwarded to the lxc-download template
	// when Template == "download". Ignored otherwise.
	Distro  string
	Release string
	Arch    string
	// CPULimit / MemoryMiB end up as cgroup constraints.
	CPULimit  int
	MemoryMiB int
	// Network is applied as a series of `lxc.net.N.*` config keys.
	Network []NetworkAttach
	// Labels are persisted into a litevirt-specific config block (we
	// own them — LXC ignores).
	Labels map[string]string
	// Confinement is ConfinementDefault or ConfinementLegacy; "" is legacy,
	// the config an earlier build wrote (a recreate of such a container).
	Confinement string
	// IDMap makes the container unprivileged in that id range; nil is
	// privileged.
	IDMap *IDMap
	// PidsMax is written as lxc.cgroup2.pids.max when positive.
	PidsMax int
	// Mounts and Devices are host paths passed into the container. Create
	// judges them against the runner's HostAccess on this host (mounts.go);
	// the caller has already required the admin role.
	Mounts  []Mount
	Devices []Device
	// CheckItem, for a library item's rootfs path, judges the item as the
	// create copies it: called under the item's lock, with the item's
	// generation, before anything is copied; its error refuses the create.
	CheckItem func(gen string) error
	// Pinned binds a rootfs path to generation PinnedGen of its library
	// item, or with PinAnyGen to the generation the fetch finds:
	// FetchImage copies it aside for the name (refusing ErrImageReplaced
	// when the item is not PinnedGen), judged by CheckItem under the item's
	// lock, and Create builds from that copy, or from the item while it is
	// still that generation, or refuses. A recreate fetches before its
	// delete, so what becomes of the item after it cannot cost the member.
	Pinned    bool
	PinnedGen string
	PinAnyGen bool
}

// ErrImageReplaced is a pinned fetch's or create's refusal of a library
// item that is no longer the generation it was pinned to.
var ErrImageReplaced = errors.New("the image under this path was replaced since it was judged")

// Validate checks cross-field invariants before any shell-out.
func (o *CreateOpts) Validate() error {
	if o == nil {
		return errors.New("nil CreateOpts")
	}
	if o.Name == "" {
		return errors.New("container name required")
	}
	if strings.ContainsAny(o.Name, "/ \t\n") {
		return fmt.Errorf("invalid container name %q: must not contain whitespace or '/'", o.Name)
	}
	if o.Template == "" {
		return errors.New("template required (\"download\" or rootfs path)")
	}
	if o.Template == "download" && o.Distro == "" {
		return errors.New("download template requires distro (e.g. alpine, ubuntu)")
	}
	for i, n := range o.Network {
		if n.Bridge == "" {
			return fmt.Errorf("network[%d]: bridge required", i)
		}
	}
	return nil
}

// LxcRunner is the production Runtime backed by lxc-* CLI tools.
type LxcRunner struct {
	// Lxcpath optionally overrides /var/lib/lxc — set per-host so test
	// rigs and fenced containers can coexist.
	Lxcpath string

	// HostName is this daemon's cluster host name, mixed into a clone's
	// deterministic NIC MAC (corrosion.ContainerMAC) so the on-disk config matches
	// the interface row grpcapi records on the SAME host. Empty in bare/test rigs.
	HostName string

	// cgPathMu guards cgPathCache, which memoizes each running container's
	// resolved cgroup-v2 directory so Stats doesn't shell out to lxc-info on
	// every Prometheus scrape (which may run concurrently). Invalidated on a
	// stat failure (container restarted → new cgroup path).
	cgPathMu    sync.Mutex
	cgPathCache map[string]string

	// hostAccessMu guards hostAccessLocks, one lock per container name under
	// which its host-access record, config block and hook policy change.
	hostAccessMu    sync.Mutex
	hostAccessLocks map[string]*sync.Mutex
	// refreshStuck (under hostAccessMu) is when each container's abandoned
	// policy refresh was given up on; it holds that container's lock until
	// it returns.
	refreshStuck map[string]time.Time

	// DefaultPidsMax is the pids.max a container whose config sets none gets
	// at its next start (prepareStart). 0 adds none.
	DefaultPidsMax int
	// IDMappedRootfs chooses how an unprivileged container's rootfs is mapped:
	// "on" (an idmapped mount), "off" (files shifted into its range), or
	// "auto"/"" (an idmapped mount where idmappedProbe says this host can).
	IDMappedRootfs string
	// SubIDSpan is the whole id span containers are allocated from; root's
	// subordinate range is added for all of it at once (ensureRootSubIDs).
	SubIDSpan *IDMap

	// HostAccess is what this host lets containers reach: the prefixes host
	// bind mounts and device nodes must resolve under. Empty allows none.
	HostAccess HostAccess

	probeOnce     sync.Once
	probeIDMapped bool
}

// NewLxcRunner returns a Runtime configured to talk to /var/lib/lxc.
func NewLxcRunner() *LxcRunner { return &LxcRunner{} }

// Available reports whether this host has the lxc-* tooling needed to run
// containers. It is the one probe behind the litevirt.lxc host label
// (corrosion.LabelLXCCapable): the runtime is wired on every host, so where the
// tooling is absent every call fails at the binary lookup, and that host has
// no containers to list, pause or miss.
func Available() bool {
	_, err := exec.LookPath("lxc-create")
	return err == nil
}

// withLxcpath prepends -P <path> if a non-default lxcpath is set —
// every lxc-* binary accepts the same flag.
func (r *LxcRunner) withLxcpath(args []string) []string {
	if r.Lxcpath == "" {
		return args
	}
	return append([]string{"-P", r.Lxcpath}, args...)
}

func (r *LxcRunner) run(ctx context.Context, bin string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, r.withLxcpath(args)...)
	stderr := strings.Builder{}
	cmd.Stderr = stringWriter{&stderr}
	out, err := cmd.Output()
	return out, []byte(stderr.String()), err
}

// defaultLxcpath is LXC's standard container store, used when Lxcpath is unset.
const defaultLxcpath = "/var/lib/lxc"

func (r *LxcRunner) lxcpath() string {
	if r.Lxcpath != "" {
		return r.Lxcpath
	}
	return defaultLxcpath
}

// Create implements Runtime.Create. See CreateOpts.Template for the modes.
//
// For a rootfs path we write the container config directly instead of shelling
// out: lxc-create's -t flag expects a template *script*, so handing it a rootfs
// directory just fails ("exit status 1"). This is the path used by `lv ct pull`
// → `lv ct create` for OCI images.
func (r *LxcRunner) Create(ctx context.Context, opts CreateOpts) (*Container, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	// The name becomes <lxcpath>/<name>, which a failed create removes: it
	// must be a container name, whatever the caller (a relocation recreate
	// from a legacy row among them) checked.
	if err := safename.ValidateContainerName(opts.Name); err != nil {
		return nil, err
	}
	if opts.PidsMax == 0 {
		opts.PidsMax = r.DefaultPidsMax
	}
	// Host mounts and devices are judged before anything is created, so a
	// refusal leaves nothing behind.
	if len(opts.Mounts) > 0 || len(opts.Devices) > 0 {
		if _, _, err := ResolveHostAccess(opts.Mounts, opts.Devices, r.hostAccess()); err != nil {
			return nil, fmt.Errorf("container %q: %w", opts.Name, err)
		}
	}
	if opts.Template != "download" {
		// A rootfs path is copied under its item's lock: a replacing pull
		// of a library item waits for the copy (LockOCIItem).
		if p, isPath, _ := TemplatePath(opts.Template); isPath {
			unlock := LockOCIItem(BundleDir(p))
			defer unlock()
		}
		rootfs, ok, err := resolveRootfs(opts.Template)
		if err != nil {
			return nil, err
		}
		if ok {
			unlockFetch := lockFetch(opts.Name)
			defer unlockFetch()
			if opts.Pinned {
				// The copy the recreate's fetch took before its delete is
				// the judged generation, whatever the item holds now.
				if staged := r.pinnedCopy(opts); staged != "" {
					return r.createFromRootfs(ctx, opts, rootfs, staged)
				}
				if gen := ReadImageGen(BundleDir(rootfs)); !opts.PinAnyGen && gen != opts.PinnedGen {
					return nil, fmt.Errorf("create %q from %s: %w (generation %q, pinned %q)", opts.Name, opts.Template, ErrImageReplaced, gen, opts.PinnedGen)
				}
			}
			if opts.CheckItem != nil {
				if err := opts.CheckItem(ReadImageGen(BundleDir(rootfs))); err != nil {
					return nil, err
				}
			}
			c, err := r.createFromRootfs(ctx, opts, rootfs, "")
			if err == nil {
				// A pinned copy of the name this create did not use (staged
				// for a create that came without its pin) is not kept.
				r.dropPinnedCopy(opts.Name)
			}
			return c, err
		}
	}
	// A container FetchImage already built for this name and image is moved
	// into place; otherwise lxc-create builds it.
	if adopted, err := r.adoptFetched(opts); err != nil {
		return nil, err
	} else if !adopted {
		args := []string{"-n", opts.Name, "-t", opts.Template}
		if opts.Template == "download" {
			args = append(args, "--",
				"-d", opts.Distro,
				"-r", opts.Release,
				"-a", opts.Arch,
			)
		}
		if _, stderr, err := r.run(ctx, "lxc-create", args...); err != nil {
			return nil, cmdErr("lxc-create", opts.Name, stderr, err)
		}
	}
	// lxc-create wrote the base config (with a default NIC from
	// /etc/lxc/default.conf). Re-render the network from opts (so an explicit
	// --network wins) and apply cgroup limits.
	if err := r.finalizeContainerConfig(opts); err != nil {
		return nil, fmt.Errorf("apply container network/resource config for %q: %w", opts.Name, err)
	}
	if err := r.shiftNewRootfs(opts); err != nil {
		_ = os.RemoveAll(filepath.Join(r.lxcpath(), opts.Name))
		return nil, err
	}
	if err := r.secureContainerDir(opts.Name); err != nil {
		_ = os.RemoveAll(filepath.Join(r.lxcpath(), opts.Name))
		return nil, err
	}
	return &Container{
		Name:      opts.Name,
		State:     StateStopped,
		CPULimit:  opts.CPULimit,
		MemoryMiB: opts.MemoryMiB,
		Network:   opts.Network,
		Labels:    opts.Labels,
		Image:     opts.Distro + ":" + opts.Release,
	}, nil
}

// fetchDirName is the directory in LXC's store under which FetchImage builds
// containers. "+" is outside every container name's charset (safename), so
// it never names a container.
const fetchDirName = ".litevirt+fetch"

// fetchedImageFile is the file in a fetch stage naming the image its
// container was built from (fetchSignature); its "+" keeps it apart from
// the container's own directory, whatever its name.
const fetchedImageFile = ".litevirt+image"

// fetchStageTTL is how long a staged fetch is reused and adopted: one left
// by a recreate that did not go ahead is not taken by a later, unrelated
// create of the name, which fetches anew.
const fetchStageTTL = time.Hour

var fetchLocks sync.Map // container name → *sync.Mutex

// adoptBeforeRename is a test seam run just before adoptFetched's rename.
var adoptBeforeRename func(built string)

func lockFetch(name string) func() {
	m, _ := fetchLocks.LoadOrStore(name, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// fetchSignature names the image a create with opts is built from.
func fetchSignature(opts CreateOpts) string {
	return strings.Join([]string{opts.Template, opts.Distro, opts.Release, opts.Arch}, "\x00")
}

// fetchStage is where FetchImage keeps the container it built for name:
// <lxcpath>/.litevirt+fetch/<name>, an lxcpath holding one container, also
// named name, so the download template writes the container's own name into
// the guest (/etc/hostname, /etc/hosts), and it is never the live member's
// directory.
func (r *LxcRunner) fetchStage(name string) string {
	return filepath.Join(r.lxcpath(), fetchDirName, name)
}

// FetchImage fetches and verifies, on this host, the rootfs a Create with
// opts would be built from, and creates no container in the store: a caller
// about to replace a container (a compose recreate) runs it before the
// delete, so an image this host cannot fetch leaves the container as it is.
//
// A rootfs path is resolved as Create resolves it (an existing directory that
// looks like a root filesystem), under its item's lock. Any other template —
// "download" above all — is run by lxc-create into a staging lxcpath under
// fetchDirName (the download template fetches the image and verifies its
// signature), and the container it built is kept there: the Create of the
// same name and image that follows moves it into place (adoptFetched)
// instead of fetching again. A fetch of another image for the name replaces
// it; SweepFetchDir clears what is left at daemon start.
func (r *LxcRunner) FetchImage(ctx context.Context, opts CreateOpts) error {
	// The name becomes a path under the store: it must be a container
	// name itself, whatever the caller checked.
	if err := safename.ValidateContainerName(opts.Name); err != nil {
		return fmt.Errorf("fetch image: %w", err)
	}
	if err := opts.Validate(); err != nil {
		return err
	}
	r.expirePinnedCopies()
	if opts.Template != "download" {
		if p, isPath, _ := TemplatePath(opts.Template); isPath {
			unlock := LockOCIItem(BundleDir(p))
			defer unlock()
		}
		rootfs, ok, err := resolveRootfs(opts.Template)
		if err != nil {
			return err
		}
		if ok {
			if opts.Pinned {
				return r.stagePinnedCopy(ctx, opts, rootfs)
			}
			return nil
		}
	}
	unlock := lockFetch(opts.Name)
	defer unlock()
	stage := r.fetchStage(opts.Name)
	if r.freshFetch(stage, opts) {
		return nil // already fetched and kept
	}
	if err := clearStage(stage); err != nil {
		return fmt.Errorf("fetch image: %w", err)
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return fmt.Errorf("fetch image: %w", err)
	}
	args := []string{"-P", stage, "-n", opts.Name, "-t", opts.Template}
	if opts.Template == "download" {
		args = append(args, "--", "-d", opts.Distro, "-r", opts.Release, "-a", opts.Arch)
	}
	cmd := dieWithDaemon(exec.CommandContext(ctx, "lxc-create", args...))
	var stderr strings.Builder
	cmd.Stderr = stringWriter{&stderr}
	if err := runPinned(func() error { _, e := cmd.Output(); return e }); err != nil {
		_ = os.RemoveAll(stage)
		return cmdErr("lxc-create (fetch image)", opts.Name, []byte(stderr.String()), err)
	}
	if err := os.WriteFile(filepath.Join(stage, fetchedImageFile), []byte(fetchSignature(opts)), 0o600); err != nil {
		_ = os.RemoveAll(stage)
		return fmt.Errorf("fetch image: %w", err)
	}
	return nil
}

// adoptFetched moves the container FetchImage built for opts.Name into the
// store as opts.Name, when it was built from the image opts names, and
// points its config at its new place. It reports whether it did; a staged
// container of another image is left for the next fetch to replace.
func (r *LxcRunner) adoptFetched(opts CreateOpts) (bool, error) {
	if err := safename.ValidateContainerName(opts.Name); err != nil {
		return false, err
	}
	unlock := lockFetch(opts.Name)
	defer unlock()
	stage := r.fetchStage(opts.Name)
	if !r.freshFetch(stage, opts) {
		return false, nil
	}
	built := filepath.Join(stage, opts.Name)
	dst := filepath.Join(r.lxcpath(), opts.Name)
	if _, err := os.Lstat(dst); err == nil {
		return false, fmt.Errorf("container %q already exists at %s", opts.Name, dst)
	}
	// Its files name its final place before the one rename that puts it
	// there: a crash leaves either a stage (swept at start) or a complete
	// container, never one whose config names the stage.
	for _, f := range []string{"config", "fstab"} {
		if err := repointFetched(filepath.Join(built, f), built, dst); err != nil {
			_ = os.RemoveAll(stage)
			return false, err
		}
	}
	if adoptBeforeRename != nil {
		adoptBeforeRename(built)
	}
	if err := os.Rename(built, dst); err != nil {
		_ = os.RemoveAll(stage)
		return false, fmt.Errorf("move the fetched container into place as %q: %w", opts.Name, err)
	}
	_ = os.RemoveAll(stage)
	return true, nil
}

// freshFetch reports whether stage holds a container built for opts within
// fetchStageTTL.
func (r *LxcRunner) freshFetch(stage string, opts CreateOpts) bool {
	sig := filepath.Join(stage, fetchedImageFile)
	b, err := os.ReadFile(sig)
	if err != nil || string(b) != fetchSignature(opts) {
		return false
	}
	// Fresh is fetched within fetchStageTTL; a fetch time in the future
	// (the clock was set back) is not.
	if fi, err := os.Stat(sig); err != nil || time.Since(fi.ModTime()) > fetchStageTTL || time.Until(fi.ModTime()) > time.Minute {
		return false
	}
	_, err = os.Stat(filepath.Join(stage, opts.Name, "config"))
	return err == nil
}

// repointFetched points a file of a moved container (its config, its
// fstab) at its new directory: every mention of from becomes to. A file
// the template did not write is left alone.
func repointFetched(f, from, to string) error {
	b, err := os.ReadFile(f)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return os.WriteFile(f, []byte(strings.ReplaceAll(string(b), from, to)), 0o644)
}

// SweepFetchDir removes, at daemon start, every container FetchImage left
// staged (a recreate refused after its fetch, or a crash).
//
// A pinned copy a recreate may still need (stagePinnedCopy, within
// pinnedCopyKeep) is kept, once nothing works in it.
func (r *LxcRunner) SweepFetchDir() error {
	dir := filepath.Join(r.lxcpath(), fetchDirName)
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	keep := false
	for _, e := range ents {
		if isPinnedCopy(filepath.Join(dir, e.Name()), pinnedCopyKeep) {
			keep = true
		}
	}
	if !keep {
		return sweepStage(dir)
	}
	var errs []error
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if isPinnedCopy(p, pinnedCopyKeep) {
			if err := stopWorkersIn(p); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := sweepStage(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sweepStage removes a staging directory at start, after stopping any
// process still working in it (stopWorkersIn), retrying briefly while one
// that was stopping releases it.
func sweepStage(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// A stage is removed only once nobody works in it any more.
	if err := stopWorkersIn(dir); err != nil {
		slog.Warn("container staging: kept a stage a process may still be working in", "path", dir, "error", err)
		return err
	}
	var err error
	for i := 0; i < 10; i++ {
		if err = os.RemoveAll(dir); err == nil {
			slog.Info("container staging: removed what an earlier run left staged", "path", dir)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// createFromRootfs materialises a container around an already-extracted rootfs
// by writing <lxcpath>/<name>/config — no lxc-create. The config mirrors what
// the download template produces (common.conf + apparmor + a veth NIC) so the
// container starts identically.
//
// The template rootfs is COPIED per container into <lxcpath>/<name>/rootfs (the
// canonical RootfsPath). This is essential: lxc.rootfs.path points at the copy, so
// lxc-destroy (which removes the rootfs its config references) only ever removes the
// container's own copy — the pulled OCI/rootfs template stays intact and reusable
// for N containers. Sharing the template by reference let `lv ct rm` gut it.
//
// staged, when not "", is a copy of the rootfs already taken for this
// create (stagePinnedCopy): it is moved into place instead of copying
// rootfs, and moved back if the create then fails.
func (r *LxcRunner) createFromRootfs(ctx context.Context, opts CreateOpts, rootfs, staged string) (*Container, error) {
	containerDir := filepath.Join(r.lxcpath(), opts.Name)
	configPath := filepath.Join(containerDir, "config")
	if _, err := os.Stat(configPath); err == nil {
		return nil, fmt.Errorf("container %q already exists at %s", opts.Name, containerDir)
	}
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		return nil, fmt.Errorf("create container dir %s: %w", containerDir, err)
	}
	// Own copy of the rootfs (== RootfsPath(r.lxcpath(), opts.Name)), so destroy
	// never touches the template. copyTree wraps failures + cleans up on error.
	dstRootfs := filepath.Join(containerDir, "rootfs")
	gen := ReadImageGen(BundleDir(rootfs))
	undo := func() {
		if staged != "" {
			_ = os.Rename(dstRootfs, staged)
		}
		_ = os.RemoveAll(containerDir)
	}
	if staged != "" {
		b, err := os.ReadFile(filepath.Join(filepath.Dir(staged), pinnedGenFile))
		if err != nil {
			_ = os.RemoveAll(containerDir)
			return nil, fmt.Errorf("read the staged rootfs copy's generation for %q: %w", opts.Name, err)
		}
		if err := os.Rename(staged, dstRootfs); err != nil {
			_ = os.RemoveAll(containerDir)
			return nil, fmt.Errorf("move the staged rootfs copy for %q into place: %w", opts.Name, err)
		}
		gen = string(b)
	} else if err := copyTree(ctx, rootfs, dstRootfs); err != nil {
		_ = os.RemoveAll(containerDir)
		return nil, fmt.Errorf("copy template rootfs for %q: %w", opts.Name, err)
	}
	if err := os.WriteFile(configPath, []byte(renderBaseRootfsConfig(opts.Name, dstRootfs)), 0o644); err != nil {
		undo()
		return nil, fmt.Errorf("write lxc config %s: %w", configPath, err)
	}
	// Apply network (explicit --network or the lxcbr0 default) and cgroup limits.
	// finalizeContainerConfig reads lxc.rootfs.path back to locate the rootfs for the
	// guest /etc/network/interfaces write, so that write lands in the copy — the
	// template is never mutated.
	if err := r.finalizeContainerConfig(opts); err != nil {
		if staged != "" {
			undo()
		}
		return nil, fmt.Errorf("apply container network/resource config for %q: %w", opts.Name, err)
	}
	if err := r.shiftNewRootfs(opts); err != nil {
		undo()
		return nil, err
	}
	if err := r.secureContainerDir(opts.Name); err != nil {
		undo()
		return nil, err
	}
	if staged != "" {
		r.dropPinnedCopy(opts.Name)
	}
	return &Container{
		Name:      opts.Name,
		State:     StateStopped,
		RootFS:    dstRootfs,
		ImageGen:  gen,
		CPULimit:  opts.CPULimit,
		MemoryMiB: opts.MemoryMiB,
		Network:   opts.Network,
		Labels:    opts.Labels,
		// Image is left to the gRPC layer, which records the originating OCI
		// reference (req.Image) — Create can't infer it from a rootfs path.
	}, nil
}

// Start runs lxc-start in daemon mode, after prepareStart.
func (r *LxcRunner) Start(ctx context.Context, name string) error {
	if err := r.prepareStart(name); err != nil {
		return err
	}
	if _, stderr, err := r.run(ctx, "lxc-start", "-n", name, "-d"); err != nil {
		return cmdErr("lxc-start", name, stderr, err)
	}
	return nil
}

// Stop runs lxc-stop with the supplied SIGTERM-then-SIGKILL timeout.
func (r *LxcRunner) Stop(ctx context.Context, name string, timeoutSec int) error {
	args := []string{"-n", name}
	if timeoutSec > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", timeoutSec))
	}
	if _, stderr, err := r.run(ctx, "lxc-stop", args...); err != nil {
		return cmdErr("lxc-stop", name, stderr, err)
	}
	return nil
}

// Delete runs lxc-destroy with -f, which stops the container first if it's
// running. Without -f, lxc-destroy refuses a running container ("<name> is
// running"), so `lv ct rm` and `compose down` of a running container would fail.
func (r *LxcRunner) Delete(ctx context.Context, name string) error {
	if err := safename.ValidateContainerName(name); err != nil {
		return err
	}
	if _, stderr, err := r.run(ctx, "lxc-destroy", "-f", "-n", name); err != nil {
		// Only classify as not-found when the container is ACTUALLY gone on disk
		// (its config is absent). A broad stderr match would mask a real failure —
		// a corrupt config, a busy mount, a permission/read error — that leaves
		// runtime state behind while the gRPC layer tombstones the row and reports
		// success. Verifying the path keeps that across lxc-* versions/wording.
		cfg := filepath.Join(r.lxcpath(), name, "config")
		if _, statErr := os.Stat(cfg); os.IsNotExist(statErr) {
			return fmt.Errorf("%w: lxc-destroy %s: %s", ErrContainerNotFound, name, strings.TrimSpace(string(stderr)))
		}
		return cmdErr("lxc-destroy", name, stderr, err)
	}
	return nil
}

// execPATH is injected into the attach context so a bare command (e.g. "cat")
// resolves: modern lxc-attach starts with a cleared environment, so without
// this PATH only absolute paths would work.
const execPATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Exec runs argv inside the container via lxc-attach.
func (r *LxcRunner) Exec(ctx context.Context, name string, argv []string) (ExecResult, error) {
	return r.ExecStarted(ctx, name, argv, nil)
}

// ExecStarted is Exec, calling started (when not nil) once lxc-attach is
// committed to the container it found running: it has forked to enter it.
// A container stopped after that ends what was attached; one started again
// is not the one attached to. If lxc-attach exits first, started is not
// called; nor is it on a kernel that cannot list a process's children
// (no CONFIG_PROC_CHILDREN), where the attach cannot be seen.
func (r *LxcRunner) ExecStarted(ctx context.Context, name string, argv []string, started func()) (ExecResult, error) {
	args := append([]string{"-n", name, "--set-var", execPATH, "--"}, argv...)
	cmd := exec.CommandContext(ctx, "lxc-attach", r.withLxcpath(args)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	var err error
	if err = cmd.Start(); err == nil {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		err = waitAttached(cmd.Process.Pid, done, started)
	}
	out := stdout.Bytes()
	res := ExecResult{Stdout: out, Stderr: stderr.Bytes()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}

// State queries lxc-info.
func (r *LxcRunner) State(ctx context.Context, name string) (State, error) {
	out, _, err := r.run(ctx, "lxc-info", "-n", name, "-s", "-H")
	if err != nil {
		return StateUnknown, err
	}
	return parseLxcInfoState(string(out)), nil
}

// IP returns the container's primary IPv4 (lxc-info -iH), or "" if it has
// none assigned yet. `-iH` prints one IP per line (IPv4 and IPv6); we pick the
// first IPv4 that isn't loopback so the result is usable as an LB backend.
func (r *LxcRunner) IP(ctx context.Context, name string) (string, error) {
	out, _, err := r.run(ctx, "lxc-info", "-n", name, "-iH")
	if err != nil {
		return "", err
	}
	return parseLxcInfoIP(string(out)), nil
}

// Stats reads a running container's live cgroup-v2 usage. It discovers the
// cgroup directory from the container's init PID (`lxc-info -n <name> -p -H` →
// /proc/<pid>/cgroup), caches it (mutex-guarded; concurrent scrapes), and reads
// cpu.stat + memory.current. Returns ErrStatsUnavailable on a cgroup-v1 host or
// when the container has no readable cgroup (so the collector skips, no spam).
func (r *LxcRunner) Stats(ctx context.Context, name string) (ContainerStats, error) {
	if err := safename.ValidateContainerName(name); err != nil {
		return ContainerStats{}, err
	}

	dir, err := r.cgroupDir(ctx, name)
	if err != nil {
		return ContainerStats{}, err
	}
	cpu, cerr := readCPUUsageUsec(filepath.Join(dir, "cpu.stat"))
	mem, merr := readUint(filepath.Join(dir, "memory.current"))
	if cerr != nil || merr != nil {
		// Require BOTH reads: a partial read would emit a bogus 0 for the missing
		// metric (a fake counter reset / memory drop). A failure usually means the
		// cached path is stale (container restarted → new cgroup) or gone, so drop
		// it; the next scrape re-discovers. Report unavailable for this round.
		r.cgPathMu.Lock()
		delete(r.cgPathCache, name)
		r.cgPathMu.Unlock()
		return ContainerStats{}, ErrStatsUnavailable
	}
	return ContainerStats{CPUUsageUsec: cpu, MemBytes: int64(mem)}, nil
}

// cgroupDir resolves (and memoizes) the container's cgroup-v2 directory under
// /sys/fs/cgroup. Returns ErrStatsUnavailable on a non-v2 layout.
func (r *LxcRunner) cgroupDir(ctx context.Context, name string) (string, error) {
	r.cgPathMu.Lock()
	if r.cgPathCache != nil {
		if dir, ok := r.cgPathCache[name]; ok {
			r.cgPathMu.Unlock()
			return dir, nil
		}
	}
	r.cgPathMu.Unlock()

	out, _, err := r.run(ctx, "lxc-info", "-n", name, "-p", "-H")
	if err != nil {
		return "", ErrStatsUnavailable
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return "", ErrStatsUnavailable // not running / no init PID
	}
	rel, err := cgroupV2RelPath(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	// rel begins with "/"; filepath.Join keeps it inside /sys/fs/cgroup.
	dir := filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+rel))
	r.cgPathMu.Lock()
	if r.cgPathCache == nil {
		r.cgPathCache = map[string]string{}
	}
	r.cgPathCache[name] = dir
	r.cgPathMu.Unlock()
	return dir, nil
}

// cgroupV2RelPath parses /proc/<pid>/cgroup and returns the unified-hierarchy
// (cgroup-v2) path — the line prefixed "0::". Absent → ErrStatsUnavailable
// (cgroup-v1 host; usage lives in per-controller hierarchies we don't read).
func cgroupV2RelPath(procCgroupFile string) (string, error) {
	data, err := os.ReadFile(procCgroupFile)
	if err != nil {
		return "", ErrStatsUnavailable
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.TrimSpace(rel), nil
		}
	}
	return "", ErrStatsUnavailable
}

// readCPUUsageUsec extracts the `usage_usec` value from a cgroup-v2 cpu.stat file.
func readCPUUsageUsec(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, fmt.Errorf("usage_usec not found in %s", path)
}

// readUint reads a single-integer cgroup file (e.g. memory.current). A "max"
// sentinel (unlimited) reads as 0.
func readUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// parseLxcInfoIP returns the first non-loopback IPv4 from lxc-info -iH output.
func parseLxcInfoIP(s string) string {
	for _, line := range strings.Split(s, "\n") {
		ip := net.ParseIP(strings.TrimSpace(line))
		if ip == nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		return ip.String()
	}
	return ""
}

// List enumerates lxc-ls --running --stopped output.
func (r *LxcRunner) List(ctx context.Context) ([]string, error) {
	out, _, err := r.run(ctx, "lxc-ls", "--quiet")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			names = append(names, t)
		}
	}
	return names, nil
}

// Freeze suspends a running container's processes (lxc-freeze).
func (r *LxcRunner) Freeze(ctx context.Context, name string) error {
	if _, stderr, err := r.run(ctx, "lxc-freeze", "-n", name); err != nil {
		return fmt.Errorf("lxc-freeze %s: %w: %s", name, err, stderr)
	}
	return nil
}

// IsFrozen reports whether a container is FROZEN, which State folds into
// running. The partition pauser uses it to leave a container someone else
// froze alone (docs/design/partition-pause.md §3.3).
func (r *LxcRunner) IsFrozen(ctx context.Context, name string) (bool, error) {
	out, _, err := r.run(ctx, "lxc-info", "-n", name, "-s", "-H")
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(string(out)), "frozen"), nil
}

// Unfreeze resumes a frozen container (lxc-unfreeze).
func (r *LxcRunner) Unfreeze(ctx context.Context, name string) error {
	if _, stderr, err := r.run(ctx, "lxc-unfreeze", "-n", name); err != nil {
		return fmt.Errorf("lxc-unfreeze %s: %w: %s", name, err, stderr)
	}
	return nil
}

// RootFSPath returns the host path of the container's root from its config's
// lxc.rootfs.path (stripping the "dir:" prefix the download template writes),
// falling back to the standard <lxcpath>/<name>/rootfs layout.
func (r *LxcRunner) RootFSPath(name string) (string, error) {
	cfg := filepath.Join(r.lxcpath(), name, "config")
	data, err := os.ReadFile(cfg)
	if err != nil {
		return "", fmt.Errorf("read container config %s: %w", cfg, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, "lxc.rootfs.path"); ok {
			if _, v, found := strings.Cut(rest, "="); found {
				p := strings.TrimPrefix(strings.TrimSpace(v), "dir:")
				if p != "" {
					return p, nil
				}
			}
		}
	}
	return filepath.Join(r.lxcpath(), name, "rootfs"), nil
}

// ExportContainer tars the container's whole on-disk directory (config + rootfs)
// from <lxcpath> to w. Tarring the directory — not just the rootfs — keeps the
// LXC config (network, limits, mounts) in the archive so a restore is faithful
// without a source cluster. Freeze the container first for a consistent read.
func (r *LxcRunner) ExportContainer(ctx context.Context, name string, w io.Writer) error {
	dir := filepath.Join(r.lxcpath(), name)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("container dir %s: %w", dir, err)
	}
	// -C <lxcpath> <name> stores paths relative to the container name, so a
	// restore can extract under a different lxcpath. --numeric-owner keeps uid/gid
	// stable across hosts that may not share /etc/passwd.
	// --xattrs with every attribute and --acls keep file capabilities, ACLs
	// and labels; setuid/setgid/sticky are in the mode. ImportContainer
	// restores all of it (safename.ExtractRootfsTar).
	// The member order is the names' order, not the directory's (an ext4
	// htree order differs per filesystem), and the pax headers --xattrs
	// selects carry no atime or ctime: a restore keeps a member's mtime
	// (safename.ExtractRootfsTar) but can never keep its ctime, and a read
	// moves its atime. Two archives of the same tree, before and after a move,
	// are then the same bytes, which is what lets a replica send only the
	// content-defined chunks that changed. GNU tar sorts with --sort=name from
	// 1.28; an older one is handed the same order as a list instead, so an
	// export never fails where it did not before.
	args := []string{"-C", r.lxcpath(), "--numeric-owner",
		"--pax-option=delete=atime,delete=ctime",
		"--xattrs", "--xattrs-include=*", "--acls", "-cf", "-"}
	var list []byte
	if tarSortsByName() {
		args = append(args, "--sort=name", name)
	} else {
		var err error
		if list, err = sortedMemberList(r.lxcpath(), name); err != nil {
			return fmt.Errorf("tar export %s: list members: %w", name, err)
		}
		args = append(args, "--no-recursion", "--null", "--files-from=-")
	}
	cmd := exec.CommandContext(ctx, "tar", args...)
	if list != nil {
		cmd.Stdin = bytes.NewReader(list)
	}
	stderr := strings.Builder{}
	cmd.Stderr = stringWriter{&stderr}
	cmd.Stdout = w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tar export %s: %w: %s", name, err, stderr.String())
	}
	return nil
}

// ImportContainer extracts a tar stream from ExportContainer into <lxcpath>,
// recreating <lxcpath>/<name>/{config,rootfs}, then rewrites lxc.rootfs.path to
// this host's layout (the archived config may carry the source host's path).
// It refuses to clobber an existing container directory.
func (r *LxcRunner) ImportContainer(ctx context.Context, name string, src io.Reader) error {
	return r.importContainer(ctx, name, src, false)
}

// RevertContainer replaces an EXISTING container's on-disk dir from a snapshot
// tar (produced by ExportContainer): it removes <lxcpath>/<name> and extracts
// the tar in its place, then rewrites lxc.rootfs.path. Unlike ImportContainer it
// clobbers — it's the in-place snapshot-revert path. The container MUST be
// stopped first (the caller stops it); replacing the rootfs of a running
// container is unsafe.
func (r *LxcRunner) RevertContainer(ctx context.Context, name string, src io.Reader) error {
	return r.importContainer(ctx, name, src, true)
}

// ContainerExists reports whether the on-disk container dir <lxcpath>/<name> exists,
// independent of any DB row or valid config — the primitive the restore resume path uses
// to detect an untracked artifact left by a crash between import and row-write. A stat
// error other than "not exist" is returned so the caller fails closed.
func (r *LxcRunner) ContainerExists(name string) (bool, error) {
	if err := safename.ValidateContainerName(name); err != nil {
		return false, err
	}
	_, err := os.Stat(filepath.Join(r.lxcpath(), name))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// importContainer is the shared extract path. replace=false refuses to clobber
// (fresh import/restore); replace=true sets any existing dir aside and
// restores it on failure (crash-safe snapshot revert — a corrupt snapshot tar
// can never lose the live container).
//
// The archive is laid down in a private (0700) staging directory under
// lxcpath and moved into place only once its config points at the final
// rootfs and the container directory is closed to other host users
// (secureContainerDirAt): a rootfs may carry setuid binaries, and the
// archive's own directory mode (0755 from an earlier build) must never be
// reachable while they are there. Root's subordinate range is ensured for an
// unprivileged container here, on the host it lands on. Attributes the
// filesystem does not support are dropped and recorded (droppedAttrsFile).
func (r *LxcRunner) importContainer(ctx context.Context, name string, src io.Reader, replace bool) error {
	return r.importContainerMarked(ctx, name, src, replace, nil)
}

// importContainerMarked is importContainer that, with markTo, marks the
// staged copy converting to markTo when its config's security differs.
func (r *LxcRunner) importContainerMarked(ctx context.Context, name string, src io.Reader, replace bool, markTo *ConvertOpts) error {
	// The name becomes <lxcpath>/<name>; validate it before it composes a path.
	if err := safename.ValidateContainerName(name); err != nil {
		return err
	}
	dir := filepath.Join(r.lxcpath(), name)
	if _, err := os.Stat(dir); err == nil && !replace {
		return fmt.Errorf("container dir %s already exists; refusing to overwrite", dir)
	}
	if err := os.MkdirAll(r.lxcpath(), 0o755); err != nil {
		return fmt.Errorf("ensure lxcpath %s: %w", r.lxcpath(), err)
	}
	staging, err := os.MkdirTemp(r.lxcpath(), ".litevirt-import-"+name+"-")
	if err != nil {
		return fmt.Errorf("staging dir for %s: %w", name, err)
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		return err
	}
	// Slip-safe extraction: the archive is untrusted backup-repo data, so we
	// contain every member under the staging dir, never write through a
	// symlink, and require the single top-level dir to be the container name.
	dropped, err := extractRootfs(src, staging, name)
	if err != nil {
		return fmt.Errorf("extract container %s: %w", name, err)
	}
	staged := filepath.Join(staging, name)
	if err := rewriteRootFSPathAt(staged, filepath.Join(dir, "rootfs")); err != nil {
		return err
	}
	// The archive is untrusted: its config keeps only what litevirt itself
	// writes (no mounts, hooks, foreign includes, device rules or confinement
	// overrides), and its authorized host-access record is not an
	// authorization here. The caller renders security and host access again
	// from the authorized spec (RebuildConfig).
	if err := SanitizeImportedDir(staged); err != nil {
		return err
	}
	if b, rerr := os.ReadFile(filepath.Join(staged, "config")); rerr == nil {
		if sec := parseSecurity(string(b)); sec.IDMap != nil {
			if err := r.ensureRootSubIDs(sec.IDMap); err != nil {
				return err
			}
		}
	}
	if err := secureContainerDirAt(staged); err != nil {
		return err
	}
	if markTo != nil {
		if b, rerr := os.ReadFile(filepath.Join(staged, "config")); rerr == nil && securityDiffers(parseSecurity(string(b)), *markTo) {
			m, _ := json.Marshal(markTo)
			if err := os.WriteFile(filepath.Join(staged, convertMarkerFile), m, 0o600); err != nil {
				return fmt.Errorf("mark the restored copy of %s converting: %w", name, err)
			}
		}
	}
	var backup string
	if _, err := os.Stat(dir); err == nil {
		// Set the current dir aside rather than deleting it, so we can roll
		// back if the swap fails.
		backup = dir + ".revert-old"
		_ = os.RemoveAll(backup) // clear any stale backup from a prior crash
		if err := os.Rename(dir, backup); err != nil {
			return fmt.Errorf("set aside existing dir %s for revert: %w", dir, err)
		}
	}
	if err := os.Rename(staged, dir); err != nil {
		if backup != "" {
			_ = os.Rename(backup, dir)
		}
		return fmt.Errorf("move container %s into place: %w", name, err)
	}
	if backup != "" {
		_ = os.RemoveAll(backup) // success — drop the old copy
	}
	if len(dropped) > 0 {
		slog.Warn("container import: the target filesystem does not support some attributes; they were dropped (a dropped ACL narrowed the file's group bits)",
			"container", name, "dropped", dropped)
		b, _ := json.Marshal(dropped)
		_ = os.WriteFile(filepath.Join(dir, droppedAttrsFile), b, 0o600)
	}
	return nil
}

// extractRootfs is safename.ExtractRootfsTarReport; a variable so a test can
// watch where it extracts.
var extractRootfs = safename.ExtractRootfsTarReport

// droppedAttrsFile records, in the container's directory, the attributes its
// last import dropped, until TakeDroppedAttrs reports them.
const droppedAttrsFile = "litevirt-dropped-attrs"

// TakeDroppedAttrs returns and clears the attributes the container's last
// import dropped ("<member> <attribute>"); nil when none.
func (r *LxcRunner) TakeDroppedAttrs(name string) ([]string, error) {
	if err := safename.ValidateContainerName(name); err != nil {
		return nil, err
	}
	p := filepath.Join(r.lxcpath(), name, droppedAttrsFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, os.Remove(p)
}

// CloneContainer makes a full copy of src's on-disk dir as dst (`cp -a`), then
// rewrites the clone's config + rootfs for a fresh identity: new lxc.uts.name,
// a regenerated MAC on every NIC, a rootfs.path pointing at the clone, and a
// reset machine-id + hostname inside the rootfs (so the guest first-boots
// clean). The caller should freeze/stop src first for a consistent copy.
// Container clones are always full copies (no qcow2 backing), so there's no
// linked-clone dependency to track.
func (r *LxcRunner) CloneContainer(ctx context.Context, src, dst string) error {
	for _, n := range []string{src, dst} {
		if err := safename.ValidateContainerName(n); err != nil {
			return err
		}
	}
	srcDir := filepath.Join(r.lxcpath(), src)
	dstDir := filepath.Join(r.lxcpath(), dst)
	if _, err := os.Stat(srcDir); err != nil {
		return fmt.Errorf("source container dir %s: %w", srcDir, err)
	}
	if _, err := os.Stat(dstDir); err == nil {
		return fmt.Errorf("container dir %s already exists; refusing to overwrite", dstDir)
	}
	if err := os.MkdirAll(r.lxcpath(), 0o755); err != nil {
		return fmt.Errorf("ensure lxcpath %s: %w", r.lxcpath(), err)
	}
	if err := copyTree(ctx, srcDir, dstDir); err != nil {
		return err
	}
	if err := r.cloneFreshIdentity(dst); err != nil {
		_ = os.RemoveAll(dstDir)
		return err
	}
	if err := r.secureContainerDir(dst); err != nil {
		_ = os.RemoveAll(dstDir)
		return err
	}
	return nil
}

// cloneFreshIdentity rewrites a freshly-copied clone's config (rootfs.path,
// uts.name, regenerated NIC MACs) and resets in-rootfs identity files so the
// clone doesn't collide with its source.
func (r *LxcRunner) cloneFreshIdentity(name string) error {
	cfg := filepath.Join(r.lxcpath(), name, "config")
	data, err := os.ReadFile(cfg)
	if err != nil {
		return fmt.Errorf("read clone config %s: %w", cfg, err)
	}
	rootfsLine := "lxc.rootfs.path = dir:" + filepath.Join(r.lxcpath(), name, "rootfs")
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "lxc.rootfs.path"):
			lines[i] = rootfsLine
		case strings.HasPrefix(t, "lxc.uts.name"):
			lines[i] = "lxc.uts.name = " + name
		case strings.HasPrefix(t, "lxc.net.") && strings.Contains(t, ".hwaddr"):
			// Fresh, DETERMINISTIC MAC keyed on the clone's name+ordinal, so the
			// on-disk config matches the interface row the clone path records.
			if n, ok := lxcNetOrdinal(t); ok {
				lines[i] = fmt.Sprintf("lxc.net.%d.hwaddr = %s", n, corrosion.ContainerMAC(r.HostName, name, n))
			}
		case strings.HasPrefix(t, "lxc.net.") && strings.Contains(t, ".veth.pair"):
			// Re-key the host veth to the clone's deterministic name so it can't
			// collide with the source's veth on the same host (and matches the DB).
			if n, ok := lxcNetOrdinal(t); ok {
				lines[i] = fmt.Sprintf("lxc.net.%d.veth.pair = %s", n, corrosion.ContainerVethName(name, n))
			}
		case strings.HasPrefix(t, "lxc.net.") && strings.Contains(t, ".ipv4.address"):
			// Drop the source's static IP — a clone is a new workload (dynamic IP).
			lines[i] = ""
		}
	}
	if err := os.WriteFile(cfg, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return fmt.Errorf("rewrite clone config %s: %w", cfg, err)
	}
	// Best-effort in-guest identity reset (so systemd regenerates machine-id and
	// the hostname matches the clone). Missing files are fine. The rootfs is
	// guest-controlled, so every write is confined to it (writeGuestFile): a
	// guest symlink at or above these paths must never steer a root write onto
	// the host.
	rootfs := filepath.Join(r.lxcpath(), name, "rootfs")
	_ = writeGuestFile(rootfs, "etc/hostname", []byte(name+"\n"), 0o644, false)
	for _, mid := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
		// empty → regenerated on first boot
		_ = writeGuestFile(rootfs, mid, nil, 0o444, true)
	}
	return nil
}

// randomMAC returns a fresh locally-administered MAC under the QEMU OUI
// (52:54:00) — mirrors libvirt.GenerateMAC without importing that package.
func randomMAC() string {
	buf := make([]byte, 3)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", buf[0], buf[1], buf[2])
}

// lxcNetOrdinal extracts N from a "lxc.net.<N>.<key>" config line.
func lxcNetOrdinal(line string) (int, bool) {
	rest := strings.TrimPrefix(strings.TrimSpace(line), "lxc.net.")
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[:dot])
	if err != nil {
		return 0, false
	}
	return n, true
}

// rewriteRootFSPath pins the container config's lxc.rootfs.path to this host's
// <lxcpath>/<name>/rootfs after an import, so a container restored under a
// different lxcpath (or from another host) boots against the real rootfs.
func (r *LxcRunner) rewriteRootFSPath(name string) error {
	return rewriteRootFSPathAt(filepath.Join(r.lxcpath(), name), filepath.Join(r.lxcpath(), name, "rootfs"))
}

// rewriteRootFSPathAt pins the config in containerDir to rootfs.
func rewriteRootFSPathAt(containerDir, rootfs string) error {
	cfg := filepath.Join(containerDir, "config")
	data, err := os.ReadFile(cfg)
	if err != nil {
		return fmt.Errorf("read imported config %s: %w", cfg, err)
	}
	want := "lxc.rootfs.path = dir:" + rootfs
	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "lxc.rootfs.path") {
			lines[i] = want
			replaced = true
		}
	}
	if !replaced {
		lines = append([]string{want}, lines...)
	}
	if err := os.WriteFile(cfg, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return fmt.Errorf("rewrite imported config %s: %w", cfg, err)
	}
	return nil
}

// parseLxcInfoState normalises lxc-info -s -H output ("RUNNING\n",
// "STOPPED\n", "FROZEN\n") to our State enum.
func parseLxcInfoState(s string) State {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "running":
		return StateRunning
	case "stopped":
		return StateStopped
	case "starting":
		return StateStarting
	case "stopping":
		return StateStopping
	case "frozen":
		// Treat frozen as running for orchestration purposes — there's
		// nothing the scheduler should do differently.
		return StateRunning
	}
	return StateUnknown
}

// cmdErr formats a failed lxc-* invocation, folding in the captured stderr so
// the real cause (e.g. "Couldn't find a matching image") surfaces instead of a
// bare "exit status 1".
func cmdErr(bin, name string, stderr []byte, err error) error {
	if s := strings.TrimSpace(string(stderr)); s != "" {
		return fmt.Errorf("%s %s: %w: %s", bin, name, err, s)
	}
	return fmt.Errorf("%s %s: %w", bin, name, err)
}

// resolveRootfs decides whether template names a pre-extracted rootfs and, if
// so, returns the absolute path to the actual root filesystem. It returns
// ok=false for a bare template name (e.g. "busybox"), which the caller hands to
// lxc-create unchanged. A directory holding an OCI/umoci bundle (a "rootfs/"
// subdir) is descended into.
func resolveRootfs(template string) (path string, ok bool, err error) {
	abs, isPath, aerr := TemplatePath(template)
	if aerr != nil {
		return "", false, aerr
	}
	if !isPath {
		return "", false, nil
	}
	if !isDir(abs) {
		return "", false, fmt.Errorf("rootfs template %q is not an existing directory", template)
	}
	// OCI/umoci bundle: the flattened fs is in rootfs/. Only descend when abs
	// isn't itself a rootfs, so a real rootfs that happens to contain /rootfs
	// is left alone.
	if !looksLikeRootfs(abs) && isDir(filepath.Join(abs, "rootfs")) {
		abs = filepath.Join(abs, "rootfs")
	}
	if !looksLikeRootfs(abs) {
		return "", false, fmt.Errorf("rootfs template %q does not look like a root filesystem (no bin//etc//usr/…)", template)
	}
	return abs, true, nil
}

// TemplatePath says whether a create template names a host directory (a
// pre-extracted rootfs) and, if so, which one, as an absolute path — the path
// resolveRootfs would read. "rootfs:<p>", an absolute path, and "./" or "../"
// relative paths (resolved against the daemon's working directory) are paths;
// "download" and any other bare name are lxc-create template names. Nothing is
// read from disk, so a caller can judge the path before anything touches it.
func TemplatePath(template string) (path string, isPath bool, err error) {
	p := template
	explicit := false
	if strings.HasPrefix(p, "rootfs:") {
		p, explicit = strings.TrimPrefix(p, "rootfs:"), true
	}
	// Only a path-shaped value is a rootfs candidate; a bare name is a
	// template name for lxc-create.
	if !explicit && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "./") && !strings.HasPrefix(p, "../") {
		return "", false, nil
	}
	abs, aerr := filepath.Abs(p)
	if aerr != nil {
		return "", true, fmt.Errorf("resolve rootfs path %q: %w", p, aerr)
	}
	return abs, true, nil
}

// renderBaseRootfsConfig builds the non-network/non-cgroup portion of an LXC
// config for a container backed by an existing rootfs, mirroring the structure
// lxc-create's download template emits. The network and resource stanzas are
// layered on afterwards by finalizeContainerConfig (shared with the download
// path) so both creation paths apply --network and --cpu/--memory identically.
func renderBaseRootfsConfig(name, rootfs string) string {
	var b strings.Builder
	b.WriteString("# Managed by litevirt — container created from a pre-extracted rootfs.\n")
	// common.conf carries the baseline mounts/capabilities lxc-create would
	// otherwise include; reference it only if present on this host.
	if fileExists("/usr/share/lxc/config/common.conf") {
		b.WriteString("lxc.include = /usr/share/lxc/config/common.conf\n")
	}
	b.WriteString("lxc.apparmor.profile = generated\n")
	b.WriteString("lxc.apparmor.allow_nesting = 1\n")
	fmt.Fprintf(&b, "lxc.rootfs.path = dir:%s\n", rootfs)
	fmt.Fprintf(&b, "lxc.uts.name = %s\n", name)
	return b.String()
}

// finalizeContainerConfig rewrites <lxcpath>/<name>/config so its network and
// cgroup stanzas reflect CreateOpts, for BOTH the download and rootfs paths.
// It strips any pre-existing `lxc.net.*` lines (the download template injects a
// default lxcbr0 NIC from /etc/lxc/default.conf) and re-renders the network from
// opts.Network — falling back to a single lxcbr0 veth when none is given — then
// appends the cgroup limits from opts.CPULimit/MemoryMiB. This is what wires
// `lv ct create --network` and `--cpu/--memory` through to the live container.
func (r *LxcRunner) finalizeContainerConfig(opts CreateOpts) error {
	path := filepath.Join(r.lxcpath(), opts.Name, "config")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read container config %s: %w", path, err)
	}
	var b strings.Builder
	var rootfs string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "lxc.net.") {
			continue // drop the existing network stanza; we re-render it below
		}
		if rest, ok := strings.CutPrefix(t, "lxc.rootfs.path"); ok {
			if _, v, found := strings.Cut(rest, "="); found {
				rootfs = strings.TrimPrefix(strings.TrimSpace(v), "dir:")
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	cfg := strings.TrimRight(b.String(), "\n") + "\n"

	netCfg, err := NetworkConfig(opts.Network)
	if err != nil {
		return fmt.Errorf("render network config: %w", err)
	}
	if netCfg == "" {
		netCfg = defaultNetConfig()
	}
	cfg += netCfg
	cfg += ResourceConfig(opts.CPULimit, opts.MemoryMiB)
	if opts.PidsMax > 0 {
		cfg += fmt.Sprintf("%s = %d\n", pidsMaxKey, opts.PidsMax)
	}
	cfg = withSecurityBlock(cfg, renderSecurityBlock(opts.Confinement, opts.IDMap, opts.IDMap != nil && r.useIDMappedMount()))

	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		return err
	}
	// Host mounts and devices, recorded as authorized and rendered (the
	// caller required the admin role; Create judged them already).
	if len(opts.Mounts) > 0 || len(opts.Devices) > 0 {
		if err := r.SetHostAccess(opts.Name, opts.Mounts, opts.Devices); err != nil {
			return err
		}
	}
	// When a static IP is requested, configure the guest's own networking too —
	// otherwise the stock image's boot-time DHCP client flushes the address LXC
	// assigned via lxc.net.*.ipv4.address.
	if rootfs != "" {
		if err := configureGuestStaticIP(rootfs, opts.Network); err != nil {
			return fmt.Errorf("configure guest static networking: %w", err)
		}
	}
	return nil
}

// configureGuestStaticIP writes the guest's /etc/network/interfaces (ifupdown,
// as used by the Alpine/Debian LXC images) when any NIC requests a static IP,
// so the guest brings the interface up static at boot instead of running a DHCP
// client that clobbers the address. No-op when no static IP is requested — the
// image's default (usually DHCP) is left untouched. Guests with no ifupdown
// (e.g. minimal OCI images) ignore the file and simply keep the address LXC
// assigned, which isn't fought by any in-guest DHCP.
func configureGuestStaticIP(rootfs string, nics []NetworkAttach) error {
	anyStatic := false
	for _, n := range nics {
		if n.IP != "" {
			anyStatic = true
		}
	}
	if !anyStatic {
		return nil
	}
	// The rootfs may come from a pulled image, so resolve every write inside it.
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll("etc/network", 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Managed by litevirt — static addressing from `lv ct create --network`.\n")
	b.WriteString("auto lo\niface lo inet loopback\n\n")
	for i, n := range nics {
		name := n.Name
		if name == "" {
			name = fmt.Sprintf("eth%d", i)
		}
		fmt.Fprintf(&b, "auto %s\n", name)
		if n.IP == "" {
			fmt.Fprintf(&b, "iface %s inet dhcp\n\n", name)
			continue
		}
		addr, netmask := splitCIDR(n.IP)
		fmt.Fprintf(&b, "iface %s inet static\n    address %s\n", name, addr)
		if netmask != "" {
			fmt.Fprintf(&b, "    netmask %s\n", netmask)
		}
		if n.Gateway != "" {
			fmt.Fprintf(&b, "    gateway %s\n", n.Gateway)
		}
		b.WriteString("\n")
	}
	return writeRootFile(root, "etc/network/interfaces", []byte(b.String()), 0o644, false)
}

// splitCIDR turns "10.0.3.5/24" into ("10.0.3.5", "255.255.255.0") for
// busybox/ifupdown, which wants address and netmask separately. A bare IP
// (no prefix) returns an empty netmask.
func splitCIDR(s string) (addr, netmask string) {
	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		return ip.String(), net.IP(ipnet.Mask).String()
	}
	return s, ""
}

// defaultNetConfig is the fallback NIC (a veth on the host's lxcbr0) used when
// no explicit network is requested — matching what the download template's
// default.conf provides, so a plain container still gets connectivity.
func defaultNetConfig() string {
	return "lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.net.0.flags = up\n"
}

// copyTree archive-copies src to dst with `cp -a` — preserving perms, owners,
// symlinks, and timestamps (including a umoci rootless-unpacked rootfs's ownership).
// dst MUST NOT already exist (callers ensure a fresh container dir); on failure dst
// is removed. Shared by the rootfs-template create path and CloneContainer.
func copyTree(ctx context.Context, src, dst string) error {
	cmd := exec.CommandContext(ctx, "cp", "-a", src, dst)
	stderr := strings.Builder{}
	cmd.Stderr = stringWriter{&stderr}
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(dst)
		return fmt.Errorf("cp -a %s %s: %w: %s", src, dst, err, stderr.String())
	}
	return nil
}

func isDir(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }

func fileExists(p string) bool { fi, err := os.Stat(p); return err == nil && !fi.IsDir() }

// looksLikeRootfs reports whether dir resembles a Linux root filesystem, used
// to tell an extracted rootfs from an arbitrary directory and to decide whether
// to descend into a bundle's rootfs/ subdir.
func looksLikeRootfs(dir string) bool {
	for _, d := range []string{"bin", "etc", "usr", "sbin", "lib"} {
		if isDir(filepath.Join(dir, d)) {
			return true
		}
	}
	return false
}

// stringWriter adapts a strings.Builder to io.Writer so cmd.Stderr
// can stream into it directly.
type stringWriter struct{ b *strings.Builder }

func (w stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

// ListRunning enumerates only the containers currently running on this host
// (lxc-ls --quiet --running). Used by the watchdog ownership probe at
// shutdown, where stopped containers must not block a disarm.
func (r *LxcRunner) ListRunning(ctx context.Context) ([]string, error) {
	out, _, err := r.run(ctx, "lxc-ls", "--quiet", "--running")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			names = append(names, t)
		}
	}
	return names, nil
}

// MemoryLimit is a container's memory cap, with "no cap" carried as its own
// field rather than as a magic zero.
//
// cgroup2 accepts both "max" (unlimited) and "0" (a finite zero-byte cap), and
// a single int collapses them: a running container with a zero-byte cap was
// reported as UNCAPPED, which trips the uncapped gate and blocks new
// admission. Turning "0" into a parse error is not the alternative — it is a
// legal cgroup2 value, and rejecting it would fail closed on a valid read.
type MemoryLimit struct {
	// MiB is the cap rounded up to a whole MiB. Meaningless when Unlimited.
	MiB int
	// Unlimited is true only for cgroup2 "max" or an absent key.
	Unlimited bool
}

// Limits parses the container's config for the cgroup limits ResourceConfig
// wrote — the exact inverse of what Create emitted. An absent memory key means
// unlimited, which is why the result carries Unlimited rather than a zero.
func (r *LxcRunner) Limits(_ context.Context, name string) (int, MemoryLimit, error) {
	raw, err := os.ReadFile(filepath.Join(r.lxcpath(), name, "config"))
	if err != nil {
		return 0, MemoryLimit{Unlimited: true}, fmt.Errorf("read lxc config for %q: %w", name, err)
	}
	return parseResourceConfig(string(raw))
}

// ParseResourceConfig is parseResourceConfig for callers outside the package
// that hold a config rendering (the fleet harness's container fake).
func ParseResourceConfig(cfg string) (cpuLimit int, mem MemoryLimit, err error) {
	return parseResourceConfig(cfg)
}

// parseResourceConfig inverts ResourceConfig — but the config file is
// root-editable and cgroup2 accepts forms litevirt never writes, so the parse
// accepts the full cgroup2/lxc vocabulary rather than only its own emission:
//
//   - cpu.max: "<quota> <period>" (period defaults to 100000 when absent, the
//     cgroup2 default; litevirt writes N cores as N*100000 over 100000, so the
//     limit is quota/period cores, rounded up — a hand-written period keeps the
//     same ratio instead of silently mis-scaling), or "max" = unlimited;
//   - memory.max: litevirt's "<MiB>M", any K/M/G/T-suffixed size, "max" =
//     unlimited, or a BARE INTEGER — which is BYTES, the cgroup2 native unit.
//     The old parse read bare bytes as MiB, turning a hand-written 256 MiB cap
//     into a 268435456 MiB charge (conservative, but absurd), and failed the
//     whole parse on "max" instead of reading it as unlimited.
//
// Byte figures round UP to MiB: a cap is a cap, and a charge may not
// undercount it. Genuinely unparseable values still error loudly.
func parseResourceConfig(cfg string) (cpuLimit int, mem MemoryLimit, err error) {
	// An absent memory.max key is unlimited, so that is the starting value.
	mem = MemoryLimit{Unlimited: true}
	for _, line := range strings.Split(cfg, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "lxc.cgroup2.cpu.max":
			quotaStr, periodStr, hasPeriod := strings.Cut(val, " ")
			quotaStr = strings.TrimSpace(quotaStr)
			// The period is validated BEFORE the quota is even looked at, so
			// "max 0" is rejected like "25000 0". The period is part of whether
			// the line is a valid cpu.max at all; returning early on "max" left
			// a malformed period reading as "no cap".
			period := int64(100000) // cgroup2 default when omitted
			if hasPeriod {
				p, perr := strconv.ParseInt(strings.TrimSpace(periodStr), 10, 64)
				if perr != nil {
					return 0, MemoryLimit{Unlimited: true}, fmt.Errorf("unparseable cpu.max period %q: %w", val, perr)
				}
				if p <= 0 {
					return 0, MemoryLimit{Unlimited: true}, fmt.Errorf("non-positive cpu.max period %q", val)
				}
				period = p
			}
			if quotaStr == "max" {
				cpuLimit = 0 // cgroup2 unlimited
				continue
			}
			quota, perr := strconv.ParseInt(quotaStr, 10, 64)
			if perr != nil {
				return 0, MemoryLimit{Unlimited: true}, fmt.Errorf("unparseable cpu.max %q: %w", val, perr)
			}
			// Zero is rejected with the negatives, not admitted with the
			// positives: the kernel enforces a minimum bandwidth and never
			// accepts a zero quota, and dividing it down would land on 0 — the
			// codebase's UNLIMITED sentinel — turning the most restrictive
			// conceivable cap into no cap at all.
			if quota <= 0 {
				return 0, MemoryLimit{Unlimited: true}, fmt.Errorf("non-positive cpu.max quota %q", val)
			}
			// quota/period is the cap in cores (ResourceConfig writes N cores
			// as N*period over period); the general inversion holds for any
			// period. Round UP, symmetric with the memory round-up: a positive
			// cap must never truncate to 0, which the codebase reads as
			// UNLIMITED — half a core, or a config written before cpu meant
			// cores (2000/100000, 2% of a core), reads as 1. Taken by remainder,
			// so no intermediate can overflow for any admitted pair.
			lim := quota / period
			if quota%period != 0 {
				lim++
			}
			// Finally bound the result to what an int holds on every platform,
			// so a 32-bit build cannot truncate a huge limit back down into a
			// small — or zero — one.
			if lim > math.MaxInt32 {
				return 0, MemoryLimit{Unlimited: true}, fmt.Errorf("cpu.max %q yields an unrepresentable limit", val)
			}
			cpuLimit = int(lim)
		case "lxc.cgroup2.memory.max":
			m, perr := parseMemoryMax(val)
			if perr != nil {
				return 0, MemoryLimit{Unlimited: true}, fmt.Errorf("unparseable memory.max %q: %w", val, perr)
			}
			mem = m
		}
	}
	return cpuLimit, mem, nil
}

// parseMemoryMax reads a cgroup2/lxc memory limit: "max" = unlimited, a
// K/M/G/T suffix (either case) scales, and a bare integer is BYTES — the
// cgroup2 native unit. Byte figures round up to a whole MiB, and a negative
// value or a size that overflows int64 errors loudly.
func parseMemoryMax(val string) (MemoryLimit, error) {
	if val == "max" {
		return MemoryLimit{Unlimited: true}, nil
	}
	mult, digits := int64(1), val // bytes per unit
	if n := len(val); n > 0 {
		switch val[n-1] {
		case 'K', 'k':
			mult, digits = 1<<10, val[:n-1]
		case 'M', 'm':
			mult, digits = 1<<20, val[:n-1]
		case 'G', 'g':
			mult, digits = 1<<30, val[:n-1]
		case 'T', 't':
			mult, digits = 1<<40, val[:n-1]
		}
	}
	n, err := strconv.Atoi(strings.TrimSpace(digits))
	if err != nil {
		return MemoryLimit{Unlimited: true}, err
	}
	if n < 0 {
		return MemoryLimit{Unlimited: true}, fmt.Errorf("negative memory limit %q", val)
	}
	bytes := int64(n)
	if bytes > math.MaxInt64/mult {
		return MemoryLimit{Unlimited: true}, fmt.Errorf("memory limit %q too large", val)
	}
	bytes *= mult
	if bytes > math.MaxInt64-((1<<20)-1) {
		return MemoryLimit{Unlimited: true}, fmt.Errorf("memory limit %q too large", val)
	}
	// Unlimited is decided by the literal "max" alone, checked at the top.
	// Anything that parsed as a number is a FINITE cap, including zero: a
	// zero-byte cap is a legal cgroup2 value and the most restrictive one
	// there is, so reading it as "no cap" inverts its meaning exactly.
	return MemoryLimit{MiB: int((bytes + (1 << 20) - 1) >> 20)}, nil
}

// shiftNewRootfs moves a new unprivileged container's rootfs (owned by host
// ids, as copied or as lxc-create wrote it) into its range, unless an
// idmapped mount maps it. The config already carries the mapping.
func (r *LxcRunner) shiftNewRootfs(opts CreateOpts) error {
	if opts.IDMap == nil {
		return nil
	}
	if err := r.ensureRootSubIDs(opts.IDMap); err != nil {
		return err
	}
	if r.useIDMappedMount() {
		return nil
	}
	rootfs, err := r.RootFSPath(opts.Name)
	if err != nil {
		return err
	}
	if err := shiftTree(rootfs, nil, opts.IDMap); err != nil {
		return fmt.Errorf("shift %s into ids %d-%d: %w", rootfs, opts.IDMap.Base, opts.IDMap.Base+opts.IDMap.Size-1, err)
	}
	return nil
}

// securityDiffers reports whether sec is not what `to` asks for.
func securityDiffers(sec Security, to ConvertOpts) bool {
	if to.IDMap != nil && (sec.IDMap == nil || sec.IDMap.Base != to.IDMap.Base) {
		return true
	}
	return to.Confinement != "" && to.Confinement != sec.Confinement
}

// tarSortsByName reports whether this host's tar is GNU tar 1.28 or later,
// which has --sort=name. Asked once.
var tarSortsByName = sync.OnceValue(func() bool {
	out, err := exec.Command("tar", "--version").Output()
	return err == nil && gnuTarAtLeast(string(out), 1, 28)
})

// gnuTarAtLeast parses `tar --version` ("tar (GNU tar) 1.34") and reports
// whether it is GNU tar major.minor or later.
func gnuTarAtLeast(version string, major, minor int) bool {
	first, _, _ := strings.Cut(version, "\n")
	if !strings.Contains(first, "GNU tar") {
		return false
	}
	f := strings.Fields(first)
	parts := strings.Split(f[len(f)-1], ".")
	if len(parts) < 2 {
		return false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > major || (maj == major && min >= minor)
}

// sortedMemberList is every path under <lxcpath>/<name>, the directory itself
// first, relative to lxcpath, NUL-separated, in the order GNU tar's
// --sort=name archives them (each directory's entries by name, depth first).
func sortedMemberList(lxcpath, name string) ([]byte, error) {
	var buf bytes.Buffer
	err := filepath.WalkDir(filepath.Join(lxcpath, name), func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(lxcpath, p)
		if rerr != nil {
			return rerr
		}
		buf.WriteString(rel)
		buf.WriteByte(0)
		return nil
	})
	return buf.Bytes(), err
}

// SanitizeImportedDir strips an imported container directory's config to
// what an imported config may keep and removes its host-access record.
func SanitizeImportedDir(dir string) error {
	cfgPath := filepath.Join(dir, "config")
	b, err := os.ReadFile(cfgPath)
	if errors.Is(err, fs.ErrNotExist) {
		b = nil // nothing to sanitize; the record still goes
	} else if err != nil {
		return fmt.Errorf("read imported config: %w", err)
	}
	if b == nil {
		if err := os.Remove(filepath.Join(dir, hostAccessFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	clean, dropped := sanitizeConfig(string(b), true)
	if len(dropped) > 0 {
		slog.Warn("container import: dropped config lines an imported container may not carry", "dir", filepath.Base(dir), "keys", dropped)
	}
	if err := os.WriteFile(cfgPath, []byte(clean), 0o644); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, hostAccessFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// pinnedCopyKeep is how long a pinned copy (stagePinnedCopy) is kept across
// a daemon restart for the recreate that took it; the next fetch of the
// name, or a create of it, removes it sooner.
const pinnedCopyKeep = 24 * time.Hour

// pinnedSignature is what a pinned copy's fetchedImageFile holds.
func pinnedSignature(opts CreateOpts) string {
	want := "=" + opts.PinnedGen
	if opts.PinAnyGen {
		want = "*"
	}
	return "pinned\x00" + opts.Template + "\x00" + want
}

// pinnedGenFile, in a pinned copy's stage, is the generation copied.
const pinnedGenFile = ".litevirt+gen"

// isPinnedCopy reports whether stage holds a pinned copy written within
// keep.
func isPinnedCopy(stage string, keep time.Duration) bool {
	sig := filepath.Join(stage, fetchedImageFile)
	b, err := os.ReadFile(sig)
	if err != nil || !strings.HasPrefix(string(b), "pinned\x00") {
		return false
	}
	fi, err := os.Stat(sig)
	return err == nil && time.Since(fi.ModTime()) <= keep && time.Until(fi.ModTime()) <= time.Minute
}

// stagePinnedCopy copies rootfs, which must be generation opts.PinnedGen of
// its item (the caller holds the item's lock), aside for opts.Name, so the
// create is built from it whatever becomes of the item (CreateOpts.Pinned).
// A copy already there for the same image and generation is kept, and
// marked as taken now.
func (r *LxcRunner) stagePinnedCopy(ctx context.Context, opts CreateOpts, rootfs string) error {
	gen := ReadImageGen(BundleDir(rootfs))
	if !opts.PinAnyGen && gen != opts.PinnedGen {
		return fmt.Errorf("fetch %s for %q: %w (generation %q, pinned %q)", opts.Template, opts.Name, ErrImageReplaced, gen, opts.PinnedGen)
	}
	if opts.CheckItem != nil {
		if err := opts.CheckItem(gen); err != nil {
			return err
		}
	}
	unlock := lockFetch(opts.Name)
	defer unlock()
	stage := r.fetchStage(opts.Name)
	sig := filepath.Join(stage, fetchedImageFile)
	if r.pinnedCopy(opts) != "" {
		if b, err := os.ReadFile(filepath.Join(stage, pinnedGenFile)); err == nil && string(b) == gen {
			now := time.Now()
			return os.Chtimes(sig, now, now)
		}
	}
	if err := clearStage(stage); err != nil {
		return fmt.Errorf("fetch image: %w", err)
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return fmt.Errorf("fetch image: %w", err)
	}
	if err := copyTree(ctx, rootfs, filepath.Join(stage, "rootfs")); err != nil {
		_ = os.RemoveAll(stage)
		return fmt.Errorf("copy %s aside for %q: %w", opts.Template, opts.Name, err)
	}
	if err := os.WriteFile(filepath.Join(stage, pinnedGenFile), []byte(gen), 0o600); err != nil {
		_ = os.RemoveAll(stage)
		return fmt.Errorf("fetch image: %w", err)
	}
	if err := os.WriteFile(sig, []byte(pinnedSignature(opts)), 0o600); err != nil {
		_ = os.RemoveAll(stage)
		return fmt.Errorf("fetch image: %w", err)
	}
	return nil
}

// pinnedCopy is the rootfs copy stagePinnedCopy took for opts, "" when
// there is none. The caller holds lockFetch(opts.Name).
//
// Only a copy taken within pinnedCopyKeep is used. A create bound to any
// generation (PinAnyGen) uses a copy of its template taken for either
// binding: the copy is the generation the member's host found and judged.
func (r *LxcRunner) pinnedCopy(opts CreateOpts) string {
	stage := r.fetchStage(opts.Name)
	if !isPinnedCopy(stage, pinnedCopyKeep) {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(stage, fetchedImageFile))
	if err != nil {
		return ""
	}
	if sig := string(b); sig != pinnedSignature(opts) &&
		!(opts.PinAnyGen && strings.HasPrefix(sig, "pinned\x00"+opts.Template+"\x00")) {
		return ""
	}
	p := filepath.Join(stage, "rootfs")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// dropPinnedCopy removes the name's pinned copy, if it holds one. The
// caller holds lockFetch(name).
func (r *LxcRunner) dropPinnedCopy(name string) {
	stage := r.fetchStage(name)
	if b, err := os.ReadFile(filepath.Join(stage, fetchedImageFile)); err == nil && strings.HasPrefix(string(b), "pinned\x00") {
		_ = os.RemoveAll(stage)
	}
}

// expirePinnedCopies removes, during the daemon's life, the pinned copies
// (stagePinnedCopy) older than pinnedCopyKeep that no recreate took: one a
// cancelled deploy left. SweepFetchDir does the same at start.
func (r *LxcRunner) expirePinnedCopies() {
	dir := filepath.Join(r.lxcpath(), fetchDirName)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		stage := filepath.Join(dir, e.Name())
		if !isPinnedCopy(stage, 100*365*24*time.Hour) || isPinnedCopy(stage, pinnedCopyKeep) {
			continue
		}
		unlock := lockFetch(e.Name())
		if isPinnedCopy(stage, 100*365*24*time.Hour) && !isPinnedCopy(stage, pinnedCopyKeep) {
			if err := clearStage(stage); err != nil {
				slog.Warn("container staging: kept an expired image copy a process may still be working in", "path", stage, "error", err)
			} else {
				slog.Info("container staging: removed an image copy no recreate took", "path", stage)
			}
		}
		unlock()
	}
}

// PinnedCopies counts the image copies recreates have taken and not yet
// used (stagePinnedCopy), and their size in bytes.
func (r *LxcRunner) PinnedCopies() (n int, bytes int64) {
	dir := filepath.Join(r.lxcpath(), fetchDirName)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, e := range ents {
		stage := filepath.Join(dir, e.Name())
		if !isPinnedCopy(stage, 100*365*24*time.Hour) {
			continue
		}
		n++
		_ = filepath.WalkDir(stage, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if fi, ierr := d.Info(); ierr == nil {
					bytes += fi.Size()
				}
			}
			return nil
		})
	}
	return n, bytes
}

// clearStage removes a stage for a new fetch, once no process works in it
// (stopWorkersIn); one that cannot be shown quiet is kept, and the fetch
// refused.
func clearStage(stage string) error {
	if _, err := os.Lstat(stage); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := stopWorkersIn(stage); err != nil {
		return fmt.Errorf("a process may still be working in %s, so it is kept: %w", stage, err)
	}
	return os.RemoveAll(stage)
}

// procChildren is the file listing pid's children; a test seam.
var procChildren = func(pid int) string { return fmt.Sprintf("/proc/%d/task/%d/children", pid, pid) }

// waitAttached calls started once process pid has a child (lxc-attach
// forks to enter the container), then waits for done; if done comes first,
// started is not called.
func waitAttached(pid int, done <-chan error, started func()) error {
	if started == nil {
		return <-done
	}
	children := procChildren(pid)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-tick.C:
			b, err := os.ReadFile(children)
			if err != nil && errors.Is(err, os.ErrNotExist) {
				if _, perr := os.Stat(fmt.Sprintf("/proc/%d", pid)); perr == nil {
					// No children file on this kernel: the attach cannot be
					// seen, so it is never reported (the caller keeps what
					// it holds for the whole exec).
					return <-done
				}
				continue
			}
			if len(strings.TrimSpace(string(b))) > 0 {
				started()
				return <-done
			}
		}
	}
}
