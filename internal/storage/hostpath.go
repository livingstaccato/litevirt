package storage

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// A pool's configuration can name places on the host's own filesystem. The
// daemon runs as root and writes there — disk files, uploaded content, an NFS
// mount laid over the directory — so whoever chooses the path chooses where
// root writes. These helpers say which parts of a Config are such paths, and
// refuse the ones no pool may ever use.

// HostPaths is what a pool configuration names on the host itself.
type HostPaths struct {
	// WriteRoots are directories the pool creates files in, or mounts over.
	WriteRoots []string
	// ReadPaths are host files the pool's tools read (Ceph conf/keyring). A
	// config file is not inert: a ceph.conf can name a log file to write.
	ReadPaths []string
	// MountOptions is set when the config passes its own NFS mount options,
	// which reach mount(8) verbatim.
	MountOptions bool
	// HostStorage names host block storage a pool allocates from: a zfs
	// dataset, or an LVM volume group and thin pool. Naming the host's root
	// pool or another tenant's VG lets a pool exhaust it.
	HostStorage string
	// Network names the remote storage a network-backed pool (nfs, ceph,
	// iscsi) attaches. Its server, not the request, decides what the daemon
	// then finds there — files, symlinks, block devices — and the daemon
	// reads and writes it as root, so attaching one is a host-level act even
	// when the pool names no local directory.
	Network string
}

// Any reports whether the configuration names anything on the host.
func (h HostPaths) Any() bool {
	return len(h.WriteRoots) > 0 || len(h.ReadPaths) > 0 || h.MountOptions || h.Network != "" || h.HostStorage != ""
}

// Describe names what was found, for an operator-facing refusal.
func (h HostPaths) Describe() string {
	var parts []string
	for _, p := range h.WriteRoots {
		parts = append(parts, fmt.Sprintf("directory %q", p))
	}
	for _, p := range h.ReadPaths {
		parts = append(parts, fmt.Sprintf("file %q", p))
	}
	if h.MountOptions {
		parts = append(parts, "custom NFS mount options")
	}
	if h.HostStorage != "" {
		parts = append(parts, fmt.Sprintf("host storage %q", h.HostStorage))
	}
	if h.Network != "" {
		parts = append(parts, fmt.Sprintf("network storage %q, whose server controls what the daemon reads and writes", h.Network))
	}
	return strings.Join(parts, ", ")
}

// HostPathsOf returns the host paths a pool configuration names. A local pool
// with no Target names none: it lives under the daemon's own data directory.
// Every network-backed pool (nfs, ceph, iscsi) names its remote storage, with
// or without a Target.
func HostPathsOf(cfg Config) HostPaths {
	var h HostPaths
	switch strings.ToLower(cfg.Driver) {
	case "", "local":
		if cfg.Target != "" {
			h.WriteRoots = append(h.WriteRoots, cfg.Target)
		}
	case "dir":
		// Target is mandatory for dir; an empty one is refused by New.
		h.WriteRoots = append(h.WriteRoots, cfg.Target)
	case "nfs":
		h.Network = cfg.Source
		if cfg.Target != "" {
			h.WriteRoots = append(h.WriteRoots, cfg.Target)
		}
		if _, ok := cfg.Options["options"]; ok {
			h.MountOptions = true
		}
	case "iscsi":
		h.Network = cfg.Source
	case "btrfs":
		h.WriteRoots = append(h.WriteRoots, cfg.Source)
	case "zfs":
		h.HostStorage = cfg.Source
	case "lvm-thin", "lvmthin":
		h.HostStorage = cfg.Source + "/" + cfg.Options["thinpool"]
	case "ceph":
		h.Network = cfg.Source
		for _, k := range []string{"conf", "keyring"} {
			if v := cfg.Options[k]; v != "" {
				h.ReadPaths = append(h.ReadPaths, v)
			}
		}
	}
	return h
}

// systemRoots are directories no pool may write into, or below. A file the
// daemon writes as root into any of them can become code execution (cron.d,
// profile.d, systemd units, ld.so.preload, authorized_keys) or can corrupt the
// host. This is a backstop, not the boundary: the boundary is that only a
// cluster-root caller may name a host path at all. It is not exhaustive —
// /opt, /var/log, /var/tmp and /srv are left to the admin who names them — and
// it is judged when the pool is created or used, not continuously: a symlink
// or bind mount made afterwards by someone with root on the host is not seen
// (EvalSymlinks does not see mounts at all). Network pools, whose server
// could otherwise plant such links, are mounted nosymfollow.
var systemRoots = []string{
	"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/libx32",
	"/proc", "/root", "/run", "/sbin", "/sys", "/usr",
	"/var/lib/libvirt", "/var/run", "/var/spool",
}

// defaultDataDir is the daemon's default data_dir (daemon/config.go). It is
// judged like the configured data directory whatever data_dir says: the
// backup session's scratch and socket directories are hardcoded under it
// (libvirt/backup_session.go), and an install that moved its data_dir may
// have left its state there. It is compared by whole path components —
// /var/lib/litevirt or /var/lib/litevirt/… — never as a string prefix, so a
// sibling such as /var/lib/litevirt-labtest is an ordinary host path.
const defaultDataDir = "/var/lib/litevirt"

// litevirtStateRoots are other directories of litevirt's own state outside
// the data directory, refused with everything in them: the gitops working
// tree's default home (gitops.go Config.LocalDir, `lv gitops --local-dir`).
var litevirtStateRoots = []string{"/var/lib/litevirt-gitops"}

// dataDirPoolAreas are the parts of the daemon's data directory a pool may
// live in: mounts/ holds the NFS mounts the daemon makes itself, and
// pools/<name> is a target-less local pool's own directory. Their roots are
// not pools: each contains every pool there.
var dataDirPoolAreas = []string{"mounts", "pools"}

// dataDirOwned are the children of the data directory that are the daemon's
// own state. No pool may be one of them, inside one, or contain one (the data
// directory itself), and no guest is given a file in one; anything else
// directly in the data directory — /var/lib/litevirt/rc5pool, a backup repo
// an admin made there — is an ordinary host path, as it was on main
// (3e4ba50b had no such check), which only storage.hostpath may name.
// disks/, pools/ and mounts/ have rules of their own (dataDirChildRefusal).
//
// The list is everything the daemon creates there, from the code;
// TestDataDirOwned_CoversEverythingTheDaemonCreates fails on a join onto the
// data directory, or a path hardcoded under /var/lib/litevirt, that it does
// not cover. It cannot see a child built inside a helper that takes the data
// directory under another parameter name (nowts.hwm, corrosion/hwm.go
// newHWMStore(dir)): those were found by sweeping every function the data
// directory is passed to, and a new one needs adding here by hand.
var dataDirOwned = []string{
	"state.db",                   // corrosion/client.go NewClient, NewLocalClient (and -wal/-shm, dataDirOwnedPrefixes)
	"pki",                        // the daemon's PKI when pki_dir is put in the data directory
	"vms",                        // health/owner_marker.go: per-VM owner-epoch markers; deleted_vm_marker_sweep.go
	"images",                     // image/store.go, imageops.go, restore_dest.go
	"imports",                    // vmimport.go: import work dirs and imports/staging (--server-path)
	"import-placements",          // vmimport_placement.go importPlacementDirName
	"iso-identity",               // iso_identity.go isoIdentityDir
	"cloudinit",                  // libvirt/xmlgen.go CloudInitISOPath; migrate.go, vm_iso.go
	"nvram",                      // libvirt/xmlgen.go NvramPath; vtpmstate.go retainedMarkerPath
	"vmstate",                    // libvirt/xmlgen.go VMStatePath (saved memory state)
	"snapfw",                     // libvirt/vtpmstate.go snapshot firmware bundles
	"oci",                        // grpcapi/containers.go OCI image cache
	"oci-owners",                 // grpcapi/container_paths.go ociOwnersDir
	"ct-idmap-ledger",            // grpcapi/container_security.go idmapLedgerFile (and its .tmp)
	"recreate-failed",            // grpcapi/vm_recreate_replaces.go: specs of failed recreates
	"kept-disks",                 // health/kept_disks.go: disks a --keep-disks delete kept, per VM
	"iscsi-lun-holds",            // grpcapi/vm_lun_hold.go lunHoldDirName: moved iSCSI LUN holds
	"containers",                 // daemon.go: the LXC container root
	"ct-snapshots",               // snapshot_container.go containerSnapshotDir
	"ct-restore",                 // backup_container.go container restore staging
	"ct-restore-markers",         // backup_container.go
	"ct-provenance",              // grpcapi/replication_container.go: container replica provenance
	"promote-markers",            // promote.go
	"restore-staging",            // peer_backup.go
	"backup-staging",             // peer_backup.go
	"backup-scratch",             // libvirt/backup_session.go sessScratchDir (hardcoded /var/lib/litevirt)
	"backup-sock",                // libvirt/backup_session.go sessSocketDir (hardcoded /var/lib/litevirt)
	"replicate-scratch",          // replication_runner.go
	"opjournal",                  // daemon.go: the operation journal
	"acme",                       // daemon/acme.go: ACME cache_dir default
	"partition-pause",            // health/partition_pause_store.go partitionPauseDir
	"operator-stops",             // health/operator_stop_marker.go operatorStopDir: operator-stop markers kept under write quarantine
	"ct-operator-stops",          // health/container_operator_stop_marker.go containerOperatorStopDir: the containers' operator-stop markers
	"settle-pending",             // health/settle_pending.go settlePendingDir: VM settles whose record is not yet written
	"onboot-boot-id",             // health/onboot_boot.go onbootBootFile (and its .tmp, dataDirOwnedPrefixes)
	"pending-audit",              // corrosion/pending_audit.go PendingAuditDirName
	"vtpm-state-sync",            // daemon.go: records that vtpm_state_sync set the swtpm tree's sync attribute
	"nvram-flush-failures.json",  // libvirt/nvramflush.go NvramFlushStateFile: this host's failed UEFI vars flushes (its temp is a dot-name)
	"image-delete-skew.json",     // grpcapi/image_delete_skew.go imageSkewHistoryFile (its temp is a dot-name; an earlier build of it left a .tmp, dataDirOwnedPrefixes)
	"audit-hold",                 // corrosion/audit_hold.go AuditHoldDirName
	"pool-trust.json",            // pooltrust/ledger.go LedgerFile: the pools this host created or confirmed (its temp is a dot-name)
	"audit-seeded.json",          // corrosion/audit_seeded.go AuditSeededFileName
	"audit-seeded-assert",        // corrosion/audit_seeded.go AuditSeededAssertFileName
	"credentials_unhydrated",     // corrosion/isolation.go credentialsUnhydratedFile
	"digest-invalidate",          // corrosion/digest_cache.go digestMarkerFile
	"host_membership_live",       // corrosion/host_membership.go hostMembershipLiveFile
	"host_runtime_live",          // corrosion/host_runtime.go hostRuntimeLiveFile
	"credentials_split_live",     // corrosion/credentials_live.go credentialsLiveFile
	"credentials_baseline",       // corrosion/credentials_live.go credentialsBaselineFile
	"credentials_external_seen",  // corrosion/credentials_live.go externalSeenFile
	"genesis-pending",            // daemon.go genesisMarkerName; host_init.go genesisMarkerScript
	"pool-uploads.json",          // storage_pool_confine.go poolUploadsFile
	"host-updates.json",          // grpcapi/host_updates.go hostUpdateCountsPath
	"file-restore",               // daemon.go fileRestoreCacheDir/fileRestoreRunDir (a non-root daemon only)
	"restart-pending",            // hostboot/hostboot.go MarkerName: a graceful stop's time, for the next boot
	"boot-awaiting-serving",      // hostboot/hostboot.go AwaitingName: a boot that awaits serving, until a daemon serves
	"boot-unclean-history",       // hostboot/hostboot.go UncleanHistoryName: the last unclean boots' times
	"nowts.hwm",                  // corrosion/hwm.go (and nowts.hwm.lock)
	"split_brain_activated",      // health/capability.go ActivationMarkerBase (markers are .<token>)
	"ceph-trash-purges.json",     // storage/ceph_trash.go cephPurgeStateFile (ResumeCephPurges(dir): set aside as .unreadable-<time>, dataDirOwnedPrefixes)
	"ceph-kept-images.json",      // grpcapi/ceph_kept.go cephKeptFile
	"kept-disks.json",            // grpcapi/disk_kept.go diskKeptFile
	"cancelled-starts.json",      // grpcapi/cancelled_starts.go cancelledStartsFile
	"firewall-log",               // daemon/firewall_log.go: the firewall log store (tenant flow records)
	"firewall-synflood-decision", // daemon.go firewallSynfloodDecisionName: the founder's SYN-flood decision
	"firewall-would-drop.json",   // daemon.go: firewall.NewWouldDropTally (its .tmp, dataDirOwnedPrefixes)
	"firewall-initial-mode",      // daemon.go firewallInitialModeName: the founder's enforcement decision
	"nic-guard-held",             // grpcapi/nic_guard_held.go heldGuestDir: guests held paused for their guards
	"promote-started",            // grpcapi/promote_serialize.go: an operator promotion's recorded start, per proof
	"shared-disk-released",       // health/shared_disk_release.go sharedReleaseDir: shared disks released for a start
	"move-unresolved",            // health/move_unresolved.go UnresolvedMoveDirName: volume moves whose config and row may disagree
	"move-started",               // health/move_started.go StartedHereDirName: the generation this host last started each VM at
	"vfio-host-drivers.json",     // vfio.HostDriversFileName (grpcapi/pci.go vfioHost): each bound device's previous host driver (its .tmp is a dot-name)
	"fwmig-inflight",             // fwmig.InflightDir: live firmware move source markers
	"fwmig-discard-owed",         // fwmig.DiscardOwedDir: owed DISCARD records
	"fwmig-hold",                 // fwmig.HoldDir: live firmware move target holds
	"fwmig-retained",             // fwmig.RetainedDir: retained firmware bundles
	"fwmig-quarantine",           // fwmig.QuarantineDir: quarantined firmware state
	"fwmig-leftover",             // fwmig.LeftoverDir: leftovers an owed DISCARD names
}

// dataDirOwnedPrefixes are owned by name prefix, each judged within one path
// component: state.db's WAL, SHM and journal (state.db-wal); one capability
// latch per token (health/capability.go ActivationMarkerPrefix,
// split_brain_activated.<token>); nowts.hwm.lock; ct-idmap-ledger.tmp;
// firewall-would-drop.json.tmp (firewall/wouldrop_tally.go); and
// every dot-name, which is how the daemon names its temp files there
// (secretfile.Write's .<name>.tmp, storage_pool_confine.go's
// .pool-uploads.json-*).
var dataDirOwnedPrefixes = []string{"state.db-", "split_brain_activated.", "nowts.hwm.", "ct-idmap-ledger.", "onboot-boot-id.", "ceph-trash-purges.json.", "firewall-would-drop.json.", "image-delete-skew.json.", "."}

// DataDirOwned returns the exact names of dataDirOwned.
func DataDirOwned() []string { return slices.Clone(dataDirOwned) }

// dataDirChildOwned reports whether name, a child of the data directory, is
// the daemon's own state.
func dataDirChildOwned(name string) bool {
	for _, o := range dataDirOwned {
		if name == o {
			return true
		}
	}
	for _, pre := range dataDirOwnedPrefixes {
		if strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}

// dataDirChild splits cand, strictly inside the data directory d, into its
// first element below d and how many elements it has there; ok is false when
// cand is not strictly inside d.
func dataDirChild(d, cand string) (first string, depth int, ok bool) {
	if !within(d, cand) || filepath.Clean(cand) == filepath.Clean(d) {
		return "", 0, false
	}
	rel, err := filepath.Rel(d, cand)
	if err != nil {
		return "", 0, false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	return parts[0], len(parts), true
}

// dataDirChildRefusal judges a pool directory cand strictly inside the data
// directory d: <data_dir>/disks itself and a directory under pools/ or
// mounts/ are the daemon's pool areas; anything else in disks/, an area's
// root, and the daemon's own state (dataDirOwned) are refused; any other
// child is an ordinary host path.
func dataDirChildRefusal(p, d, cand, dataDir string) error {
	first, depth, ok := dataDirChild(d, cand)
	if !ok {
		return nil
	}
	switch {
	case first == dataDirDisks:
		if depth == 1 {
			return nil
		}
		return fmt.Errorf("%q is inside the daemon's disks directory %s; a pool may be that directory itself, not one inside it", p, filepath.Join(dataDir, dataDirDisks))
	case slices.Contains(dataDirPoolAreas, first):
		if depth > 1 {
			return nil
		}
		return fmt.Errorf("%q is the root of the daemon's %s/ area in %s, which holds every pool there; a pool is a directory inside it", p, first, dataDir)
	case dataDirChildOwned(first):
		return fmt.Errorf("%q is the daemon's own state (%s in its data directory %s)", p, first, dataDir)
	}
	return nil
}

// dataDirDisks is <data_dir>/disks, where every VM's local disks live across
// projects and where the built-in default pool of an older cluster still is.
// A pool may be that directory exactly (not one inside it); what a caller
// sees and changes in it is confined to the files its project owns by record.
const dataDirDisks = "disks"

// IsDataDirDisks reports whether p is <data_dir>/disks, as written or after
// resolving symlinks. The resolutions are bounded (resolveBounded): a form a
// network filesystem that does not answer keeps from being resolved is
// judged as written only. A caller that confines on the answer uses
// IsDataDirDisksErr, and confines on its error.
func IsDataDirDisks(p, dataDir string) bool {
	return MountTable{}.IsDataDirDisks(p, dataDir)
}

// IsDataDirDisks is IsDataDirDisks against this table (an empty one is read
// when needed).
func (t MountTable) IsDataDirDisks(p, dataDir string) bool {
	is, _ := t.IsDataDirDisksErr(p, dataDir)
	return is
}

// IsDataDirDisksErr is IsDataDirDisks, and an error when it answered false
// without every form resolved: a resolution did not answer, so p may still
// be <data_dir>/disks through a symlink. A match on the forms that did
// resolve is still true, with no error.
func IsDataDirDisksErr(p, dataDir string) (bool, error) {
	return MountTable{}.IsDataDirDisksErr(p, dataDir)
}

// IsDataDirDisksErr is IsDataDirDisksErr against this table (an empty one is
// read when needed).
func (t MountTable) IsDataDirDisksErr(p, dataDir string) (bool, error) {
	if dataDir == "" || p == "" {
		return false, nil
	}
	if t.Empty() {
		if mt, err := ReadMountTable(); err == nil {
			t = mt
		}
	}
	dataForms, errD := pathFormsBounded(&t, dataDir)
	forms, errP := pathFormsBounded(&t, p)
	for _, d := range dataForms {
		for _, c := range forms {
			if c == filepath.Join(d, dataDirDisks) {
				return true, nil
			}
		}
	}
	if err := errors.Join(errD, errP); err != nil {
		return false, fmt.Errorf("cannot tell whether %s is %s: %w", p, filepath.Join(dataDir, dataDirDisks), err)
	}
	return false, nil
}

// CheckWriteRoot refuses a directory no pool may write into: a relative path,
// the filesystem root, anything under a system directory, the daemon's PKI
// directory, its data directory or any parent of it, and inside it the
// daemon's own state (dataDirChildRefusal); another child of the data
// directory is an ordinary host path. Symlinks
// are resolved first (through the deepest part of the path that exists), and
// both the path as written and the path it resolves to must pass, so a link
// planted at an innocent name cannot reach a refused directory.
func CheckWriteRoot(p, dataDir, pkiDir string) error {
	return MountTable{}.CheckWriteRoot(p, dataDir, pkiDir)
}

// CheckWriteRoot is CheckWriteRoot against this table (an empty one is read
// when needed).
func (t MountTable) CheckWriteRoot(p, dataDir, pkiDir string) error {
	if p == "" {
		return errors.New("an empty path names no directory")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%q is not an absolute path", p)
	}
	// Resolved under a bound (resolveBounded): a pool directory below an NFS
	// mount whose server does not answer is refused, as one that cannot be
	// checked, instead of holding the caller (lab 2 F-2).
	forms, err := pathFormsBounded(&t, p)
	if err != nil {
		return fmt.Errorf("%q cannot be checked: %w", p, err)
	}
	for _, cand := range forms {
		if cand == "/" {
			return fmt.Errorf("%q is the filesystem root", p)
		}
		for _, root := range systemRoots {
			for _, r := range pathForms(root) {
				if within(r, cand) {
					return fmt.Errorf("%q is under %s, a system directory", p, root)
				}
			}
		}
		for _, root := range litevirtStateRoots {
			for _, r := range pathForms(root) {
				if within(r, cand) {
					return fmt.Errorf("%q is under %s, litevirt state", p, root)
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
				if err := dataDirChildRefusal(p, d, cand, dd); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// CheckDaemonStatePath refuses a file path to be written that is the daemon's
// own state, whoever asks: in or below the PKI directory or a litevirt state
// root, the data directory (configured or default) or a directory containing
// it, or in or below a child of the data directory the daemon owns
// (dataDirOwned). It is the pool rule for one file (a restore or copy
// target_path): anywhere else — disks/, a pool, an ordinary child of the data
// directory, any other host path — passes. Judged by path components, as
// written and after resolving symlinks through the deepest existing parent,
// so the parent directories a write would create cannot land in daemon state
// either.
func CheckDaemonStatePath(p, dataDir, pkiDir string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%q is not an absolute path", p)
	}
	for _, cand := range pathForms(p) {
		if pkiDir != "" {
			for _, d := range pathForms(pkiDir) {
				if within(d, cand) {
					return fmt.Errorf("%q is in the daemon's PKI directory %s", p, pkiDir)
				}
			}
		}
		for _, root := range litevirtStateRoots {
			for _, r := range pathForms(root) {
				if within(r, cand) {
					return fmt.Errorf("%q is under %s, litevirt state", p, root)
				}
			}
		}
		for _, dd := range dataDirsToJudge(dataDir) {
			for _, d := range pathForms(dd) {
				if within(cand, d) {
					return fmt.Errorf("%q is the daemon's data directory %s or contains it", p, dd)
				}
				if first, _, ok := dataDirChild(d, cand); ok && dataDirChildOwned(first) {
					return fmt.Errorf("%q is the daemon's own state (%s in its data directory %s)", p, first, dd)
				}
			}
		}
	}
	return nil
}

// CheckConfig refuses a Source or option that is not in its driver's strict
// form (ValidateSource), applies CheckWriteRoot to every directory the
// configuration writes into, and refuses an NFS source that would derive a
// mount directory outside <data_dir>/mounts.
func CheckConfig(cfg Config, dataDir, pkiDir string) error {
	return MountTable{}.CheckConfig(cfg, dataDir, pkiDir)
}

// CheckConfig is CheckConfig against this table (an empty one is read when
// needed).
func (t MountTable) CheckConfig(cfg Config, dataDir, pkiDir string) error {
	if err := ValidateSource(cfg); err != nil {
		return err
	}
	for _, p := range HostPathsOf(cfg).WriteRoots {
		if err := t.CheckWriteRoot(p, dataDir, pkiDir); err != nil {
			return err
		}
	}
	if strings.EqualFold(cfg.Driver, "nfs") && cfg.Target == "" {
		switch NFSMountName(cfg.Source) {
		case "", ".", "..":
			return fmt.Errorf("nfs source %q is not server:/export", cfg.Source)
		}
	}
	return nil
}

// NFSMountName is the directory under <data_dir>/mounts that an NFS pool with
// no Target is mounted on.
func NFSMountName(source string) string {
	return strings.NewReplacer("/", "_", ":", "_").Replace(source)
}

// pathForms returns p cleaned, plus what it resolves to when that differs.
func pathForms(p string) []string {
	clean := filepath.Clean(p)
	out := []string{clean}
	if r := resolveExisting(clean); r != clean {
		out = append(out, r)
	}
	return out
}

// resolveExisting resolves symlinks through the deepest ancestor of p that
// exists and re-attaches the rest, so a path a driver is about to create is
// judged by where it would really land.
func resolveExisting(p string) string {
	cur, rest := p, ""
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return r
			}
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// within reports whether path is dir or below it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// inPoolArea reports whether p is strictly inside one of the data directory's
// pool areas. An area's root is not a pool: it contains every pool there.
func inPoolArea(dataDir, p string) bool {
	for _, a := range dataDirPoolAreas {
		area := filepath.Join(dataDir, a)
		if within(area, p) && filepath.Clean(p) != filepath.Clean(area) {
			return true
		}
	}
	return false
}

// InDataDirPoolArea reports whether p is one of the daemon's own pool
// directories: <data_dir>/disks itself, or a directory strictly inside
// <data_dir>/pools or <data_dir>/mounts. Every form of p — as written, and
// resolved through symlinks — must be one, so a link in pools/ to a directory
// elsewhere is not. The resolutions are bounded (resolveBounded): one that
// does not answer is an error, and the answer false.
func InDataDirPoolArea(p, dataDir string) (bool, error) {
	if p == "" || dataDir == "" || !filepath.IsAbs(p) {
		return false, nil
	}
	var t MountTable
	dataForms, errD := pathFormsBounded(&t, dataDir)
	forms, errP := pathFormsBounded(&t, p)
	if err := errors.Join(errD, errP); err != nil {
		return false, err
	}
	for _, c := range forms {
		ok := false
		for _, d := range dataForms {
			if c == filepath.Join(d, dataDirDisks) || inPoolArea(d, c) {
				ok = true
				break
			}
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// DirsOverlap reports whether two directories are the same, or one is inside
// the other, judged both as written and after resolving symlinks.
//
// As written first, with no system call. Then resolved, under a bound
// (resolveBounded): a mount point the mount table names is its own
// resolution, and any other path's resolution that does not finish in time —
// a symlink into, or a path below, a network mount whose server does not
// answer — is an error. An overlap found on any form is an overlap; no
// overlap is reported only when every form was resolved. A caller deciding
// whether two pools may coexist must treat the error as "cannot verify",
// never as "no overlap".
func DirsOverlap(a, b string) (bool, error) {
	return MountTable{}.DirsOverlap(a, b)
}

// DirsOverlap is DirsOverlap against this table (an empty one is read when
// needed).
func (t MountTable) DirsOverlap(a, b string) (bool, error) {
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if within(ca, cb) || within(cb, ca) {
		return true, nil
	}
	if t.Empty() {
		if mt, err := ReadMountTable(); err == nil {
			t = mt
		}
	}
	xs, errA := pathFormsBounded(&t, a)
	ys, errB := pathFormsBounded(&t, b)
	for _, x := range xs {
		for _, y := range ys {
			if within(x, y) || within(y, x) {
				return true, nil
			}
		}
	}
	if err := errors.Join(errA, errB); err != nil {
		return false, fmt.Errorf("cannot verify that %s and %s do not overlap: %w", a, b, err)
	}
	return false, nil
}

// dataDirsToJudge is the configured data directory and defaultDataDir.
func dataDirsToJudge(dataDir string) []string {
	out := []string{defaultDataDir}
	if dataDir != "" && filepath.Clean(dataDir) != defaultDataDir {
		out = append(out, dataDir)
	}
	return out
}

// The strict forms a pool's Source and identifying options must take. Each
// reaches a tool's argv (mount, rbd, zfs, lvs, iscsiadm, btrfs) as a positional
// argument or option value; a value that starts with "-" would be parsed as an
// option, which would let a caller pass the very options that need
// storage.hostpath (an alternate config, keyring or log file). The drivers
// also put "--" before positional arguments; this is the first line.
var (
	nfsSourceRe   = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\]):/[^\s,]*$`)
	cephNameRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	cephPoolRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)?$`) // pool[/namespace]
	zfsDatasetRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]*(/[A-Za-z0-9_][A-Za-z0-9_.:-]*)*$`)
	lvmNameRe     = regexp.MustCompile(`^[A-Za-z0-9_+.][A-Za-z0-9_+.-]*$`)
	iscsiTargetRe = regexp.MustCompile(`^(?i:iqn|eui|naa)\.[A-Za-z0-9.:_-]+$`)
	iscsiPortalRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$`)
)

// ValidateSource refuses a Source, or a driver option that names an object,
// that is not in its driver's strict form.
func ValidateSource(cfg Config) error {
	src := cfg.Source
	bad := func(what, v, want string) error {
		return fmt.Errorf("%s %q is not %s", what, v, want)
	}
	switch strings.ToLower(cfg.Driver) {
	case "", "local", "dir":
		if src != "" {
			return fmt.Errorf("a %s pool takes no source (got %q)", strings.ToLower(cfg.Driver), src)
		}
	case "nfs":
		if !nfsSourceRe.MatchString(src) {
			return bad("nfs source", src, "server:/export")
		}
	case "ceph":
		if !cephPoolRe.MatchString(src) {
			return bad("ceph pool", src, "a pool[/namespace] name")
		}
		if id := cfg.Options["id"]; id != "" && !cephNameRe.MatchString(id) {
			return bad("ceph id", id, "a client name")
		}
		for _, k := range []string{"conf", "keyring"} {
			if v := cfg.Options[k]; v != "" && !filepath.IsAbs(v) {
				return bad("ceph "+k, v, "an absolute path")
			}
		}
	case "zfs":
		if !zfsDatasetRe.MatchString(src) {
			return bad("zfs dataset", src, "pool/dataset")
		}
	case "btrfs":
		if !filepath.IsAbs(src) {
			return bad("btrfs source", src, "an absolute path")
		}
	case "lvm-thin", "lvmthin":
		if !lvmNameRe.MatchString(src) {
			return bad("volume group", src, "a volume group name")
		}
		if tp := cfg.Options["thinpool"]; tp != "" && !lvmNameRe.MatchString(tp) {
			return bad("thin pool", tp, "a logical volume name")
		}
	case "iscsi":
		if !iscsiTargetRe.MatchString(src) {
			return bad("iscsi target", src, "an iqn./eui./naa. name")
		}
		if pt := cfg.Options["portal"]; pt != "" && !iscsiPortalRe.MatchString(pt) {
			return bad("iscsi portal", pt, "host[:port]")
		}
	}
	return nil
}
