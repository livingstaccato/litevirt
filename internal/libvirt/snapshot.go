package libvirt

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// libvirt VIR_DOMAIN_SAVE_* flag values (not all exported as typed consts by
// this go-libvirt version, so we pin the numeric API values).
const (
	domainSaveRunning = 2 // VIR_DOMAIN_SAVE_RUNNING — restore as running
	domainSavePaused  = 4 // VIR_DOMAIN_SAVE_PAUSED  — save/restore as paused
)

// CreateSnapshot takes an external disk-only snapshot of a VM.
// External snapshots work with UEFI/pflash firmware (no qcow2 nvram required).
// Returns the allocation size (bytes) of the disk at the time of the snapshot.
func (c *Client) CreateSnapshot(domainName, snapshotName string) (int64, error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return 0, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	// Get current disk allocation before snapshot — this becomes the snapshot's size.
	allocation, _, _, _ := c.virt.DomainGetBlockInfo(dom, "vda", 0)

	xml := fmt.Sprintf(`<domainsnapshot><name>%s</name></domainsnapshot>`, snapshotName)
	flags := uint32(golibvirt.DomainSnapshotCreateDiskOnly | golibvirt.DomainSnapshotCreateAtomic)
	_, err = c.virt.DomainSnapshotCreateXML(dom, xml, flags)
	if err != nil {
		return 0, err
	}
	return int64(allocation), nil
}

// ListSnapshots returns all snapshot names for a domain.
func (c *Client) ListSnapshots(domainName string) ([]string, error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	snaps, _, err := c.virt.DomainListAllSnapshots(dom, -1, 0)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(snaps))
	for i, s := range snaps {
		names[i] = s.Name
	}
	return names, nil
}

// RevertToSnapshot reverts a domain to the named external disk-only snapshot.
//
// Libvirt does not support DomainRevertToSnapshot for external disk-only
// snapshots, so we revert manually. The disk revert RESETS the live overlay to
// a fresh empty qcow2 over its (frozen) base — it does NOT swap the domain back
// onto the base path. Swapping makes the restarted domain open the base file
// read-WRITE, which races the just-destroyed domain's read lock on that same
// base (held while the base was the overlay's backing) and fails with "Failed
// to get write lock". Keeping the domain on the overlay leaves the base opened
// read-only exactly as before — no lock conflict. (Same technique as
// RevertToLiveSnapshot, which fixed the identical class of bug.)
// restorePreDefine, when non-nil, restores firmware state (NVRAM + swtpm) from
// the snapshot's sidecar right before the domain is redefined, so reverted disks
// and firmware are a consistent set (G1).
func (c *Client) RevertToSnapshot(domainName, snapshotName string, restorePreDefine func() error) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	snap, err := c.virt.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}

	// The snapshot XML embeds the <domain> as it was at snapshot time — its disk
	// <source file/> entries are the (frozen) base paths.
	snapXML, err := c.virt.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return fmt.Errorf("get snapshot XML: %w", err)
	}
	origDisks := parseSnapshotDomainDisks(snapXML) // dev → base (frozen)
	if len(origDisks) == 0 {
		return fmt.Errorf("snapshot %q: no disk sources found in snapshot XML", snapshotName)
	}

	// Current (live) domain XML has the overlay paths the snapshot cut over to.
	domXML, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML: %w", err)
	}
	currentDisks := parseDomainDiskSources(domXML) // dev → overlay (live)

	// Each changed disk: reset overlay (live) → empty over base (frozen).
	type overlayReset struct{ overlay, base string }
	var resets []overlayReset
	for dev, base := range origDisks {
		overlay, ok := currentDisks[dev]
		if !ok || overlay == base {
			continue
		}
		resets = append(resets, overlayReset{overlay: overlay, base: base})
	}

	// Inactive XML still references the overlay paths — redefine with it
	// unchanged after the overlays are reset (no path swap).
	inactiveXML, err := c.virt.DomainGetXMLDesc(dom, golibvirt.DomainXMLInactive)
	if err != nil {
		inactiveXML = domXML
	}

	// Destroy the running domain — but skip if it's already shut off, so
	// reverting a STOPPED VM works instead of erroring "domain is not running".
	if st, _, sErr := c.virt.DomainGetState(dom, 0); sErr == nil && st != int32(golibvirt.DomainShutoff) {
		if err := c.virt.DomainDestroy(dom); err != nil {
			return fmt.Errorf("destroy domain before revert: %w", err)
		}
		for i := 0; i < 30; i++ {
			dom2, lookupErr := c.virt.DomainLookupByName(domainName)
			if lookupErr != nil {
				break
			}
			state, _, _ := c.virt.DomainGetState(dom2, 0)
			if state == int32(golibvirt.DomainShutoff) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	// Delete snapshot metadata (we manage overlay files ourselves) and undefine
	// to release virtlockd locks.
	_ = c.virt.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)
	if d, e := c.virt.DomainLookupByName(domainName); e == nil {
		_ = c.virt.DomainUndefineFlags(d, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineKeepNvram|golibvirt.DomainUndefineKeepTpm))
	}
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		if !c.DomainExists(domainName) {
			break
		}
	}
	time.Sleep(time.Second)

	// Disk revert: reset each overlay to an empty qcow2 over its frozen base.
	// All post-snapshot writes (in the old overlay) are discarded.
	for _, r := range resets {
		if err := resetOverlay(r.overlay, r.base); err != nil {
			return fmt.Errorf("reset overlay %q: %w", r.overlay, err)
		}
	}

	// Restore firmware state (NVRAM + swtpm) BEFORE redefine, so libvirt reuses
	// the snapshot-instant firmware (G1).
	if restorePreDefine != nil {
		if err := restorePreDefine(); err != nil {
			return fmt.Errorf("restore firmware state on revert: %w", err)
		}
	}

	// Redefine with the original (overlay-pointing) XML.
	if _, err := c.virt.DomainDefineXML(inactiveXML); err != nil {
		return fmt.Errorf("redefine domain after revert: %w", err)
	}

	// Re-register the snapshot metadata the undefine dropped. Without this the
	// snapshot is GONE from libvirt while still recorded in the cluster DB, so a
	// later "lv snapshot restore" fails with "no domain snapshot with matching
	// name" — permanently unrevertable. Doing it here (before the start) means
	// the snapshot survives even if the start below fails and the operator
	// retries. The overlay is freshly reset over the same base, so the recorded
	// point still holds. Best-effort.
	if redom, lerr := c.virt.DomainLookupByName(domainName); lerr == nil {
		_, _ = c.virt.DomainSnapshotCreateXML(redom, snapXML, uint32(golibvirt.DomainSnapshotCreateRedefine))
	}

	// Start, retrying on any residual lock-release race (the base stays
	// read-only now, so this should not normally trigger).
	var startErr error
	for i := 0; i < 10; i++ {
		if startErr = c.StartDomain(domainName); startErr == nil {
			return nil
		}
		if !strings.Contains(startErr.Error(), "lock") {
			return fmt.Errorf("start domain %s after revert: %w", domainName, startErr)
		}
		if d, e := c.virt.DomainLookupByName(domainName); e == nil {
			_ = c.virt.DomainDestroy(d) // drop any partial lock; keeps the definition
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("start domain %s after revert (disk lock not released after retries): %w", domainName, startErr)
}

// FlattenSnapshot deletes the snapshot's libvirt metadata, then merges each
// disk's active layer down into bases[dev], and returns, per disk whose
// persistent definition names its base, the layers the domain no longer
// uses — for the caller to remove once its own record names the base too. bases names, per disk, the layer to merge into, as the
// disk's chain spells it: the caller (grpcapi) picks it within the VM's own
// snapshot layers, so nothing another chain reads is written or removed; a
// disk not in bases is left as it is.
//
//   - running: an active-layer block-commit bounded at the base, then a
//     pivot onto it (qemu writes; nothing else opens the files);
//   - shut off: qemu-img commit into the base, then the persistent
//     definition is repointed at it.
//
// Order. Every base is judged first (in the disk's chain, every layer above
// it plain qcow2); nothing is written when one is not. The metadata goes
// next, before any byte of the frozen layer changes: a revert can never
// reach a snapshot whose frozen layer holds later data. A disk's layers are
// given up only once the persistent definition names its base — repointed
// here when the pivot left it on a merged layer (settleMerges); when that
// fails they are kept and marked, so a start booting them refuses.
//
// Any other state is an error before anything is written. A failure after
// the metadata delete returns the error and gives up nothing: each disk
// still reads its current data, from its top or (pivoted) its base.
func (c *Client) FlattenSnapshot(domainName, snapshotName string, bases map[string]string) (map[string][]string, error) {
	return flattenSnapshot(c.virt, domainName, snapshotName, bases)
}

// flattenAPI is the part of libvirt flattenSnapshot uses.
type flattenAPI interface {
	snapshotMetadataAPI
	DomainGetState(dom golibvirt.Domain, flags uint32) (int32, int32, error)
	DomainGetXMLDesc(dom golibvirt.Domain, flags golibvirt.DomainXMLFlags) (string, error)
	DomainBlockCommit(dom golibvirt.Domain, disk string, base, top golibvirt.OptString, bandwidth uint64, flags golibvirt.DomainBlockCommitFlags) error
	DomainGetBlockJobInfo(dom golibvirt.Domain, path string, flags uint32) (int32, int32, uint64, uint64, uint64, error)
	DomainBlockJobAbort(dom golibvirt.Domain, path string, flags golibvirt.DomainBlockJobAbortFlags) error
	DomainDefineXML(xml string) (golibvirt.Domain, error)
}

func flattenSnapshot(v flattenAPI, domainName, snapshotName string, bases map[string]string) (map[string][]string, error) {
	dom, err := v.DomainLookupByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	st, _, sErr := v.DomainGetState(dom, 0)
	if sErr != nil {
		return nil, fmt.Errorf("domain state: %w", sErr)
	}
	running := st == int32(golibvirt.DomainRunning)
	if !running && st != int32(golibvirt.DomainShutoff) {
		return nil, fmt.Errorf("flatten requires a running or shut-off domain")
	}
	flags := golibvirt.DomainXMLFlags(0)
	if !running {
		// Secure: the redefinition must keep the graphics password.
		flags = golibvirt.DomainXMLInactive | golibvirt.DomainXMLSecure
	}
	domXML, err := v.DomainGetXMLDesc(dom, flags)
	if err != nil {
		return nil, fmt.Errorf("get domain XML: %w", err)
	}
	cur := parseDomainDiskSources(domXML) // dev → active layer

	var merges []mergedDisk
	for dev, base := range bases {
		top, ok := cur[dev]
		if !ok {
			return nil, fmt.Errorf("disk %s is not in the domain", dev)
		}
		if resolvedPath(top) == resolvedPath(base) {
			continue
		}
		// Judged before anything is written: base must be in this chain.
		above, err := layersAbove(top, base)
		if err != nil {
			return nil, fmt.Errorf("disk %s: %w", dev, err)
		}
		merges = append(merges, mergedDisk{dev: dev, top: top, base: base, above: above})
	}

	// The metadata first (review M-3). A snapshot already gone is fine.
	if snap, err := v.DomainSnapshotLookupByName(dom, snapshotName, 0); err == nil {
		if err := v.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly); err != nil {
			return nil, fmt.Errorf("delete snapshot %q metadata: %w", snapshotName, err)
		}
	} else if !IsNotFound(err) {
		return nil, fmt.Errorf("snapshot %q: %w", snapshotName, err)
	}

	if running {
		for i, m := range merges {
			// Active-layer commit bounded at the base: layers under it (a
			// shared image, another VM's disk) are untouched.
			err := v.DomainBlockCommit(dom, m.dev,
				golibvirt.OptString{m.base}, golibvirt.OptString{}, 0,
				golibvirt.DomainBlockCommitActive)
			if err == nil {
				if err = waitBlockJobReady(v, dom, m.dev); err != nil {
					err = fmt.Errorf("sync: %w", err)
				}
			}
			if err == nil {
				if err = v.DomainBlockJobAbort(dom, m.dev, golibvirt.DomainBlockJobAbortPivot); err != nil {
					err = fmt.Errorf("pivot onto base: %w", err)
				}
			}
			if err != nil {
				// The disks already pivoted run on their bases: their
				// persistent definition must say so too, or a cold start
				// boots stale data. Nothing is given up.
				settleMerges(v, dom, domainName, merges[:i])
				return nil, fmt.Errorf("block-commit %s: %w", m.dev, err)
			}
		}
	} else if len(merges) > 0 {
		newXML := domXML
		for _, m := range merges {
			if _, err := commitLayersOffline(m.top, m.base); err != nil {
				return nil, fmt.Errorf("disk %s: %w", m.dev, err)
			}
			out, changed, err := RewriteDiskSourceFile(newXML, m.dev, m.top, m.base)
			if err != nil || !changed {
				return nil, fmt.Errorf("repoint disk %s at %s (changed=%v): %v", m.dev, m.base, changed, err)
			}
			newXML = out
		}
		// The data is in each base and every top still reads the same over
		// it, so a failure here leaves a consistent (deeper) chain.
		if _, err := v.DomainDefineXML(newXML); err != nil {
			return nil, fmt.Errorf("redefine the domain on its merged disks: %w", err)
		}
	}
	if len(merges) == 0 {
		return nil, nil
	}
	return settleMerges(v, dom, domainName, merges), nil
}

// mergedDisk is one disk a flatten merged: its active layer (top) was
// committed into base, and above are the layers that held its data.
type mergedDisk struct {
	dev, top, base string
	above          []string
}

// settleMerges makes the persistent definition name each merged disk's base
// and returns, per disk it does, the layers given up (re-review 2, I-B).
//
// libvirt rewrites the persistent definition on a pivot only when its
// source and the live one match, and only logs a failed config save. A
// definition still naming a merged layer is repointed here
// (RewriteDiskSourceFile on the secure inactive XML, then DomainDefineXML)
// before anything is given up. When that cannot be done the disk's layers
// are all kept and each is marked (MergedLayerMarker): its data is now in
// base, so a start that would boot one of them must refuse, never run the
// guest on stale data.
func settleMerges(v flattenAPI, dom golibvirt.Domain, domainName string, merges []mergedDisk) map[string][]string {
	if len(merges) == 0 {
		return nil
	}
	read := func() (string, map[string]string, error) {
		x, err := v.DomainGetXMLDesc(dom, golibvirt.DomainXMLInactive|golibvirt.DomainXMLSecure)
		if err != nil {
			return "", nil, err
		}
		return x, parseDomainDiskSources(x), nil
	}
	inactive, persistent, err := read()
	if err == nil {
		newXML, repoint := inactive, false
		for _, m := range merges {
			p := persistent[m.dev]
			if resolvedPath(p) == resolvedPath(m.base) || !inLayers(p, m.above) {
				continue
			}
			out, changed, rerr := RewriteDiskSourceFile(newXML, m.dev, p, m.base)
			if rerr != nil || !changed {
				slog.Error("snapshot flatten: cannot repoint the persistent definition at the merged base",
					"vm", domainName, "disk", m.dev, "base", m.base, "persistent", p, "error", rerr)
				continue
			}
			newXML, repoint = out, true
		}
		if repoint {
			if _, derr := v.DomainDefineXML(newXML); derr != nil {
				slog.Error("snapshot flatten: redefining the domain on its merged bases failed",
					"vm", domainName, "error", derr)
			}
			inactive, persistent, err = read()
		}
	}
	if err != nil {
		slog.Error("snapshot flatten: cannot read the persistent definition — the merged layers are kept and marked",
			"vm", domainName, "error", err)
	}
	named := map[string]bool{}
	for _, src := range persistent {
		named[resolvedPath(src)] = true
	}
	out := map[string][]string{}
	for _, m := range merges {
		settled := err == nil && resolvedPath(persistent[m.dev]) == resolvedPath(m.base)
		for _, l := range m.above {
			if named[resolvedPath(l)] {
				settled = false
			}
		}
		if settled {
			out[m.dev] = m.above
			continue
		}
		slog.Error("snapshot flatten: the persistent definition does not name the merged base — its layers are kept, and a start booting them is refused",
			"vm", domainName, "disk", m.dev, "base", m.base, "persistent", persistent[m.dev], "layers", m.above)
		for _, l := range m.above {
			if werr := os.WriteFile(MergedLayerMarker(l), []byte(m.base+"\n"), 0o644); werr != nil {
				slog.Error("snapshot flatten: cannot mark a merged layer", "vm", domainName, "layer", l, "error", werr)
			}
		}
	}
	return out
}

func inLayers(p string, layers []string) bool {
	rp := resolvedPath(p)
	for _, l := range layers {
		if resolvedPath(l) == rp {
			return true
		}
	}
	return false
}

// MergedLayerMarker is the file beside a layer that says its data was merged
// into another file (its content names that file) while something may still
// name the layer: a start that would boot it is refused.
func MergedLayerMarker(layer string) string { return layer + ".lv-merged" }

// MergedInto reads layer's marker: the file its data was merged into.
func MergedInto(layer string) (string, bool) {
	b, err := os.ReadFile(MergedLayerMarker(layer))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// DomainDiskFiles is a domain XML's disks as target dev → source file.
func DomainDiskFiles(domXML string) map[string]string { return parseDomainDiskSources(domXML) }

// waitBlockJobReady polls a disk's block job until it has synced (cur >= end),
// the point at which an active-layer commit is ready to pivot. Returns when the
// job is ready or gone; errors only on a query failure or timeout.
func waitBlockJobReady(v flattenAPI, dom golibvirt.Domain, dev string) error {
	for i := 0; i < 1200; i++ { // ~10 min ceiling for large disks
		found, _, _, curr, end, err := v.DomainGetBlockJobInfo(dom, dev, 0)
		if err != nil {
			return err
		}
		if found == 0 {
			return nil // no active job (already complete)
		}
		if end > 0 && curr >= end {
			return nil // synced — ready to pivot
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("block job on %s did not reach ready state in time", dev)
}

// DeleteSnapshot removes libvirt's record of a named snapshot, and only that:
// no disk file is merged, moved or deleted. litevirt's snapshots are
// external and litevirt manages their files itself (FlattenSnapshot, the
// reverts' overlay resets), deleting libvirt's record metadata-only as here.
//
// Never let libvirt delete an external snapshot's files. libvirt >= 9 does,
// and decides how by its own current/parent bookkeeping, which litevirt's
// reverts do not keep (they undefine the domain and re-register the snapshot
// without them): a snapshot it judges a "leaf non-active" one has the disk
// its embedded domain was on UNLINKED — the snapshot's base, under every
// later layer of the VM — and a current one is block-committed and its
// overlay unlinked, though a linked clone may back on it (lab-recheck-5,
// lines 81 and 82: a VM and a linked clone left without their disks).
func (c *Client) DeleteSnapshot(domainName, snapshotName string) error {
	return deleteSnapshotMetadata(c.virt, domainName, snapshotName)
}

// snapshotMetadataAPI is the part of libvirt deleteSnapshotMetadata uses.
type snapshotMetadataAPI interface {
	DomainLookupByName(name string) (golibvirt.Domain, error)
	DomainSnapshotLookupByName(dom golibvirt.Domain, name string, flags uint32) (golibvirt.DomainSnapshot, error)
	DomainSnapshotDelete(snap golibvirt.DomainSnapshot, flags golibvirt.DomainSnapshotDeleteFlags) error
}

func deleteSnapshotMetadata(v snapshotMetadataAPI, domainName, snapshotName string) error {
	dom, err := v.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	snap, err := v.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}

	return v.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)
}

// CreateLiveSnapshot captures both the guest's disks AND its RAM/CPU state at a
// single instant, leaving the VM running. The saved RAM image is written to
// vmstatePath; a later RevertToLiveSnapshot restores both disk and RAM to this
// exact point. Returns (disk allocation bytes, vmstate file bytes).
//
// Sequence (the suspend is the single freeze point, so disk and RAM are the
// same instant):
//  1. suspend the guest
//  2. external disk-only snapshot of the frozen guest (overlay cutover)
//  3. save RAM to vmstatePath (libvirt stops the domain when the save finishes)
//  4. restore from that image as running — the VM resumes with its exact RAM,
//     now writing to the post-snapshot overlay
//
// The VM is unavailable only for the suspend→save→restore window (seconds for
// small guests); it does NOT reboot. Memory snapshots are not compatible with a
// stopped VM — callers must fall back to CreateSnapshot for that case.
// captureSuspended, when non-nil, is invoked while the guest is frozen (disks
// snapshotted, guest paused) so firmware state (NVRAM + swtpm) is captured at the
// SAME instant as the disk+RAM snapshot — see CreateLiveSnapshot (G1).
func (c *Client) CreateLiveSnapshot(domainName, snapshotName, vmstatePath string, captureSuspended func() error) (diskBytes, vmstateBytes int64, err error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	state, _, _ := c.virt.DomainGetState(dom, 0)
	if state == int32(golibvirt.DomainPaused) {
		// The capture ends by resuming the guest. A paused domain is paused by
		// someone — an operator, or this host's partition pause, which must
		// keep it stopped — so a memory snapshot of it is refused rather than
		// resuming it behind their back (docs/design/partition-pause.md §3.3).
		return 0, 0, fmt.Errorf("domain %q is paused — a memory snapshot would resume it; resume it first", domainName)
	}
	if state != int32(golibvirt.DomainRunning) {
		return 0, 0, fmt.Errorf("domain %q is not running — memory snapshot requires a running VM", domainName)
	}

	// 1. Freeze point.
	if err := c.virt.DomainSuspend(dom); err != nil {
		return 0, 0, fmt.Errorf("suspend domain %q: %w", domainName, err)
	}
	resumed := false
	// On any early error, best-effort resume so we don't leave the guest paused.
	defer func() {
		if !resumed {
			_ = c.virt.DomainResume(dom)
		}
	}()

	// 2. External disk snapshot of the frozen guest.
	snapXML := fmt.Sprintf(`<domainsnapshot><name>%s</name></domainsnapshot>`, snapshotName)
	flags := uint32(golibvirt.DomainSnapshotCreateDiskOnly | golibvirt.DomainSnapshotCreateAtomic)
	if _, err := c.virt.DomainSnapshotCreateXML(dom, snapXML, flags); err != nil {
		return 0, 0, fmt.Errorf("disk snapshot: %w", err)
	}
	allocation, _, _, _ := c.virt.DomainGetBlockInfo(dom, "vda", 0)

	// 2b. Capture firmware (NVRAM + swtpm) at this frozen instant — consistent
	// with the disk+RAM snapshot. Must be here (guest paused), not after resume.
	if captureSuspended != nil {
		if err := captureSuspended(); err != nil {
			return 0, 0, fmt.Errorf("capture firmware state: %w", err)
		}
	}

	// 3. Save RAM. This stops the (already-paused) domain and writes the full
	// domain XML (referencing the new overlay paths) into the image.
	if err := c.virt.DomainSaveFlags(dom, vmstatePath, nil, uint32(domainSavePaused)); err != nil {
		return 0, 0, fmt.Errorf("save guest memory: %w", err)
	}

	// 4. Resume from the saved image as running (disks already point at the
	// overlay, so no Dxml override is needed here).
	if err := c.restoreWithRetry(domainName, vmstatePath, ""); err != nil {
		return 0, 0, fmt.Errorf("resume from saved memory: %w", err)
	}
	resumed = true // the domain is running again; the deferred resume is a no-op

	if fi, statErr := os.Stat(vmstatePath); statErr == nil {
		vmstateBytes = fi.Size()
	}
	return int64(allocation), vmstateBytes, nil
}

// RevertToLiveSnapshot reverts disk AND RAM to a memory snapshot taken by
// CreateLiveSnapshot, leaving the VM running at the snapshot instant. All disk
// writes since the snapshot are discarded.
//
// The VM runs on an external overlay whose backing file (the base) was frozen at
// snapshot time, and the saved RAM image references that overlay path. To revert
// we RESET the overlay to empty (a fresh qcow2 over the same frozen base), then
// restore the RAM unchanged — the overlay reference stays valid and now shows
// exactly the snapshot-instant content. This avoids any disk-path rewrite (an
// earlier attempt that swapped overlay→base made qemu open the base file both
// read-write as the disk AND read-only as its own backing → write-lock
// self-deadlock).
//
// rewriteSaved, when set, judges the saved image's definition before anything
// is torn down and returns the definition to restore with (the CD-ROMs pointed
// at the files judged on this host): it is passed to the restore as its
// replacement XML and defined persistently. An error refuses the revert.
func (c *Client) RevertToLiveSnapshot(domainName, snapshotName, vmstatePath string, restorePreDefine func() error, rewriteSaved func(savedXML string) (string, error)) error {
	// Pre-flight: never start tearing the VM down if the RAM image is gone.
	if _, err := os.Stat(vmstatePath); err != nil {
		return fmt.Errorf("vmstate image %q missing — cannot restore memory snapshot: %w", vmstatePath, err)
	}

	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	snap, err := c.virt.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}
	snapXML, err := c.virt.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return fmt.Errorf("get snapshot XML: %w", err)
	}
	origDisks := parseSnapshotDomainDisks(snapXML)
	if len(origDisks) == 0 {
		return fmt.Errorf("snapshot %q: no disk sources found in snapshot XML", snapshotName)
	}
	domXML, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML: %w", err)
	}
	currentDisks := parseDomainDiskSources(domXML)

	// Each changed disk: overlay (live) → base (frozen at snapshot). We reset the
	// overlay to a fresh empty qcow2 backed by the base.
	type overlayReset struct{ overlay, base string }
	var resets []overlayReset
	for dev, base := range origDisks {
		overlay, ok := currentDisks[dev]
		if !ok || overlay == base {
			continue
		}
		resets = append(resets, overlayReset{overlay: overlay, base: base})
	}

	// The saved image's domain XML references the overlay paths — keep it as-is
	// for the persistent redefine after restore.
	savedXML, err := c.virt.DomainSaveImageGetXMLDesc(vmstatePath, 0)
	if err != nil {
		return fmt.Errorf("read saved image XML: %w", err)
	}
	restoreXML := ""
	if rewriteSaved != nil {
		// Secure: the replacement must keep the graphics password the saved
		// image carries.
		secure, err := c.virt.DomainSaveImageGetXMLDesc(vmstatePath, uint32(golibvirt.DomainSaveImageXMLSecure))
		if err != nil {
			return fmt.Errorf("read saved image XML: %w", err)
		}
		rewritten, err := rewriteSaved(secure)
		if err != nil {
			return err
		}
		if rewritten != secure {
			restoreXML, savedXML = rewritten, rewritten
		}
	}

	// Destroy the running domain and wait for shutoff.
	if err := c.virt.DomainDestroy(dom); err != nil {
		return fmt.Errorf("destroy domain before revert: %w", err)
	}
	for i := 0; i < 30; i++ {
		dom2, lookupErr := c.virt.DomainLookupByName(domainName)
		if lookupErr != nil {
			break
		}
		st, _, _ := c.virt.DomainGetState(dom2, 0)
		if st == int32(golibvirt.DomainShutoff) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Delete snapshot metadata (we manage the overlay files ourselves).
	_ = c.virt.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)

	// Undefine to release virtlockd locks (mirrors the disk-only revert).
	dom, _ = c.virt.DomainLookupByName(domainName)
	_ = c.virt.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineKeepNvram|golibvirt.DomainUndefineKeepTpm))
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		if !c.DomainExists(domainName) {
			break
		}
	}
	time.Sleep(time.Second)

	// Reset each overlay to empty over its (frozen) base — this is the disk
	// revert: all post-snapshot writes (in the old overlay) are discarded.
	for _, r := range resets {
		if err := resetOverlay(r.overlay, r.base); err != nil {
			return fmt.Errorf("reset overlay %q: %w", r.overlay, err)
		}
	}

	// Restore firmware (NVRAM + swtpm) to the snapshot instant BEFORE bringing the
	// guest back, so it resumes against the consistent firmware (G1).
	if restorePreDefine != nil {
		if err := restorePreDefine(); err != nil {
			return fmt.Errorf("restore firmware state on revert: %w", err)
		}
	}

	// Restore the VM running from the snapshot-instant RAM. The saved XML's disk
	// references (the overlays) are valid and now empty, so no Dxml override is
	// needed for them; the chain is overlay→base→image with no file opened
	// twice. Its CD-ROMs are the files judged here (rewriteSaved), when they
	// differ.
	if err := c.restoreWithRetry(domainName, vmstatePath, restoreXML); err != nil {
		return fmt.Errorf("restore guest memory: %w", err)
	}
	if _, err := c.virt.DomainDefineXML(savedXML); err != nil {
		// Running instance is fine; it just isn't persistent yet. Surface it so
		// the operator knows a stop would lose the definition.
		return fmt.Errorf("revert restored the running VM but re-defining it persistently failed: %w", err)
	}

	// The undefine above dropped the libvirt snapshot metadata. Re-register it
	// (best-effort) so the snapshot stays revertible AND deletable — the overlay
	// is freshly reset over the same base, so the recorded snapshot point still
	// holds. A failure here is non-fatal: the revert already succeeded.
	if redom, lerr := c.virt.DomainLookupByName(domainName); lerr == nil {
		_, _ = c.virt.DomainSnapshotCreateXML(redom, snapXML, uint32(golibvirt.DomainSnapshotCreateRedefine))
	}
	return nil
}

// resetOverlay recreates overlay as a fresh, empty qcow2 backed by base,
// discarding any prior contents. Used by the live-snapshot revert to roll a
// disk back to its frozen base without touching the base itself.
//
// qemu-img create opens base (to read its size) with the format NAMED (-F
// qcow2), never probed. base is the snapshot's frozen disk, written by qemu;
// its header is still checked for an external data file first, which qemu
// would open with it.
func resetOverlay(overlay, base string) error {
	if err := qcow2.AssertNoExternalData(base); err != nil {
		return fmt.Errorf("snapshot base %s: %w", base, err)
	}
	_ = os.Remove(overlay)
	cmd := exec.Command("qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, overlay)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// restoreWithRetry calls DomainRestoreFlags (as running) retrying on virtlockd
// lock-release races, mirroring the StartDomain retry in RevertToSnapshot. When
// dxml is non-empty it is passed as the restore-time domain XML override (used
// to swap the saved image's overlay disk paths back to the originals).
//
// A restore that fails at QEMU 'cont' (disk write-lock not yet released by the
// just-destroyed domain) can leave a paused domain holding things, so between
// attempts we destroy any partial domain and wait for the lease to release —
// sanlock/lockd leases can take longer than a single second.
func (c *Client) restoreWithRetry(domainName, vmstatePath, dxml string) error {
	var dxmlOpt golibvirt.OptString
	if dxml != "" {
		dxmlOpt = golibvirt.OptString{dxml}
	}
	// Restore PAUSED first so qemu opens the disks and acquires their write
	// locks before we resume the CPU. Restoring with the RUNNING flag does the
	// 'cont' as part of the same call, which races the just-destroyed domain's
	// lock release and fails with "Failed to get write lock". Splitting the
	// resume into a separate, retried DomainResume lets the lease settle.
	var err error
	for i := 0; i < 8; i++ {
		err = c.virt.DomainRestoreFlags(vmstatePath, dxmlOpt, uint32(domainSavePaused))
		if err == nil {
			break
		}
		msg := err.Error()
		if !strings.Contains(msg, "lock") && !strings.Contains(msg, "already") {
			return err
		}
		c.forceRemoveDomain(domainName) // clear any partial domain holding the lock
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return err
	}
	// The domain is restored and paused, holding its disk locks. Resume the CPU.
	dom, lerr := c.virt.DomainLookupByName(domainName)
	if lerr != nil {
		return fmt.Errorf("lookup restored domain: %w", lerr)
	}
	for i := 0; i < 6; i++ {
		if err = c.virt.DomainResume(dom); err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "lock") {
			return err
		}
		time.Sleep(time.Second)
	}
	return err
}

// forceRemoveDomain destroys (if up) and undefines (if defined) a domain so a
// subsequent restore starts from a clean slate and the disk lease is released.
func (c *Client) forceRemoveDomain(domainName string) {
	d, e := c.virt.DomainLookupByName(domainName)
	if e != nil {
		return
	}
	_ = c.virt.DomainDestroy(d) // no-op/err if already shut off
	if d2, e2 := c.virt.DomainLookupByName(domainName); e2 == nil {
		_ = c.virt.DomainUndefineFlags(d2, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineKeepNvram|golibvirt.DomainUndefineKeepTpm))
	}
}

// parseSnapshotDomainDisks extracts the original disk paths from the <domain>
// element embedded in a snapshot's XML. Returns a map of target dev → file path.
func parseSnapshotDomainDisks(snapXML string) map[string]string {
	var snap struct {
		Domain struct {
			Devices struct {
				Disks []struct {
					Source struct {
						File string `xml:"file,attr"`
					} `xml:"source"`
					Target struct {
						Dev string `xml:"dev,attr"`
					} `xml:"target"`
				} `xml:"disk"`
			} `xml:"devices"`
		} `xml:"domain"`
	}
	if err := xml.Unmarshal([]byte(snapXML), &snap); err != nil {
		return nil
	}
	m := make(map[string]string)
	for _, d := range snap.Domain.Devices.Disks {
		if d.Target.Dev != "" && d.Source.File != "" {
			m[d.Target.Dev] = d.Source.File
		}
	}
	return m
}

// DomainDiskSources returns the live domain's disk sources as target-dev →
// source-file. Used to reconcile litevirt's recorded vm_disks.path after a
// snapshot op cuts the domain over to an overlay. Method form so callers can go
// through grpcapi.LibvirtBackend (and the fake can stub it).
func (c *Client) DomainDiskSources(domainName string) (map[string]string, error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	xmlStr, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return nil, fmt.Errorf("get domain XML %q: %w", domainName, err)
	}
	return parseDomainDiskSources(xmlStr), nil
}

// parseDomainDiskSources extracts disk target dev → source file from domain XML.
func parseDomainDiskSources(domXML string) map[string]string {
	var domain struct {
		Devices struct {
			Disks []struct {
				Source struct {
					File string `xml:"file,attr"`
				} `xml:"source"`
				Target struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &domain); err != nil {
		return nil
	}
	m := make(map[string]string)
	for _, d := range domain.Devices.Disks {
		if d.Target.Dev != "" && d.Source.File != "" {
			m[d.Target.Dev] = d.Source.File
		}
	}
	return m
}
