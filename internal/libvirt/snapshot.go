package libvirt

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

// snapshotAPI is the part of libvirt the snapshot reverts and delete use. It
// is *golibvirt.Libvirt in production; the tests run the same code against a
// model of libvirt 10.0's external-snapshot rules.
type snapshotAPI interface {
	DomainLookupByName(name string) (golibvirt.Domain, error)
	DomainGetState(dom golibvirt.Domain, flags uint32) (int32, int32, error)
	DomainGetXMLDesc(dom golibvirt.Domain, flags golibvirt.DomainXMLFlags) (string, error)
	DomainDestroy(dom golibvirt.Domain) error
	DomainUndefineFlags(dom golibvirt.Domain, flags golibvirt.DomainUndefineFlagsValues) error
	DomainDefineXML(xml string) (golibvirt.Domain, error)
	DomainCreate(dom golibvirt.Domain) error
	DomainResume(dom golibvirt.Domain) error
	DomainRestoreFlags(from string, dxml golibvirt.OptString, flags uint32) error
	DomainSaveImageGetXMLDesc(file string, flags uint32) (string, error)
	DomainSnapshotLookupByName(dom golibvirt.Domain, name string, flags uint32) (golibvirt.DomainSnapshot, error)
	DomainSnapshotGetXMLDesc(snap golibvirt.DomainSnapshot, flags uint32) (string, error)
	DomainSnapshotCreateXML(dom golibvirt.Domain, xml string, flags uint32) (golibvirt.DomainSnapshot, error)
	DomainSnapshotDelete(snap golibvirt.DomainSnapshot, flags golibvirt.DomainSnapshotDeleteFlags) error
	DomainSnapshotCurrent(dom golibvirt.Domain, flags uint32) (golibvirt.DomainSnapshot, error)
	DomainSnapshotNumChildren(snap golibvirt.DomainSnapshot, flags uint32) (int32, error)
	DomainListAllSnapshots(dom golibvirt.Domain, needResults int32, flags uint32) ([]golibvirt.DomainSnapshot, int32, error)
}

var _ snapshotAPI = (*golibvirt.Libvirt)(nil)

// How long a revert waits for an undefine to land, per poll and once after.
// Variables so the tests run without the real waits.
var (
	revertUndefinePoll   = 250 * time.Millisecond
	revertUndefineSettle = time.Second
)

func startDomain(v snapshotAPI, name string) error {
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := v.DomainCreate(dom); err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	return nil
}

func domainExists(v snapshotAPI, name string) bool {
	_, err := v.DomainLookupByName(name)
	return err == nil
}

// snapshotCreateXML is the definition a new disk-only snapshot is created
// with. libvirt names a new overlay by cutting the disk's current source at
// its last dot; when that source is the overlay of a snapshot whose name has
// a dot (vm-root.v1.2), the cut lands inside the name (vm-root.v1.s3) and
// nothing ties the file back to its disk, so it leaked on VM delete
// (snapshot-lab.md, Round 3 "4b"). For such a disk the overlay is named
// here: the disk's stem, cut by the VM's known snapshot names, then the new
// name. Every other disk is left to libvirt, as before.
func snapshotCreateXML(v snapshotAPI, dom golibvirt.Domain, snapshotName string) (string, error) {
	plain := "<domainsnapshot><name>" + xmlText(snapshotName) + "</name></domainsnapshot>"
	snaps, _, err := v.DomainListAllSnapshots(dom, -1, 0)
	if err != nil || len(snaps) == 0 {
		return plain, nil
	}
	names := make([]string, 0, len(snaps))
	for _, sn := range snaps {
		names = append(names, sn.Name)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	domXML, err := v.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return plain, nil
	}
	sources := parseDomainDiskSources(domXML)
	var disks strings.Builder
	for _, dev := range sortedDevs(sources) {
		src := sources[dev]
		stem, ok := stemByNames(src, names)
		if !ok || stem == strings.TrimSuffix(src, filepath.Ext(src)) {
			continue
		}
		fmt.Fprintf(&disks, "<disk name='%s' snapshot='external'><source file='%s'/></disk>",
			xmlAttr(dev), xmlAttr(stem+"."+snapshotName))
	}
	if disks.Len() == 0 {
		return plain, nil
	}
	return "<domainsnapshot><name>" + xmlText(snapshotName) + "</name><disks>" + disks.String() + "</disks></domainsnapshot>", nil
}

// stemByNames cuts a known snapshot's name — the longest that fits — off
// an overlay's path: <stem>.<name>, or a restore's <stem>.<name>-r<time>.
func stemByNames(p string, names []string) (string, bool) {
	dir, base := filepath.Dir(p), filepath.Base(p)
	for _, n := range names {
		if n == "" {
			continue
		}
		if stem, ok := strings.CutSuffix(base, "."+n); ok && stem != "" {
			return filepath.Join(dir, stem), true
		}
		if i := strings.LastIndex(base, "."+n+"-r"); i > 0 {
			rest := base[i+len(n)+3:]
			if rest != "" && strings.Trim(rest, "0123456789-") == "" {
				return filepath.Join(dir, base[:i]), true
			}
		}
	}
	return "", false
}

func sortedDevs(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func xmlAttr(s string) string {
	return strings.NewReplacer("'", "&#39;", `"`, "&#34;").Replace(xmlText(s))
}

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

	xml, err := snapshotCreateXML(c.virt, dom, snapshotName)
	if err != nil {
		return 0, err
	}
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
	return revertToSnapshot(c.virt, domainName, snapshotName, restorePreDefine)
}

func revertToSnapshot(v snapshotAPI, domainName, snapshotName string, restorePreDefine func() error) error {
	dom, err := v.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	snap, err := v.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}

	// The snapshot XML embeds the <domain> as it was at snapshot time — its disk
	// <source file/> entries are the (frozen) base paths.
	snapXML, err := v.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return fmt.Errorf("get snapshot XML: %w", err)
	}
	origDisks := parseSnapshotDomainDisks(snapXML) // dev → base (frozen)
	if len(origDisks) == 0 {
		return fmt.Errorf("snapshot %q: no disk sources found in snapshot XML", snapshotName)
	}

	// Current (live) domain XML has the overlay paths the snapshot cut over to.
	domXML, err := v.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML: %w", err)
	}
	currentDisks := parseDomainDiskSources(domXML) // dev → overlay (live)

	// Each changed disk: an empty overlay over its base (frozen) — the live
	// layer reset in place, or a new one when the snapshot is not the
	// newest (planRevert).
	resets, err := planRevert(snapXML, currentDisks, snapshotName)
	if err != nil {
		return fmt.Errorf("plan the revert: %w", err)
	}

	// Inactive XML still references the overlay paths — redefine with it
	// unchanged after the overlays are reset (no path swap), except a disk
	// moved to a new overlay, which is repointed there with its old
	// <backingStore> dropped: libvirt would open that chain as written.
	inactiveXML, err := v.DomainGetXMLDesc(dom, golibvirt.DomainXMLInactive)
	if err != nil {
		inactiveXML = domXML
	}
	for _, r := range resets {
		if r.target == r.live {
			continue
		}
		if inactiveXML, err = repointRevertedDisk(inactiveXML, r.dev, r.target); err != nil {
			return fmt.Errorf("revert disk %s onto %s: %w", r.dev, r.target, err)
		}
	}

	// Destroy the running domain — but skip if it's already shut off, so
	// reverting a STOPPED VM works instead of erroring "domain is not running".
	if st, _, sErr := v.DomainGetState(dom, 0); sErr == nil && st != int32(golibvirt.DomainShutoff) {
		if err := v.DomainDestroy(dom); err != nil {
			return fmt.Errorf("destroy domain before revert: %w", err)
		}
		for i := 0; i < 30; i++ {
			dom2, lookupErr := v.DomainLookupByName(domainName)
			if lookupErr != nil {
				break
			}
			state, _, _ := v.DomainGetState(dom2, 0)
			if state == int32(golibvirt.DomainShutoff) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	// Delete snapshot metadata (we manage overlay files ourselves) and undefine
	// to release virtlockd locks.
	_ = v.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)
	if d, e := v.DomainLookupByName(domainName); e == nil {
		_ = v.DomainUndefineFlags(d, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineKeepNvram|golibvirt.DomainUndefineKeepTpm))
	}
	for i := 0; i < 20; i++ {
		time.Sleep(revertUndefinePoll)
		if !domainExists(v, domainName) {
			break
		}
	}
	time.Sleep(revertUndefineSettle)

	// Disk revert: reset each overlay to an empty qcow2 over its frozen base.
	// All post-snapshot writes (in the old overlay) are discarded.
	for _, r := range resets {
		if err := resetOverlay(r.target, r.base); err != nil {
			return fmt.Errorf("reset overlay %q: %w", r.target, err)
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
	if _, err := v.DomainDefineXML(inactiveXML); err != nil {
		return fmt.Errorf("redefine domain after revert: %w", err)
	}

	// Re-register the snapshot metadata the undefine dropped. Without this the
	// snapshot is GONE from libvirt while still recorded in the cluster DB, so a
	// later "lv snapshot restore" fails with "no domain snapshot with matching
	// name" — permanently unrevertable. Doing it here (before the start) means
	// the snapshot survives even if the start below fails and the operator
	// retries. The overlay is freshly reset over the same base, so the recorded
	// point still holds. A revert that could not register it as current is
	// reported once the domain is back (RestoredNotCurrentError).
	notCurrent := reregisterSnapshot(v, domainName, snapshotName, snapXML)

	// Start, retrying on any residual lock-release race (the base stays
	// read-only now, so this should not normally trigger).
	var startErr error
	for i := 0; i < 10; i++ {
		if startErr = startDomain(v, domainName); startErr == nil {
			return notCurrent
		}
		if !strings.Contains(startErr.Error(), "lock") {
			return fmt.Errorf("start domain %s after revert: %w", domainName, startErr)
		}
		if d, e := v.DomainLookupByName(domainName); e == nil {
			_ = v.DomainDestroy(d) // drop any partial lock; keeps the definition
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("start domain %s after revert (disk lock not released after retries): %w", domainName, startErr)
}

// FlattenSnapshot live-merges (block-commit) each disk's active overlay down
// into the named snapshot's base, then deletes the snapshot metadata. After
// this the running VM is on a single standalone disk (the snapshot's base, now
// holding all current data) — no backing chain — so it can be migrated and the
// chain stops growing across snapshot+delete cycles.
//
// We commit only down to THIS snapshot's base (not to the bottom of the chain),
// so a shared/lower base image (e.g. the OS image other VMs share) is never
// touched. RUNNING domains only.
func (c *Client) FlattenSnapshot(domainName, snapshotName string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	if st, _, sErr := c.virt.DomainGetState(dom, 0); sErr != nil || st != int32(golibvirt.DomainRunning) {
		return fmt.Errorf("flatten requires a running domain")
	}
	snap, err := c.virt.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}
	snapXML, err := c.virt.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return fmt.Errorf("get snapshot XML: %w", err)
	}
	base := parseSnapshotDomainDisks(snapXML) // dev → base (commit target)
	domXML, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML: %w", err)
	}
	cur := parseDomainDiskSources(domXML) // dev → overlay (active)

	for dev, basePath := range base {
		overlay, ok := cur[dev]
		if !ok || overlay == basePath {
			continue // disk has no overlay to merge
		}
		// Active-layer commit: merge the active overlay DOWN into basePath. base
		// is set so the commit stops at this snapshot's base (lower layers, e.g.
		// a shared OS image, are untouched); empty top = the active layer.
		if err := c.virt.DomainBlockCommit(dom, dev,
			golibvirt.OptString{basePath}, golibvirt.OptString{}, 0,
			golibvirt.DomainBlockCommitActive); err != nil {
			return fmt.Errorf("block-commit %s: %w", dev, err)
		}
		if err := c.waitBlockJobReady(dom, dev); err != nil {
			return fmt.Errorf("block-commit %s sync: %w", dev, err)
		}
		// Pivot the active layer onto base, ending the job.
		if err := c.virt.DomainBlockJobAbort(dom, dev, golibvirt.DomainBlockJobAbortPivot); err != nil {
			return fmt.Errorf("pivot %s onto base: %w", dev, err)
		}
		os.Remove(overlay) // committed overlay is no longer referenced
	}

	_ = c.virt.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)
	return nil
}

// waitBlockJobReady polls a disk's block job until it has synced (cur >= end),
// the point at which an active-layer commit is ready to pivot. Returns when the
// job is ready or gone; errors only on a query failure or timeout.
func (c *Client) waitBlockJobReady(dom golibvirt.Domain, dev string) error {
	for i := 0; i < 1200; i++ { // ~10 min ceiling for large disks
		found, _, _, curr, end, err := c.virt.DomainGetBlockJobInfo(dom, dev, 0)
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

// DeleteSnapshot removes a named snapshot from a domain.
func (c *Client) DeleteSnapshot(domainName, snapshotName string) error {
	return deleteSnapshot(c.virt, domainName, snapshotName)
}

func deleteSnapshot(v snapshotAPI, domainName, snapshotName string) error {
	dom, err := v.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	snap, err := v.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}

	// libvirt's own external-snapshot delete does the work, except in the one
	// case where libvirt deletes without merging: a snapshot that is not
	// libvirt's current one and has no children. libvirt >= 9 takes it for a
	// leaf with no overlay and unlinks the disk the snapshot was taken of,
	// with no chain check (qemuSnapshotDeleteExternalPrepare, merge=false).
	// litevirt's snapshots always have an overlay: in every such delete the
	// lab reproduced (snapshot-repro.md, scenarios 1, 2a-2c and the minimal
	// one) that disk was the backing file of the VM's live layer, and its
	// data was lost. An earlier build's restore leaves every restored
	// snapshot this way. Its files are kept and only the metadata goes: the
	// VM stays on its chain, which costs disk space and nothing else.
	//
	// Making the snapshot current first, so libvirt merges it, is not done:
	// it would move libvirt's current pointer off whatever snapshot holds it,
	// and libvirt decides the next delete on that pointer.
	if leafNotCurrent(v, dom, snap) {
		slog.Warn("snapshot delete: libvirt does not hold this snapshot as current and it has no children, "+
			"so libvirt would unlink the disk it was taken of, under the VM's live layer; "+
			"deleting its metadata only and keeping its files",
			"vm", domainName, "snapshot", snapshotName)
		return v.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)
	}
	// The other case libvirt cannot handle: a snapshot it would merge, whose
	// overlay is not in the VM's live chain over the disk it was taken of.
	// libvirt refuses that merge ("... disk source ... not the same"), every
	// time, so the snapshot could never be deleted and its record would keep
	// blocking migrate and move. Restoring an older snapshot while a later
	// one exists leaves it this way: the revert resets the live overlay over
	// the older snapshot's base, and the older snapshot's own overlay drops
	// out of the chain. Nothing libvirt would merge is in use, so only the
	// metadata goes and every file stays.
	if why := notInLiveChain(v, dom, snap); why != "" {
		slog.Warn("snapshot delete: libvirt cannot merge this snapshot ("+why+"); "+
			"deleting its metadata only and keeping its files",
			"vm", domainName, "snapshot", snapshotName)
		return v.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)
	}
	return v.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteFlags(0))
}

// notInLiveChain says why libvirt cannot merge the snapshot — an external
// disk whose overlay is not in the domain's live chain, or is not backed
// there by the disk the snapshot was taken of — or "" when every disk is in
// place. Read from the domain's disk sources and the qcow2 headers; what
// cannot be read is a reason, so the delete keeps the files.
func notInLiveChain(v snapshotAPI, dom golibvirt.Domain, snap golibvirt.DomainSnapshot) string {
	snapXML, err := v.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return "snapshot XML: " + err.Error()
	}
	domXML, err := v.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return "domain XML: " + err.Error()
	}
	live := parseDomainDiskSources(domXML)
	bases := parseSnapshotDomainDisks(snapXML)
	for dev, overlay := range parseSnapshotOverlays(snapXML) {
		top, ok := live[dev]
		if !ok {
			return "disk " + dev + " is not in the domain"
		}
		layers, err := qcow2Chain(top)
		idx := -1
		for i, l := range layers {
			if filepath.Clean(l) == filepath.Clean(overlay) {
				idx = i
				break
			}
		}
		if idx < 0 {
			if err != nil {
				return "disk " + dev + ": " + err.Error()
			}
			return "disk " + dev + ": its overlay " + overlay + " is not in the live chain of " + top
		}
		if idx+1 >= len(layers) || filepath.Clean(layers[idx+1]) != filepath.Clean(bases[dev]) {
			if err != nil {
				return "disk " + dev + ": " + err.Error()
			}
			return "disk " + dev + ": its overlay " + overlay + " is not backed by " + bases[dev] + " in the live chain"
		}
	}
	return ""
}

// qcow2Chain is file and the layers under it. Each layer is listed before
// anything reads it, and the next one comes from its parent's own header
// (which litevirt or libvirt wrote), so the disk a snapshot was taken of is
// compared by its path, never parsed. A layer is opened as qcow2 only when
// it is the top or its parent declares it qcow2: a raw file or a block
// device (an LVM volume, a zvol) is listed and ends the chain — it holds
// guest data, not a header — as an empty backing does. The error says where
// a qcow2 layer could not be read; the layers listed so far are returned.
func qcow2Chain(file string) ([]string, error) {
	var out []string
	p, parse := file, true
	for depth := 0; p != "" && depth < 64; depth++ {
		out = append(out, p)
		if !parse {
			break
		}
		info, err := qcow2.Info(p)
		if err != nil {
			return out, fmt.Errorf("read %s: %w", p, err)
		}
		b := info.BackingFile
		if b != "" && !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(p), b)
		}
		p, parse = b, info.BackingFormat == "qcow2"
	}
	return out, nil
}

// leafNotCurrent reports a snapshot libvirt would delete without merging:
// not libvirt's current snapshot, and without children. Anything it cannot
// confirm counts as that, so libvirt is never left to unlink on a guess.
func leafNotCurrent(v snapshotAPI, dom golibvirt.Domain, snap golibvirt.DomainSnapshot) bool {
	n, err := v.DomainSnapshotNumChildren(snap, 0)
	if err != nil {
		return true
	}
	if n > 0 {
		return false
	}
	cur, err := v.DomainSnapshotCurrent(dom, 0)
	return err != nil || cur.Name != snap.Name
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
	snapXML, err := snapshotCreateXML(c.virt, dom, snapshotName)
	if err != nil {
		return 0, 0, err
	}
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
	return revertToLiveSnapshot(c.virt, domainName, snapshotName, vmstatePath, restorePreDefine, rewriteSaved)
}

func revertToLiveSnapshot(v snapshotAPI, domainName, snapshotName, vmstatePath string, restorePreDefine func() error, rewriteSaved func(savedXML string) (string, error)) error {
	// Pre-flight: never start tearing the VM down if the RAM image is gone.
	if _, err := os.Stat(vmstatePath); err != nil {
		return fmt.Errorf("vmstate image %q missing — cannot restore memory snapshot: %w", vmstatePath, err)
	}

	dom, err := v.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	snap, err := v.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}
	snapXML, err := v.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return fmt.Errorf("get snapshot XML: %w", err)
	}
	origDisks := parseSnapshotDomainDisks(snapXML)
	if len(origDisks) == 0 {
		return fmt.Errorf("snapshot %q: no disk sources found in snapshot XML", snapshotName)
	}
	domXML, err := v.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML: %w", err)
	}
	currentDisks := parseDomainDiskSources(domXML)

	// Each changed disk: an empty overlay over its base (frozen at snapshot)
	// — the live layer reset in place, or a new one when the snapshot is not
	// the newest (planRevert).
	resets, err := planRevert(snapXML, currentDisks, snapshotName)
	if err != nil {
		return fmt.Errorf("plan the revert: %w", err)
	}

	// The saved image's domain XML references the overlay paths — keep it as-is
	// for the persistent redefine after restore.
	savedXML, err := v.DomainSaveImageGetXMLDesc(vmstatePath, 0)
	if err != nil {
		return fmt.Errorf("read saved image XML: %w", err)
	}
	restoreXML := ""
	if rewriteSaved != nil {
		// Secure: the replacement must keep the graphics password the saved
		// image carries.
		secure, err := v.DomainSaveImageGetXMLDesc(vmstatePath, uint32(golibvirt.DomainSaveImageXMLSecure))
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
	// The saved image's definition may lack litevirt's own metadata (the
	// managed stamp, the owner epoch) that the domain carries now: the lab
	// saw a restored domain without litevirt-managed until a background
	// stamp ~10 s later. Carried over from the current definition into the
	// one the domain is restored with and defined as, so it never runs
	// without it.
	if cur, err := v.DomainGetXMLDesc(dom, golibvirt.DomainXMLInactive); err == nil {
		base := restoreXML
		if base == "" {
			secure, err := v.DomainSaveImageGetXMLDesc(vmstatePath, uint32(golibvirt.DomainSaveImageXMLSecure))
			if err != nil {
				return fmt.Errorf("read saved image XML: %w", err)
			}
			base = secure
		}
		with, err := carryLitevirtMetadata(base, cur)
		if err != nil {
			return fmt.Errorf("carry litevirt metadata into the restored definition: %w", err)
		}
		if with != base {
			restoreXML, savedXML = with, with
		}
	}

	// The saved image names the overlays the snapshot made. Every disk is
	// restored onto the overlay it will run on — a new one, or one an
	// earlier restore of this snapshot made — with the old chain dropped,
	// whenever that is not the overlay the image names: the RAM would come
	// back over a disk holding later writes, and the guest would write into
	// a later snapshot's base (re-review R2-C1). Compared with the image's
	// own sources, not with the live layer.
	savedDisks := parseDomainDiskSources(savedXML)
	for _, r := range resets {
		if savedDisks[r.dev] == r.target {
			continue
		}
		if restoreXML == "" {
			secure, err := v.DomainSaveImageGetXMLDesc(vmstatePath, uint32(golibvirt.DomainSaveImageXMLSecure))
			if err != nil {
				return fmt.Errorf("read saved image XML: %w", err)
			}
			restoreXML = secure
		}
		if restoreXML, err = repointRevertedDisk(restoreXML, r.dev, r.target); err != nil {
			return fmt.Errorf("revert disk %s onto %s: %w", r.dev, r.target, err)
		}
		savedXML = restoreXML
	}

	// Destroy the domain and wait for shutoff — only an active one: a
	// stopped VM has nothing to destroy, and destroying it failed the revert
	// ("domain is not running") before anything was done.
	if st, _, sErr := v.DomainGetState(dom, 0); sErr != nil || st != int32(golibvirt.DomainShutoff) {
		if err := v.DomainDestroy(dom); err != nil {
			return fmt.Errorf("destroy domain before revert: %w", err)
		}
		for i := 0; i < 30; i++ {
			dom2, lookupErr := v.DomainLookupByName(domainName)
			if lookupErr != nil {
				break
			}
			st, _, _ := v.DomainGetState(dom2, 0)
			if st == int32(golibvirt.DomainShutoff) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	// Delete snapshot metadata (we manage the overlay files ourselves).
	_ = v.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)

	// Undefine to release virtlockd locks (mirrors the disk-only revert).
	dom, _ = v.DomainLookupByName(domainName)
	_ = v.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineKeepNvram|golibvirt.DomainUndefineKeepTpm))
	for i := 0; i < 20; i++ {
		time.Sleep(revertUndefinePoll)
		if !domainExists(v, domainName) {
			break
		}
	}
	time.Sleep(revertUndefineSettle)

	// Reset each overlay to empty over its (frozen) base — this is the disk
	// revert: all post-snapshot writes (in the old overlay) are discarded.
	for _, r := range resets {
		if err := resetOverlay(r.target, r.base); err != nil {
			return fmt.Errorf("reset overlay %q: %w", r.target, err)
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
	if err := restoreWithRetry(v, domainName, vmstatePath, restoreXML); err != nil {
		return fmt.Errorf("restore guest memory: %w", err)
	}
	if _, err := v.DomainDefineXML(savedXML); err != nil {
		// Running instance is fine; it just isn't persistent yet. Surface it so
		// the operator knows a stop would lose the definition.
		return fmt.Errorf("revert restored the running VM but re-defining it persistently failed: %w", err)
	}

	// The undefine above dropped the libvirt snapshot metadata. Re-register it
	// (best-effort) so the snapshot stays revertible AND deletable — the overlay
	// is freshly reset over the same base, so the recorded snapshot point still
	// holds. A failure here does not fail the revert, which already
	// succeeded; it is reported as a RestoredNotCurrentError.
	return reregisterSnapshot(v, domainName, snapshotName, snapXML)
}

// RestoredNotCurrentError is what a revert returns when the domain is
// restored and running but its snapshot could not be registered again as
// libvirt's current snapshot: registered plain (Registered), or not at all.
// The restore itself succeeded. A later delete of the snapshot then keeps
// its files rather than letting libvirt merge it (deleteSnapshot's guards),
// so nothing is lost, but the chain is not reclaimed — which an operator
// must be able to see rather than find in a log.
type RestoredNotCurrentError struct {
	Snapshot   string
	Registered bool
	Err        error
}

func (e *RestoredNotCurrentError) Error() string {
	if e.Registered {
		return fmt.Sprintf("snapshot %q was restored, but libvirt refused to make it its current snapshot (%v); "+
			"it is registered as a plain snapshot, and deleting it will keep its files instead of merging them", e.Snapshot, e.Err)
	}
	return fmt.Sprintf("snapshot %q was restored, but libvirt refused to register it again (%v); "+
		"libvirt no longer holds it, and deleting it removes only its record", e.Snapshot, e.Err)
}

func (e *RestoredNotCurrentError) Unwrap() error { return e.Err }

// reregisterSnapshot defines a reverted snapshot's metadata again, as
// libvirt's CURRENT snapshot. The revert dropped it with a METADATA_ONLY
// delete, which moved libvirt's current snapshot to its parent (or to none),
// and the domain now runs on the snapshot's own overlay, freshly reset: it is
// the snapshot the domain's state descends from, which is what "current"
// means to libvirt.
//
// It matters because libvirt >= 9 decides on "current" alone how a later
// plain delete treats the files (qemuSnapshotDeleteExternalPrepare): a
// snapshot that is not current and has no children is taken for a leaf with
// no overlay, and the disk its <domain> names — the base under the VM's live
// overlay — is unlinked without a chain check. Redefined without CURRENT,
// every restored snapshot became that (snapshot-repro.md: one memory
// snapshot, restore, delete unlinked the VM's root disk). Redefined current,
// a delete merges: the overlay is committed into the base and removed.
//
// A redefine libvirt refuses as current is retried as a plain one so the
// snapshot is not lost, and deleteSnapshot's guards keep the files of a
// snapshot left non-current. Either way short of current is returned as a
// RestoredNotCurrentError (nil when it is current).
func reregisterSnapshot(v snapshotAPI, domainName, snapshotName, snapXML string) error {
	redom, err := v.DomainLookupByName(domainName)
	if err != nil {
		slog.Error("snapshot revert: domain not found to re-register the snapshot", "vm", domainName, "snapshot", snapshotName, "error", err)
		return &RestoredNotCurrentError{Snapshot: snapshotName, Err: err}
	}
	_, err = v.DomainSnapshotCreateXML(redom, snapXML,
		uint32(golibvirt.DomainSnapshotCreateRedefine|golibvirt.DomainSnapshotCreateCurrent))
	if err == nil {
		return nil
	}
	slog.Error("snapshot revert: re-registering the snapshot as current failed; registering it plain",
		"vm", domainName, "snapshot", snapshotName, "error", err)
	if _, perr := v.DomainSnapshotCreateXML(redom, snapXML, uint32(golibvirt.DomainSnapshotCreateRedefine)); perr != nil {
		slog.Error("snapshot revert: re-registering the snapshot failed", "vm", domainName, "snapshot", snapshotName, "error", perr)
		return &RestoredNotCurrentError{Snapshot: snapshotName, Err: fmt.Errorf("%v; plain: %w", err, perr)}
	}
	return &RestoredNotCurrentError{Snapshot: snapshotName, Registered: true, Err: err}
}

// revertStep is what a revert does to one disk: it runs afterwards on
// target, an empty overlay directly on base, the disk the snapshot was taken
// of. target is the live layer, reset in place, when that is the snapshot's
// own overlay (the snapshot is the newest), or an overlay this revert made
// earlier on the same base. Otherwise — an older snapshot restored while a
// later one exists — the live layer and the snapshot's own overlay both
// belong to later snapshots (the latter is a later snapshot's base), so
// neither is touched, and target is a new file beside them.
type revertStep struct {
	dev, base, live, target string
}

// planRevert plans the revert of each disk the snapshot changed.
//
// Resetting the live layer when the snapshot is not the newest — what the
// revert did — reset the newest overlay over the older snapshot's base, but
// the domain's XML still carried the old <backingStore> chain, which libvirt
// opens as written: the guest kept every write since the older snapshot
// (snapshot-lab.md, Round 1 row 5), and a memory revert came back on the
// snapshot's own overlay, holding later writes, under its RAM.
func planRevert(snapXML string, live map[string]string, snapshotName string) ([]revertStep, error) {
	overlays := parseSnapshotOverlays(snapXML)
	var out []revertStep
	for dev, base := range parseSnapshotDomainDisks(snapXML) {
		ov := overlays[dev]
		if ov != "" {
			// The base is what the snapshot's own overlay was created on,
			// read from that overlay's header, never from the snapshot's
			// XML: libvirt rewrites a descendant's recorded base to its
			// parent's base whenever the parent's metadata is dropped — as
			// every revert of the parent does — so after restoring s1, s2's
			// XML named s1's base and s2's restore lost s2's data
			// (snapshot-lab.md, Round 3 row 2b).
			b, err := overlayBacking(ov)
			if err != nil {
				return nil, fmt.Errorf("disk %s: snapshot %q's overlay %s: %w", dev, snapshotName, ov, err)
			}
			base = b
		}
		l, ok := live[dev]
		if !ok || l == base {
			continue
		}
		step := revertStep{dev: dev, base: base, live: l, target: l}
		if ov != "" && l != ov && !isRevertOverlay(l, ov, snapshotName, base) {
			step.target = newRevertOverlayPath(ov, snapshotName)
		}
		out = append(out, step)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dev < out[j].dev })
	return out, nil
}

// overlayBacking is the file a snapshot overlay was created on, from its own
// qcow2 header (written by libvirt when the snapshot was taken; the guest
// writes data into it, not its header).
func overlayBacking(ov string) (string, error) {
	info, err := qcow2.Info(ov)
	if err != nil {
		return "", err
	}
	if info.BackingFile == "" {
		return "", fmt.Errorf("it names no backing file")
	}
	b := info.BackingFile
	if !filepath.IsAbs(b) {
		b = filepath.Join(filepath.Dir(ov), b)
	}
	return filepath.Clean(b), nil
}

// revertOverlayPrefix is the name a revert's new overlays of the snapshot's
// overlay ov take: <stem>.<snapshot>-r. The stem is the disk's, so the disk
// keeps its name for everything that matches by stem.
func revertOverlayPrefix(ov, snapshotName string) string {
	return overlayStem(ov, snapshotName) + "." + snapshotName + "-r"
}

// overlayStem is the disk stem of the snapshot's overlay ov. libvirt names
// it <stem>.<snapshot>, so the snapshot's name is cut off whole — a name
// with a dot (v1.2) would otherwise split the stem (re-review R2-M3).
func overlayStem(ov, snapshotName string) string {
	if stem, ok := strings.CutSuffix(ov, "."+snapshotName); ok && filepath.Base(stem) != "" {
		return stem
	}
	return strings.TrimSuffix(ov, filepath.Ext(ov))
}

// isRevertOverlay reports that layer is an overlay an earlier revert to
// this snapshot made, still directly on base (no snapshot since): it is
// reset in place rather than another one made.
func isRevertOverlay(layer, ov, snapshotName, base string) bool {
	if !strings.HasPrefix(layer, revertOverlayPrefix(ov, snapshotName)) {
		return false
	}
	info, err := qcow2.Info(layer)
	if err != nil {
		return false
	}
	b := info.BackingFile
	if b != "" && !filepath.IsAbs(b) {
		b = filepath.Join(filepath.Dir(layer), b)
	}
	return filepath.Clean(b) == filepath.Clean(base)
}

// newRevertOverlayPath is a new file name for a revert's overlay.
func newRevertOverlayPath(ov, snapshotName string) string {
	p := revertOverlayPrefix(ov, snapshotName) + strconv.FormatInt(time.Now().Unix(), 10)
	for i, c := 1, p; ; i++ {
		if _, err := os.Lstat(c); os.IsNotExist(err) {
			return c
		}
		c = fmt.Sprintf("%s-%d", p, i)
	}
}

// repointRevertedDisk points the disk with target dev at file and drops the
// <backingStore> chain under it, so libvirt probes the new overlay's chain
// from its header instead of opening the old one as written.
//
// It splices the original text: only the value of that disk's <source
// file=> and its direct <backingStore> children change, and every other
// byte — litevirt's namespaced metadata (litevirt-managed,
// litevirt-owner-epoch), a qemu:commandline block, comments, formatting —
// is kept as it was. Every litevirt domain carries namespaced metadata, so
// re-encoding the XML, or refusing namespaces, is not an option.
func repointRevertedDisk(domXML, dev, file string) (string, error) {
	type span struct{ start, end int64 }
	dec := xml.NewDecoder(strings.NewReader(domXML))
	var stack []string
	diskDepth, bsDepth := -1, -1
	var src, bsOpen span
	var bss []span
	var target string
	found := false
	for !found {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("decode domain XML: %w", err)
		}
		end := dec.InputOffset()
		switch t := tok.(type) {
		case xml.StartElement:
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, t.Name.Local)
			depth := len(stack) - 1
			if diskDepth < 0 && t.Name.Space == "" && t.Name.Local == "disk" && parent == "devices" {
				diskDepth, src, bss, target = depth, span{-1, -1}, nil, ""
				continue
			}
			if diskDepth >= 0 && depth == diskDepth+1 && t.Name.Space == "" {
				switch t.Name.Local {
				case "source":
					if src.start < 0 {
						src = span{start, end}
					}
				case "target":
					for _, a := range t.Attr {
						if a.Name.Local == "dev" {
							target = a.Value
						}
					}
				case "backingStore":
					bsOpen, bsDepth = span{start, end}, depth
				}
			}
		case xml.EndElement:
			depth := len(stack) - 1
			if bsDepth >= 0 && depth == bsDepth {
				bss = append(bss, span{bsOpen.start, end})
				bsDepth = -1
			}
			if diskDepth >= 0 && depth == diskDepth {
				if target == dev {
					found = true
				} else {
					diskDepth = -1
				}
			}
			stack = stack[:len(stack)-1]
		}
	}
	if !found {
		return "", fmt.Errorf("no disk %s in the domain XML", dev)
	}
	if src.start < 0 {
		return "", fmt.Errorf("disk %s has no <source> to repoint", dev)
	}
	m := sourceFileAttr.FindStringSubmatchIndex(domXML[src.start:src.end])
	if m == nil {
		return "", fmt.Errorf("disk %s has no <source file=> to repoint", dev)
	}
	quote, vi := "'", 2 // single-quoted value in group 1, double in group 2
	if m[2] < 0 {
		quote, vi = `"`, 4
	}
	var esc bytes.Buffer
	if err := xml.EscapeText(&esc, []byte(file)); err != nil {
		return "", err
	}
	value := esc.String()
	if quote == "'" {
		value = strings.ReplaceAll(value, "'", "&#39;")
	} else {
		value = strings.ReplaceAll(value, `"`, "&#34;")
	}
	edits := append([]span(nil), bss...)
	repl := map[int64]string{}
	vs, ve := src.start+int64(m[vi]), src.start+int64(m[vi+1])
	edits = append(edits, span{vs, ve})
	repl[vs] = value
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := domXML
	for _, e := range edits {
		out = out[:e.start] + repl[e.start] + out[e.end:]
	}
	return out, nil
}

// sourceFileAttr finds a <source> start tag's file attribute value:
// single-quoted in group 1, double-quoted in group 2.
var sourceFileAttr = regexp.MustCompile(`\sfile\s*=\s*(?:'([^']*)'|"([^"]*)")`)

// litevirtMetadataPrefix starts the namespace URI of every element litevirt
// keeps in a domain's <metadata>.
const litevirtMetadataPrefix = "https://litevirt.dev/xmlns/"

// carryLitevirtMetadata copies into domXML each of from's <metadata>
// elements in a litevirt namespace that domXML has none of, spliced into
// the text so every other byte is kept. domXML is returned unchanged when
// it lacks nothing.
func carryLitevirtMetadata(domXML, from string) (string, error) {
	type elem struct {
		uri  string
		text string
	}
	scan := func(x string) (els []elem, mdEnd, afterName int64, err error) {
		dec := xml.NewDecoder(strings.NewReader(x))
		depth, mdEnd, afterName := 0, int64(-1), int64(-1)
		inMD, elStart, elDepth, elURI := false, int64(-1), -1, ""
		for {
			start := dec.InputOffset()
			tok, err := dec.Token()
			if err == io.EOF {
				return els, mdEnd, afterName, nil
			}
			if err != nil {
				return nil, 0, 0, err
			}
			end := dec.InputOffset()
			switch t := tok.(type) {
			case xml.StartElement:
				depth++
				if depth == 2 && t.Name.Local == "metadata" && t.Name.Space == "" {
					inMD = true
				} else if inMD && depth == 3 && strings.HasPrefix(t.Name.Space, litevirtMetadataPrefix) {
					elStart, elDepth, elURI = start, depth, t.Name.Space
				}
			case xml.EndElement:
				if elStart >= 0 && depth == elDepth {
					els = append(els, elem{elURI, x[elStart:end]})
					elStart = -1
				}
				if inMD && depth == 2 {
					inMD, mdEnd = false, start
				}
				if depth == 2 && (t.Name.Local == "name" || t.Name.Local == "uuid") && t.Name.Space == "" {
					afterName = end
				}
				depth--
			}
		}
	}
	have, mdEnd, afterName, err := scan(domXML)
	if err != nil {
		return "", err
	}
	want, _, _, err := scan(from)
	if err != nil {
		return "", err
	}
	got := map[string]bool{}
	for _, e := range have {
		got[e.uri] = true
	}
	var add strings.Builder
	for _, e := range want {
		if !got[e.uri] {
			add.WriteString(e.text)
			got[e.uri] = true
		}
	}
	if add.Len() == 0 {
		return domXML, nil
	}
	if mdEnd >= 0 {
		return domXML[:mdEnd] + add.String() + domXML[mdEnd:], nil
	}
	if afterName < 0 {
		return "", fmt.Errorf("the definition has no <name> to put <metadata> after")
	}
	return domXML[:afterName] + "<metadata>" + add.String() + "</metadata>" + domXML[afterName:], nil
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
	return restoreWithRetry(c.virt, domainName, vmstatePath, dxml)
}

func restoreWithRetry(v snapshotAPI, domainName, vmstatePath, dxml string) error {
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
		err = v.DomainRestoreFlags(vmstatePath, dxmlOpt, uint32(domainSavePaused))
		if err == nil {
			break
		}
		msg := err.Error()
		if !strings.Contains(msg, "lock") && !strings.Contains(msg, "already") {
			return err
		}
		forceRemoveDomain(v, domainName) // clear any partial domain holding the lock
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return err
	}
	// The domain is restored and paused, holding its disk locks. Resume the CPU.
	dom, lerr := v.DomainLookupByName(domainName)
	if lerr != nil {
		return fmt.Errorf("lookup restored domain: %w", lerr)
	}
	for i := 0; i < 6; i++ {
		if err = v.DomainResume(dom); err == nil {
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
func forceRemoveDomain(v snapshotAPI, domainName string) {
	d, e := v.DomainLookupByName(domainName)
	if e != nil {
		return
	}
	_ = v.DomainDestroy(d) // no-op/err if already shut off
	if d2, e2 := v.DomainLookupByName(domainName); e2 == nil {
		_ = v.DomainUndefineFlags(d2, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineKeepNvram|golibvirt.DomainUndefineKeepTpm))
	}
}

// SnapshotDiskFiles returns the files a delete of the snapshot may merge or
// remove: for each disk the snapshot made an external overlay of, the
// overlay (its <disks> source) and the disk it was taken of (its <domain>
// source), which libvirt commits the overlay into. Sorted, without repeats.
func (c *Client) SnapshotDiskFiles(domainName, snapshotName string) ([]string, error) {
	return snapshotDiskFiles(c.virt, domainName, snapshotName)
}

func snapshotDiskFiles(v snapshotAPI, domainName, snapshotName string) ([]string, error) {
	dom, err := v.DomainLookupByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	snap, err := v.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return nil, fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}
	snapXML, err := v.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return nil, fmt.Errorf("get snapshot XML: %w", err)
	}
	bases := parseSnapshotDomainDisks(snapXML)
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for dev, overlay := range parseSnapshotOverlays(snapXML) {
		add(overlay)
		add(bases[dev])
		// And the file the overlay's own header backs on: libvirt rewrites
		// a snapshot's recorded base when its parent's metadata is dropped,
		// so the XML's base can be a layer further down (planRevert).
		if b, err := overlayBacking(overlay); err == nil {
			add(b)
		}
	}
	sort.Strings(out)
	return out, nil
}

// DomainDiskFormats returns the domain's disks as source file → libvirt
// driver type (qcow2, raw, ...), from its live definition.
func (c *Client) DomainDiskFormats(domainName string) (map[string]string, error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	x, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return nil, fmt.Errorf("get domain XML %q: %w", domainName, err)
	}
	return DiskFormatsFromXML(x), nil
}

// DiskFormatsFromXML is a domain XML's disks as source file → driver type,
// for the disks with a file source and a driver type.
func DiskFormatsFromXML(domXML string) map[string]string {
	var v struct {
		Devices struct {
			Disks []struct {
				Driver struct {
					Type string `xml:"type,attr"`
				} `xml:"driver"`
				Source struct {
					File string `xml:"file,attr"`
				} `xml:"source"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &v); err != nil {
		return nil
	}
	out := map[string]string{}
	for _, d := range v.Devices.Disks {
		if d.Source.File != "" && d.Driver.Type != "" {
			out[d.Source.File] = d.Driver.Type
		}
	}
	return out
}

// parseSnapshotOverlays extracts, from a snapshot's <disks>, each external
// disk's overlay: target dev → file. Disks with snapshot='no' have none.
func parseSnapshotOverlays(snapXML string) map[string]string {
	var snap struct {
		Disks struct {
			Disk []struct {
				Name     string `xml:"name,attr"`
				Snapshot string `xml:"snapshot,attr"`
				Source   struct {
					File string `xml:"file,attr"`
				} `xml:"source"`
			} `xml:"disk"`
		} `xml:"disks"`
	}
	if err := xml.Unmarshal([]byte(snapXML), &snap); err != nil {
		return nil
	}
	m := map[string]string{}
	for _, d := range snap.Disks.Disk {
		if d.Snapshot == "external" && d.Name != "" && d.Source.File != "" {
			m[d.Name] = d.Source.File
		}
	}
	return m
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
