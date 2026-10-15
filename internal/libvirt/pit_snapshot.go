package libvirt

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Point-in-time copy of a running disk through an external disk-only snapshot.
//
// The copy layer (grpcapi, pit_copy.go) uses this when no backup session is
// available: a disk-only external snapshot moves the guest's writes onto a new
// overlay, which freezes the disk's own file at one instant. The caller copies
// that frozen file, then CommitDiskOverlay merges the overlay back down into it
// (active block-commit, then pivot), so the domain ends on the file it started
// on.
//
// Only the one disk is snapshotted; every other disk is listed with
// snapshot='no'. NO_METADATA keeps the snapshot out of the domain's snapshot
// list, where `lv snapshot` would otherwise find it. ATOMIC makes a failed
// snapshot leave the domain as it was.

// pitAPI is the part of libvirt the point-in-time snapshot uses.
// *golibvirt.Libvirt in production; a model in the tests.
type pitAPI interface {
	DomainLookupByName(name string) (golibvirt.Domain, error)
	DomainGetState(dom golibvirt.Domain, flags uint32) (int32, int32, error)
	DomainGetXMLDesc(dom golibvirt.Domain, flags golibvirt.DomainXMLFlags) (string, error)
	DomainDefineXML(xml string) (golibvirt.Domain, error)
	DomainSnapshotCreateXML(dom golibvirt.Domain, xml string, flags uint32) (golibvirt.DomainSnapshot, error)
	DomainBlockCommit(dom golibvirt.Domain, disk string, base, top golibvirt.OptString, bandwidth uint64, flags golibvirt.DomainBlockCommitFlags) error
	DomainGetBlockJobInfo(dom golibvirt.Domain, path string, flags uint32) (int32, int32, uint64, uint64, uint64, error)
	DomainBlockJobAbort(dom golibvirt.Domain, path string, flags golibvirt.DomainBlockJobAbortFlags) error
}

var _ pitAPI = (*golibvirt.Libvirt)(nil)

// pitCommitPoll and pitCommitTimeout bound the wait for an active commit to
// reach its ready state; pitPivotTries bounds the pivot attempts. Variables so
// the tests run without the real waits.
var (
	pitCommitPoll    = 500 * time.Millisecond
	pitCommitTimeout = 30 * time.Minute
	pitPivotTries    = 5
)

// pitDomainActive reports whether the domain is running or paused — the only
// states in which a disk-only snapshot is taken live and an active commit can
// run. libvirt would also snapshot an inactive domain (offline, with
// qemu-img), which no layer-2 copy wants.
func pitDomainActive(v pitAPI, dom golibvirt.Domain) (bool, error) {
	st, _, err := v.DomainGetState(dom, 0)
	if err != nil {
		return false, err
	}
	switch golibvirt.DomainState(st) {
	case golibvirt.DomainRunning, golibvirt.DomainPaused, golibvirt.DomainBlocked, golibvirt.DomainPmsuspended:
		return true, nil
	}
	return false, nil
}

// SnapshotDiskExternal creates an external disk-only snapshot of the disk
// whose source is diskPath, putting the guest's new writes on overlay. It asks
// the guest agent to quiesce first and, when that is refused (no agent), takes
// it crash-consistent. quiesced reports which. On error the domain is still on
// diskPath (the snapshot is atomic).
func (c *Client) SnapshotDiskExternal(domain, diskPath, overlay string) (quiesced bool, err error) {
	return snapshotDiskExternal(c.virt, domain, diskPath, overlay)
}

func snapshotDiskExternal(v pitAPI, domain, diskPath, overlay string) (bool, error) {
	dom, err := v.DomainLookupByName(domain)
	if err != nil {
		return false, fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	if active, err := pitDomainActive(v, dom); err != nil || !active {
		return false, fmt.Errorf("domain %s is not running or paused (%v); no live snapshot is taken", domain, err)
	}
	domXML, err := v.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return false, fmt.Errorf("dump domain xml: %w", err)
	}
	snapXML, err := pitSnapshotXML(domXML, diskPath, overlay)
	if err != nil {
		return false, err
	}
	base := uint32(golibvirt.DomainSnapshotCreateDiskOnly | golibvirt.DomainSnapshotCreateAtomic | golibvirt.DomainSnapshotCreateNoMetadata)
	if _, qerr := v.DomainSnapshotCreateXML(dom, snapXML, base|uint32(golibvirt.DomainSnapshotCreateQuiesce)); qerr == nil {
		narrowNew(overlay)
		return true, nil
	} else if _, err := v.DomainSnapshotCreateXML(dom, snapXML, base); err != nil {
		return false, fmt.Errorf("external disk snapshot (quiesced: %v; crash-consistent: %w)", qerr, err)
	}
	narrowNew(overlay)
	return false, nil
}

// pitSnapshotXML is the snapshot definition: diskPath's disk external onto
// overlay, every other disk not snapshotted.
func pitSnapshotXML(domXML, diskPath, overlay string) (string, error) {
	var d domainDisksXML
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return "", fmt.Errorf("parse domain xml: %w", err)
	}
	var disks strings.Builder
	found := false
	for _, disk := range d.Disks {
		dev := disk.Target.Dev
		if dev == "" {
			continue
		}
		if disk.Source.File == diskPath || disk.Source.Dev == diskPath {
			found = true
			fmt.Fprintf(&disks, "<disk name='%s' snapshot='external' type='file'><driver type='qcow2'/><source file='%s'/></disk>",
				xmlAttr(dev), xmlAttr(overlay))
			continue
		}
		fmt.Fprintf(&disks, "<disk name='%s' snapshot='no'/>", xmlAttr(dev))
	}
	if !found {
		return "", fmt.Errorf("no disk with source %q in the domain", diskPath)
	}
	return "<domainsnapshot><name>lv-pit-" + fmt.Sprint(time.Now().UTC().UnixNano()) +
		"</name><description>litevirt point-in-time copy</description><disks>" + disks.String() + "</disks></domainsnapshot>", nil
}

// CommitDiskOverlay merges overlay back into diskPath and pivots the domain
// onto diskPath: an active block-commit of the disk running on overlay. A
// commit job already running on that disk (one a dead daemon or a cancelled
// call started) is resumed rather than started again. A pivot that keeps
// failing is aborted, so the domain is left on the overlay with no job and the
// next call can try again. The live part runs only on an active domain; an
// inactive one is the caller's to commit offline (pitoverlay).
//
// The persistent definition is then repaired: a disk entry that still names
// overlay is pointed back at diskPath with diskFormat as its driver type and
// no <backingStore> — libvirt's post-snapshot entry is the overlay's, and a
// restart from it would lose every write made after the pivot. The overlay
// file itself is the caller's to remove, once DomainUsesFile says nothing
// references it.
//
// beforePivot, when set, runs once the commit is ready and before the pivot:
// it records, durably, that a pivot is about to happen, so a daemon that dies
// right after the pivot is known to have pivoted. If it fails, nothing is
// pivoted: the job is aborted and the domain stays on the overlay.
//
// It ends by redefining the domain's persistent disk, so the firmware move
// guard is asked for that define (OpDefine) before anything is committed.
func (c *Client) CommitDiskOverlay(domain, diskPath, overlay, diskFormat string, beforePivot func() error) error {
	if err := c.firmwareGuard().check(FirmwareCall{Op: OpDefine, Name: domain}); err != nil {
		return fmt.Errorf("commit %s into %s: %w", overlay, diskPath, err)
	}
	return commitDiskOverlay(keepConsolePITAPI{c.virt, c}, domain, diskPath, overlay, diskFormat, beforePivot)
}

func commitDiskOverlay(v pitAPI, domain, diskPath, overlay, diskFormat string, beforePivot func() error) error {
	dom, err := v.DomainLookupByName(domain)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	active, err := pitDomainActive(v, dom)
	if err != nil {
		return fmt.Errorf("domain %s state: %w", domain, err)
	}
	if active {
		live, err := v.DomainGetXMLDesc(dom, 0)
		if err != nil {
			return fmt.Errorf("dump domain xml: %w", err)
		}
		if dev := diskTargetForSource(live, overlay); dev != "" {
			if err := activeCommitAndPivot(v, dom, dev, diskPath, beforePivot); err != nil {
				return err
			}
			after, err := v.DomainGetXMLDesc(dom, 0)
			if err != nil {
				return fmt.Errorf("dump domain xml after pivot: %w", err)
			}
			if diskTargetForSource(after, overlay) != "" {
				return fmt.Errorf("disk %s still runs on %s after the pivot", dev, overlay)
			}
		}
	}
	return repairPersistentDisk(v, dom, diskPath, overlay, diskFormat)
}

// activeCommitAndPivot commits dev's active layer down into diskPath and
// pivots, resuming a commit job already there.
func activeCommitAndPivot(v pitAPI, dom golibvirt.Domain, dev, diskPath string, beforePivot func() error) error {
	found, typ, _, _, _, err := v.DomainGetBlockJobInfo(dom, dev, 0)
	if err != nil {
		return fmt.Errorf("block job of %s: %w", dev, err)
	}
	// Only an active commit is ours to resume. Any other job on the disk —
	// a copy a live move left behind, say — is not touched: pivoting it
	// would move the disk where nothing records.
	if found != 0 && golibvirt.DomainBlockJobType(typ) != golibvirt.DomainBlockJobTypeActiveCommit {
		return fmt.Errorf("disk %s has another block job (type %d) running; it is not ours and is left alone", dev, typ)
	}
	if found == 0 {
		if err := v.DomainBlockCommit(dom, dev, golibvirt.OptString{diskPath}, golibvirt.OptString{}, 0,
			golibvirt.DomainBlockCommitActive); err != nil {
			return fmt.Errorf("block-commit %s: %w", dev, err)
		}
	}
	if err := waitPITCommitReady(v, dom, dev); err != nil {
		_ = v.DomainBlockJobAbort(dom, dev, 0)
		return fmt.Errorf("block-commit %s: %w", dev, err)
	}
	// Record the pivot before it happens: a daemon that dies right after it
	// must find it recorded. No record, no pivot — the domain stays on the
	// overlay with no job.
	if beforePivot != nil {
		if err := beforePivot(); err != nil {
			_ = v.DomainBlockJobAbort(dom, dev, 0)
			return fmt.Errorf("record the pivot of %s before it: %w", dev, err)
		}
	}
	var perr error
	for i := 0; i < pitPivotTries; i++ {
		if perr = v.DomainBlockJobAbort(dom, dev, golibvirt.DomainBlockJobAbortPivot); perr == nil {
			return nil
		}
		time.Sleep(pitCommitPoll)
	}
	// Leave no job behind: the domain stays on the overlay, which keeps the
	// guest's writes, and the next call starts the commit afresh.
	_ = v.DomainBlockJobAbort(dom, dev, 0)
	return fmt.Errorf("pivot %s onto %s (%d tries): %w", dev, diskPath, pitPivotTries, perr)
}

// repairPersistentDisk points a persistent disk entry that names overlay
// back at diskPath.
func repairPersistentDisk(v pitAPI, dom golibvirt.Domain, diskPath, overlay, diskFormat string) error {
	// Secure: the repaired definition is redefined, and a dump without
	// VIR_DOMAIN_XML_SECURE has no console password to keep.
	inactive, err := v.DomainGetXMLDesc(dom, golibvirt.DomainXMLInactive|golibvirt.DomainXMLSecure)
	if err != nil {
		return fmt.Errorf("dump persistent domain xml: %w", err)
	}
	fixed, changed, err := repairPITDiskXML(inactive, overlay, diskPath, diskFormat)
	if err != nil {
		return fmt.Errorf("repoint persistent disk to %s: %w", diskPath, err)
	}
	if changed {
		if _, err := v.DomainDefineXML(fixed); err != nil {
			return fmt.Errorf("redefine persistent disk on %s: %w", diskPath, err)
		}
	}
	return nil
}

// repairPITDiskXML rewrites the <disk> element whose <source file> is overlay:
// the source becomes diskPath, the driver type diskFormat, and every
// <backingStore> inside it goes (libvirt re-probes the chain on define).
func repairPITDiskXML(domXML, overlay, diskPath, diskFormat string) (string, bool, error) {
	if diskFormat == "" {
		diskFormat = "qcow2"
	}
	for _, q := range []string{"'", "\""} {
		marker := "file=" + q + overlay + q
		i := strings.Index(domXML, marker)
		if i < 0 {
			continue
		}
		start := strings.LastIndex(domXML[:i], "<disk ")
		endRel := strings.Index(domXML[i:], "</disk>")
		if start < 0 || endRel < 0 {
			return "", false, fmt.Errorf("no <disk> element around %s", overlay)
		}
		end := i + endRel
		disk := domXML[start:end]
		disk = strings.Replace(disk, marker, "file="+q+diskPath+q, 1)
		disk = stripBackingStore(disk)
		disk = pitDriverTypeRE.ReplaceAllString(disk, "${1}"+diskFormat+"${3}")
		return domXML[:start] + disk + domXML[end:], true, nil
	}
	return domXML, false, nil
}

var pitDriverTypeRE = regexp.MustCompile(`(<driver\b[^>]*\btype=['"])([^'"]*)(['"])`)

// stripBackingStore removes every <backingStore> element (self-closing or
// nested) from a disk element's text.
func stripBackingStore(disk string) string {
	for {
		i := strings.Index(disk, "<backingStore")
		if i < 0 {
			return disk
		}
		gt := strings.Index(disk[i:], ">")
		if gt < 0 {
			return disk
		}
		if disk[i+gt-1] == '/' { // <backingStore/>
			disk = disk[:i] + disk[i+gt+1:]
			continue
		}
		depth, j := 0, i
		for j < len(disk) {
			o := strings.Index(disk[j:], "<backingStore")
			c := strings.Index(disk[j:], "</backingStore>")
			if c < 0 {
				return disk
			}
			if o >= 0 && o < c {
				og := strings.Index(disk[j+o:], ">")
				if disk[j+o+og-1] != '/' {
					depth++
				}
				j += o + og + 1
				continue
			}
			depth--
			j += c + len("</backingStore>")
			if depth == 0 {
				break
			}
		}
		disk = disk[:i] + disk[j:]
	}
}

func waitPITCommitReady(v pitAPI, dom golibvirt.Domain, dev string) error {
	deadline := time.Now().Add(pitCommitTimeout)
	for {
		found, _, _, cur, end, err := v.DomainGetBlockJobInfo(dom, dev, 0)
		if err != nil {
			return err
		}
		if found == 0 {
			return fmt.Errorf("the commit job ended before it was ready to pivot")
		}
		if cur >= end {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not ready to pivot after %s", pitCommitTimeout)
		}
		time.Sleep(pitCommitPoll)
	}
}

// DomainRunsOnFile reports whether the domain's LIVE definition names path as
// a disk source: whether qemu runs the disk on it now.
func (c *Client) DomainRunsOnFile(domain, path string) (bool, error) {
	return domainRunsOnFile(c.virt, domain, path)
}

func domainRunsOnFile(v pitAPI, domain, path string) (bool, error) {
	dom, err := v.DomainLookupByName(domain)
	if err != nil {
		return false, fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	x, err := v.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return false, fmt.Errorf("dump domain xml: %w", err)
	}
	return diskTargetForSource(x, path) != "", nil
}

// DomainUsesFile reports whether the domain's live or persistent definition
// names path as a disk source.
func (c *Client) DomainUsesFile(domain, path string) (bool, error) {
	return domainUsesFile(c.virt, domain, path)
}

func domainUsesFile(v pitAPI, domain, path string) (bool, error) {
	dom, err := v.DomainLookupByName(domain)
	if err != nil {
		return false, fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	for _, f := range []golibvirt.DomainXMLFlags{0, golibvirt.DomainXMLInactive} {
		x, err := v.DomainGetXMLDesc(dom, f)
		if err != nil {
			return false, fmt.Errorf("dump domain xml: %w", err)
		}
		if diskTargetForSource(x, path) != "" {
			return true, nil
		}
	}
	return false, nil
}
