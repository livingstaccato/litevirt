package libvirt

import (
	"encoding/xml"
	"fmt"
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
	DomainGetXMLDesc(dom golibvirt.Domain, flags golibvirt.DomainXMLFlags) (string, error)
	DomainDefineXML(xml string) (golibvirt.Domain, error)
	DomainSnapshotCreateXML(dom golibvirt.Domain, xml string, flags uint32) (golibvirt.DomainSnapshot, error)
	DomainBlockCommit(dom golibvirt.Domain, disk string, base, top golibvirt.OptString, bandwidth uint64, flags golibvirt.DomainBlockCommitFlags) error
	DomainGetBlockJobInfo(dom golibvirt.Domain, path string, flags uint32) (int32, int32, uint64, uint64, uint64, error)
	DomainBlockJobAbort(dom golibvirt.Domain, path string, flags golibvirt.DomainBlockJobAbortFlags) error
}

var _ pitAPI = (*golibvirt.Libvirt)(nil)

// pitCommitPoll and pitCommitTimeout bound the wait for an active commit to
// reach its ready state. Variables so the tests run without the real waits.
var (
	pitCommitPoll    = 500 * time.Millisecond
	pitCommitTimeout = 30 * time.Minute
)

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
		return true, nil
	} else if _, err := v.DomainSnapshotCreateXML(dom, snapXML, base); err != nil {
		return false, fmt.Errorf("external disk snapshot (quiesced: %v; crash-consistent: %w)", qerr, err)
	}
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
// domain not running on overlay is left alone (nil). The persistent definition
// is checked afterwards too: one that still names overlay is rewritten to
// diskPath, since a restart from the overlay would lose every write made after
// the pivot. The overlay file itself is the caller's to remove, once
// DomainUsesFile says nothing references it.
func (c *Client) CommitDiskOverlay(domain, diskPath, overlay string) error {
	return commitDiskOverlay(c.virt, domain, diskPath, overlay)
}

func commitDiskOverlay(v pitAPI, domain, diskPath, overlay string) error {
	dom, err := v.DomainLookupByName(domain)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	live, err := v.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("dump domain xml: %w", err)
	}
	if dev := diskTargetForSource(live, overlay); dev != "" {
		if err := v.DomainBlockCommit(dom, dev, golibvirt.OptString{diskPath}, golibvirt.OptString{}, 0,
			golibvirt.DomainBlockCommitActive); err != nil {
			return fmt.Errorf("block-commit %s: %w", dev, err)
		}
		if err := waitPITCommitReady(v, dom, dev); err != nil {
			_ = v.DomainBlockJobAbort(dom, dev, 0)
			return fmt.Errorf("block-commit %s: %w", dev, err)
		}
		if err := v.DomainBlockJobAbort(dom, dev, golibvirt.DomainBlockJobAbortPivot); err != nil {
			return fmt.Errorf("pivot %s onto %s: %w", dev, diskPath, err)
		}
		after, err := v.DomainGetXMLDesc(dom, 0)
		if err != nil {
			return fmt.Errorf("dump domain xml after pivot: %w", err)
		}
		if diskTargetForSource(after, overlay) != "" {
			return fmt.Errorf("disk %s still runs on %s after the pivot", dev, overlay)
		}
	}
	inactive, err := v.DomainGetXMLDesc(dom, golibvirt.DomainXMLInactive)
	if err != nil {
		return fmt.Errorf("dump persistent domain xml: %w", err)
	}
	if dev := diskTargetForSource(inactive, overlay); dev != "" {
		fixed, changed, err := RewriteDiskSourceFile(inactive, dev, overlay, diskPath)
		if err != nil {
			return fmt.Errorf("repoint persistent disk %s to %s: %w", dev, diskPath, err)
		}
		if changed {
			if _, err := v.DomainDefineXML(fixed); err != nil {
				return fmt.Errorf("redefine persistent disk %s on %s: %w", dev, diskPath, err)
			}
		}
	}
	return nil
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
		if end > 0 && cur >= end {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not ready to pivot after %s", pitCommitTimeout)
		}
		time.Sleep(pitCommitPoll)
	}
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
