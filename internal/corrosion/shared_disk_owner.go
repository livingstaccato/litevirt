package corrosion

import (
	"context"
	"fmt"
	"strings"
)

// SharedDiskOwnerProvedOff reads host — the host a shared disk's row names,
// or a VM's owner — and whether it is PROVEN powered off: recorded 'fenced'
// over a proof-grade newest fence (FenceRecordProvesOff), or no longer a
// member (tombstoned, recorded 'removed', or with no row) over a proof-grade
// newest fence of its LAST life (RemovedHostProvedOff, review R4-I1). Any
// other state proves nothing. h is nil for a host with no live row.
//
// It is the one reading of "may this host still be writing the disk" that a
// promotion's reattach (grpcapi sharedReattachVerdict) and every start that
// builds a domain from the disk rows (JudgeSharedDiskRows) share.
func SharedDiskOwnerProvedOff(ctx context.Context, c *Client, host string) (h *HostRecord, provedOff bool, err error) {
	h, err = GetHost(ctx, c, host)
	if err != nil {
		return nil, false, err
	}
	switch {
	case h == nil || h.State == "removed":
		provedOff, err = RemovedHostProvedOff(ctx, c, host)
	case h.State == "fenced":
		provedOff, err = FenceRecordProvesOff(ctx, c, host)
	}
	return h, provedOff, err
}

// SharedDiskOwnerVerdict is the manual rule for a shared disk whose owner is
// another host: attached only when that owner is fenced, removed or no longer
// a member AND proven off (SharedDiskOwnerProvedOff). An owner whose state or
// fence record cannot be read never passes (fail closed). why says, when it
// does not pass, why — in words an operator reads in a partial report.
func SharedDiskOwnerVerdict(owner string, h *HostRecord, provedOff bool, err error) (ok bool, why string) {
	switch {
	case err != nil:
		return false, fmt.Sprintf("the state of its owner %s cannot be read: %v", owner, err)
	case provedOff && (h == nil || h.State == "removed" || h.State == "fenced"):
		return true, ""
	case h == nil || h.State == "removed":
		return false, fmt.Sprintf("its owner %s is no longer a member of the cluster, but not proven powered off: removing a host "+
			"does not power it off, and its newest fence is not an IPMI power-off or an operator's confirmation, "+
			"so it may still be writing the disk", owner)
	case h.State == "fenced":
		return false, fmt.Sprintf("its owner %s is fenced, but not proven powered off: its newest fence is not an IPMI power-off or "+
			"an operator's confirmation, so it may still be writing the disk", owner)
	default:
		return false, fmt.Sprintf("its owner %s is %s, not fenced (and no proof-grade fence was verified)", owner, h.State)
	}
}

// WithheldSharedDisk is a shared disk a domain was built without: its row
// names Owner, another host, which did not pass SharedDiskOwnerVerdict.
type WithheldSharedDisk struct {
	Disk  DiskRecord
	Owner string
	Why   string
}

// JudgeSharedDiskRows splits a VM's disk rows, for a domain this host (self)
// builds from them, into the disks to attach and the shared ones withheld
// (review R4-I2). A disk on shared storage (shared) whose row names another
// host is attached only when that host passes SharedDiskOwnerVerdict: a
// partial promotion leaves such a row naming the VM's old owner, which may
// still be writing the disk, and the next domain built from the rows — onboot,
// the reconciler's restart, a redefine — would otherwise attach it without
// judging that host, two writers on one disk. A row naming this host or no
// host, and a disk not on shared storage, is attached as before. Each host is
// read once.
func JudgeSharedDiskRows(ctx context.Context, c *Client, disks []DiskRecord, self string, shared func(DiskRecord) bool) (attach []DiskRecord, withheld []WithheldSharedDisk) {
	type verdict struct {
		ok  bool
		why string
	}
	judged := map[string]verdict{}
	for _, d := range disks {
		if d.HostName == "" || d.HostName == self || !shared(d) {
			attach = append(attach, d)
			continue
		}
		v, seen := judged[d.HostName]
		if !seen {
			h, proved, err := SharedDiskOwnerProvedOff(ctx, c, d.HostName)
			v.ok, v.why = SharedDiskOwnerVerdict(d.HostName, h, proved, err)
			judged[d.HostName] = v
		}
		if v.ok {
			attach = append(attach, d)
			continue
		}
		withheld = append(withheld, WithheldSharedDisk{Disk: d, Owner: d.HostName, Why: v.why})
	}
	return attach, withheld
}

// WithheldSharedDiskDetail is the report of a domain of vm built on self
// without the withheld shared disks: each disk, why, and the remedy. "" when
// none is withheld.
func WithheldSharedDiskDetail(vm, self string, withheld []WithheldSharedDisk) string {
	if len(withheld) == 0 {
		return ""
	}
	var parts []string
	owners := map[string]bool{}
	var order []string
	for _, w := range withheld {
		parts = append(parts, fmt.Sprintf("%s (shared (%s) at %s, its row naming %s): %s",
			w.Disk.DiskName, w.Disk.StorageType, w.Disk.Path, w.Owner, w.Why))
		if !owners[w.Owner] {
			owners[w.Owner] = true
			order = append(order, w.Owner)
		}
	}
	var remedies []string
	for _, o := range order {
		remedies = append(remedies, fmt.Sprintf("once %s is powered off, `lv host fence-confirm %s` (with recovery claims "+
			"enforced, a confirmation may also let the failover coordinator recover every workload still recorded on %s), "+
			"then `lv restart %s`. Until %s is proven off no move of %s re-homes the disk's row, and "+
			"`lv doctor repair-owner` refuses to",
			o, o, o, vm, o, vm))
	}
	return fmt.Sprintf("the domain of VM %s on %s was built without its shared disk(s) %s. A domain built from the disk rows "+
		"attaches a shared disk whose row names another host only once that host is proven powered off. To attach it: %s",
		vm, self, strings.Join(parts, "; "), strings.Join(remedies, "; "))
}

// SharedRowKeepsOwner reports whether a move of a VM from source to dest must
// leave disk d's row naming its own host (review I1): d is on shared storage
// and its row names a THIRD host — neither the host the VM leaves nor the one
// it goes to, as a partial promotion leaves a disk it did not attach — that
// is not proven powered off (SharedDiskOwnerVerdict). Re-pointing that row at
// dest would make it "this host's" there, and the next domain built from the
// rows would attach it without judging the host that may still be writing
// it. Kept, the row is judged at every build (JudgeSharedDiskRows) and the
// disk stays withheld until that host is proven off. A row naming the source
// moves as before: the source is the host the move itself is judged by (its
// fence, a live migration's own handoff). why says why it is kept.
func SharedRowKeepsOwner(ctx context.Context, c *Client, d DiskRecord, source, dest string) (keep bool, why string) {
	if d.HostName == "" || d.HostName == source || d.HostName == dest {
		return false, ""
	}
	if !DiskOnSharedStorage(ctx, c, d, source, dest) {
		return false, ""
	}
	h, proved, err := SharedDiskOwnerProvedOff(ctx, c, d.HostName)
	ok, why := SharedDiskOwnerVerdict(d.HostName, h, proved, err)
	return !ok, why
}

// vmHostOf is the host vm's live row names, "" when there is none.
func vmHostOf(ctx context.Context, c *Client, vm string) (string, error) {
	rows, err := c.Query(ctx, `SELECT host_name FROM vms WHERE name = ? AND deleted_at IS NULL`, vm)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("host_name"), nil
}

// WithheldBootDisk returns the withheld disk that is the VM's boot disk, if
// one is (review m1): the disk named "root", or the one at the first target
// of its bus (vda, sda, hda). A domain built without it boots nothing, which
// is worse than not starting, so the start is deferred instead.
func WithheldBootDisk(withheld []WithheldSharedDisk) (WithheldSharedDisk, bool) {
	for _, w := range withheld {
		switch {
		case w.Disk.DiskName == "root", w.Disk.TargetDev == "vda", w.Disk.TargetDev == "sda", w.Disk.TargetDev == "hda":
			return w, true
		}
	}
	return WithheldSharedDisk{}, false
}
