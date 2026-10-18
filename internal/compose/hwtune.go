package compose

import (
	"fmt"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// Disk and NIC tuning that rides in the stored spec: discard, detect_zeroes,
// the I/O throttle and virtio-net queues. Every path that renders a domain from
// a spec — create, redefine, failover start, reconcile — calls the Apply*
// helpers below, so a tuning set once is rendered the same wherever the VM is
// (re)defined, a migration destination included.

// MaxNICQueues bounds virtio-net multiqueue. Linux allows 256 queue pairs, but
// past the guest's vCPU count a queue is dead weight, and libvirt itself warns
// on large values; Proxmox stops at 64.
const MaxNICQueues = 64

// autoQueuesCap is the most queues "queues: auto" asks for.
const autoQueuesCap = 8

// NormalizeDiscard maps the compose spellings to the stored one: on/true →
// unmap, off/false → ignore (Proxmox's discard=on). Anything else is returned
// as is for the validator to refuse.
func NormalizeDiscard(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "yes":
		return libvirt.DiscardUnmap
	case "off", "false", "no":
		return libvirt.DiscardIgnore
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// IOTuneFromSpec converts a stored disk's limits to the libvirt form. A nil
// message is the zero IOTune.
func IOTuneFromSpec(l *pb.DiskIOLimits) libvirt.IOTune {
	if l == nil {
		return libvirt.IOTune{}
	}
	return libvirt.IOTune{
		TotalBytesSec: l.TotalBytesSec, ReadBytesSec: l.ReadBytesSec, WriteBytesSec: l.WriteBytesSec,
		TotalIopsSec: l.TotalIopsSec, ReadIopsSec: l.ReadIopsSec, WriteIopsSec: l.WriteIopsSec,
		TotalBytesSecMax: l.TotalBytesSecMax, ReadBytesSecMax: l.ReadBytesSecMax, WriteBytesSecMax: l.WriteBytesSecMax,
		TotalIopsSecMax: l.TotalIopsSecMax, ReadIopsSecMax: l.ReadIopsSecMax, WriteIopsSecMax: l.WriteIopsSecMax,
		BurstSec: l.BurstSeconds,
	}
}

// ValidateDiskTuning checks one stored disk's discard, detect_zeroes and
// throttle the way libvirt and qemu will, so a bad value is refused where the
// operator typed it instead of failing a define.
func ValidateDiskTuning(d *pb.DiskSpec) error {
	if d == nil {
		return nil
	}
	if err := libvirt.ValidateDiscard(d.Discard); err != nil {
		return err
	}
	if err := libvirt.ValidateDetectZeroes(d.DetectZeroes, d.Discard); err != nil {
		return err
	}
	return IOTuneFromSpec(d.Io).Validate()
}

// ValidateQueues checks a NIC's multiqueue count against its model.
func ValidateQueues(model string, queues int32) error {
	if queues == 0 {
		return nil
	}
	if queues < 0 || queues > MaxNICQueues {
		return fmt.Errorf("queues %d: want 1 to %d", queues, MaxNICQueues)
	}
	if queues > 1 && model != "" && model != "virtio" {
		return fmt.Errorf("queues needs the virtio model (this NIC is %s)", model)
	}
	return nil
}

// DiskKey is a disk's name as every matcher compares it: an empty name in a
// stored spec is the root disk.
func DiskKey(name string) string {
	if name == "" {
		return "root"
	}
	return name
}

// IOLimitsSet reports whether a throttle names any limit. An empty message is a
// clear (`iotune: {}`), which sets nothing.
func IOLimitsSet(l *pb.DiskIOLimits) bool { return !IOTuneFromSpec(l).IsZero() }

// ApplyDiskTuning copies each stored disk's discard, detect_zeroes and
// throttle onto the DiskConfig of the same name. A disk the spec does not name
// (a hot-plugged one, a cdrom) is left as it is.
func ApplyDiskTuning(disks []libvirt.DiskConfig, spec *pb.VMSpec) {
	if spec == nil || len(spec.Disks) == 0 {
		return
	}
	byName := make(map[string]*pb.DiskSpec, len(spec.Disks))
	for _, d := range spec.Disks {
		if d == nil {
			continue
		}
		byName[DiskKey(d.Name)] = d
	}
	for i := range disks {
		if disks[i].IsISO {
			continue
		}
		d, ok := byName[DiskKey(disks[i].Name)]
		if !ok {
			continue
		}
		disks[i].Discard = d.Discard
		disks[i].DetectZeroes = d.DetectZeroes
		disks[i].IOTune = IOTuneFromSpec(d.Io)
	}
}

// ApplyNICTuning copies each stored NIC's queue count onto the NetworkConfig
// it belongs to: by MAC when the spec recorded one, else by position — but only
// onto a spec entry that recorded no MAC (a NIC's MAC is server-assigned when
// compose left it unset, and is not always written back to the spec). A NIC
// whose MAC the spec does not hold at its position is another device and is
// left alone.
//
// A NIC rendered with another model than its entry records takes only the
// tuning that model can take: no MTU and no multiqueue unless it is virtio.
// That is a NIC of a stack VM attached again under a detached NIC's MAC with
// another model, whose entry the attach leaves as the compose file wrote it
// (rewritten, it would read as a topology change and recreate the VM).
func ApplyNICTuning(nets []libvirt.NetworkConfig, spec *pb.VMSpec) {
	if spec == nil || len(spec.Network) == 0 {
		return
	}
	for i := range nets {
		var match *pb.NetworkAttachment
		if nets[i].MAC != "" {
			for _, a := range spec.Network {
				if a != nil && a.Mac != "" && strings.EqualFold(a.Mac, nets[i].MAC) {
					match = a
					break
				}
			}
		}
		// A spec entry that recorded no MAC is found by its position: the NIC's
		// ordinal when the caller knows it (so a hot-plugged or detached NIC
		// elsewhere does not move it), else its place in an equal-length list.
		if match == nil {
			pos := -1
			switch {
			case nets[i].SpecOrdinal > 0:
				pos = nets[i].SpecOrdinal - 1
			case len(spec.Network) == len(nets):
				pos = i
			}
			if pos >= 0 && pos < len(spec.Network) && spec.Network[pos] != nil && spec.Network[pos].Mac == "" {
				match = spec.Network[pos]
			}
		}
		if match != nil {
			nets[i].Queues = int(match.Queues)
			nets[i].MTU = int(match.Mtu)
			if model := nicModelOrVirtio(nets[i].Model); model != nicModelOrVirtio(match.Model) {
				if ValidateNICMTU(model, match.Mtu) != nil {
					nets[i].MTU = 0
				}
				if ValidateQueues(model, match.Queues) != nil {
					nets[i].Queues = 0
				}
			}
		}
	}
}

// nicModelOrVirtio is the model a NIC renders with: virtio when unset.
func nicModelOrVirtio(model string) string {
	if model == "" {
		return "virtio"
	}
	return model
}

// ApplyNICTuningByPosition is ApplyNICTuning for a caller that built its NICs
// from the spec's own list, one for one and in order, with MACs of its own (a
// clone, a restore under a new name): the position is the identity.
func ApplyNICTuningByPosition(nets []libvirt.NetworkConfig, spec *pb.VMSpec) {
	if spec == nil {
		return
	}
	for i := range nets {
		if i < len(spec.Network) && spec.Network[i] != nil {
			nets[i].Queues = int(spec.Network[i].Queues)
			nets[i].MTU = int(spec.Network[i].Mtu)
		}
	}
}

// ResolveAutoQueues is what "queues: auto" means: one queue per vCPU up to 8,
// and no multiqueue for a single-vCPU guest.
func ResolveAutoQueues(vcpus int) int32 {
	if vcpus <= 1 {
		return 0
	}
	if vcpus > autoQueuesCap {
		return autoQueuesCap
	}
	return int32(vcpus)
}
