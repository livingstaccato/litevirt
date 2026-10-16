package health

import (
	"sort"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// failoverDiskConfigs is the disk list of a domain this reconciler renders,
// from the VM's disk rows that are to be attached. The first disk is the one
// the generator gives boot order 1, so it is the boot disk:
//
//   - the spec's disks first, in the spec's order (the root is the first), on
//     the spec's bus with its cache and SCSI controller model;
//   - then any disk hot-plugged since the create (a row with no spec entry),
//     on its recorded bus, in target order. When the spec lists no disks at
//     all, the root row (rootRow) goes first.
//
// Every disk keeps the target its row records, so a spec disk that is
// withheld or gone does not shift a later one into another disk's slot. Rows
// that are not disk-shaped (DeviceKind) are left out, as on a redefine.
//
// rows are in whatever order the database returned them; a render in that
// order boots whichever disk name sorts first.
func failoverDiskConfigs(spec *pb.VMSpec, rows []corrosion.DiskRecord) []lv.DiskConfig {
	var disks []corrosion.DiskRecord
	for _, d := range rows {
		if d.DeviceKind == "" || d.DeviceKind == "disk" {
			disks = append(disks, d)
		}
	}
	byName := make(map[string]corrosion.DiskRecord, len(disks))
	for _, d := range disks {
		byName[d.DiskName] = d
	}
	var out []lv.DiskConfig
	inSpec := map[string]bool{}
	for _, sd := range spec.GetDisks() {
		name := sd.Name
		if name == "" {
			name = "root"
		}
		if inSpec[name] {
			continue
		}
		inSpec[name] = true
		d, ok := byName[name]
		if !ok {
			continue
		}
		bus := sd.Bus
		if bus == "" {
			bus = "virtio"
		}
		// The recorded target, when it names a device of the spec's bus;
		// otherwise the generator's positional one.
		target := ""
		if len(d.TargetDev) > 2 && d.TargetDev[:2] == lv.DiskDevName(bus, 0)[:2] {
			target = d.TargetDev
		}
		out = append(out, lv.DiskConfig{
			Name:            d.DiskName,
			Path:            d.Path,
			Bus:             bus,
			Cache:           sd.Cache,
			ControllerModel: sd.ControllerModel,
			TargetDev:       target,
		})
	}
	var hot []corrosion.DiskRecord
	for _, d := range disks {
		if !inSpec[d.DiskName] {
			hot = append(hot, d)
		}
	}
	sort.SliceStable(hot, func(i, j int) bool { return hot[i].TargetDev < hot[j].TargetDev })
	if len(spec.GetDisks()) == 0 {
		if i := rootRow(hot); i > 0 {
			root := hot[i]
			hot = append(append([]corrosion.DiskRecord{root}, hot[:i]...), hot[i+1:]...)
		}
	}
	for _, d := range hot {
		out = append(out, lv.DiskConfig{
			Name:            d.DiskName,
			Path:            d.Path,
			Bus:             recordedDiskBus(d),
			ControllerModel: d.ControllerModel,
			TargetDev:       d.TargetDev,
		})
	}
	return out
}

// rootRow is the index of the root among the disk rows of a VM whose spec
// lists no disks: the row named root, else the one built from an image, else
// the first target of its bus (vda, sda, hda); -1 when none is.
func rootRow(rows []corrosion.DiskRecord) int {
	for _, match := range []func(corrosion.DiskRecord) bool{
		func(d corrosion.DiskRecord) bool { return d.DiskName == "root" },
		func(d corrosion.DiskRecord) bool { return d.BackingImage != "" },
		func(d corrosion.DiskRecord) bool { return len(d.TargetDev) == 3 && d.TargetDev[2] == 'a' },
	} {
		for i, d := range rows {
			if match(d) {
				return i
			}
		}
	}
	return -1
}

// recordedDiskBus is a disk row's bus: the stored one, else inferred from its
// target's prefix (sdX scsi, hdX ide, else virtio).
func recordedDiskBus(d corrosion.DiskRecord) string {
	if d.Bus != "" {
		return d.Bus
	}
	if d.TargetDev != "" {
		switch d.TargetDev[0] {
		case 's':
			return "scsi"
		case 'h':
			return "ide"
		}
	}
	return "virtio"
}
