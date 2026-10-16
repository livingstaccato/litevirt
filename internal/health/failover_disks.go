package health

import (
	"sort"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// failoverDiskConfigs is the disk list of a domain this reconciler renders,
// from the VM's disk rows that are to be attached, laid out as CreateVM and a
// redefine lay it out: the spec's disks first, in the spec's order (the boot
// disk is the first), on the spec's bus with its cache and SCSI controller
// model; then any disk hot-plugged since the create (a row with no spec
// entry), on its recorded bus and target, in target order.
//
// rows are in whatever order the database returned them; a render in that
// order boots whichever disk name sorts first.
func failoverDiskConfigs(spec *pb.VMSpec, rows []corrosion.DiskRecord) []lv.DiskConfig {
	byName := make(map[string]corrosion.DiskRecord, len(rows))
	for _, d := range rows {
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
		out = append(out, lv.DiskConfig{
			Name:            d.DiskName,
			Path:            d.Path,
			Bus:             bus,
			Cache:           sd.Cache,
			ControllerModel: sd.ControllerModel,
		})
	}
	var hot []corrosion.DiskRecord
	for _, d := range rows {
		if !inSpec[d.DiskName] {
			hot = append(hot, d)
		}
	}
	sort.SliceStable(hot, func(i, j int) bool { return hot[i].TargetDev < hot[j].TargetDev })
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

// recordedDiskBus is a disk row's bus: the stored one, else inferred from its
// target's prefix (sdX scsi, hdX ide, else virtio), as a redefine infers it.
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
