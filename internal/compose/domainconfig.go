package compose

import (
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// DomainConfig assembles the libvirt VMConfig fields derived from a stored
// VMSpec. CreateVM, a full-regeneration redefine and the reconciler's start
// (failover, onboot, self-heal) build their domain from it, so those
// scalar settings (CPU, memory, consoles, machine, firmware choice,
// resources, disk and NIC tuning) come out the same on each.
//
// Disks, networks and hostdevs are passed in, and each path sources them its
// own way, so they can still differ between paths. Firmware/nvram/TPM, the
// cloud-init seed and USB devices are applied by the caller.
func DomainConfig(spec *pb.VMSpec, disks []libvirt.DiskConfig, nets []libvirt.NetworkConfig, hostdevs []libvirt.HostdevConfig) libvirt.VMConfig {
	cfg := libvirt.VMConfig{
		Name:         spec.Name,
		UUID:         spec.Uuid,
		CPU:          int(spec.Cpu),
		MaxCPU:       int(spec.MaxCpu),
		CPUMode:      spec.CpuMode,
		CPUModel:     spec.CpuModel,
		MemoryMiB:    int(spec.MemoryMib),
		MinMemoryMiB: int(spec.MinMemoryMib),
		MaxMemoryMiB: int(spec.MaxMemoryMib),
		// Memory hot-add (virtio-mem): the boot cell and the ceiling.
		HotplugBaseMiB: int(spec.MemoryHotplugBaseMib),
		HotplugMaxMiB:  int(spec.MemoryHotplugMaxMib),
		Machine:        spec.Machine,
		Firmware:       spec.Firmware,
		GuestAgent:     spec.GuestAgent,
		EnableVNC:      !spec.DisableVnc,
		EnableSPICE:    spec.EnableSpice,
		Disks:          disks,
		Networks:       nets,
		Hostdevs:       hostdevs,
		Boot:           spec.Boot,
		CPULimit:       spec.CpuLimit,
		CPUShares:      int(spec.CpuShares),
	}
	// Disk discard / detect_zeroes / I/O throttle and NIC queues ride in the
	// stored spec, so every render of the domain carries them.
	ApplyDiskTuning(cfg.Disks, spec)
	ApplyNICTuning(cfg.Networks, spec)
	if r := spec.Resources; r != nil {
		cfg.HugePages = r.Hugepages
		cfg.IOThreads = int(r.IoThreads)
		for _, pin := range r.CpuPinning {
			cfg.CPUPinning = append(cfg.CPUPinning, int(pin))
		}
		if np := r.NumaPolicy; np != nil {
			cfg.NUMAPolicy = &libvirt.NUMAPolicy{
				PreferredNode: int(np.PreferredNode),
				Strict:        np.Strict,
			}
		}
	}
	return cfg
}
