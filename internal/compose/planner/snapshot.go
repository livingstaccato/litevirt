// Package planner resolves a compose file into a fully-planned set of resource
// actions against a point-in-time cluster state snapshot. The planner makes all
// placement, device, network target, and LB decisions up front so that execution
// is deterministic and requires no further queries.
package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ClusterState is a point-in-time snapshot of the cluster, loaded once before
// planning. The planner works entirely off this snapshot — no Corrosion queries
// during the resolve phase.
type ClusterState struct {
	Hosts      []corrosion.HostRecord
	VMs        []corrosion.VMRecord
	Containers []corrosion.ContainerRecord // cluster-wide; diffed per-stack via LabelStack
	Networks   []corrosion.NetworkRecord
	LBs        []corrosion.LBConfigRecord
	Devices    map[string][]corrosion.PCIDeviceRecord // host → available devices

	// HeldDevices is host → the PCI devices assigned to a VM. Only an update of
	// the VM that holds one sees it: Resolve adds a VM's own devices to its
	// update's pool (placement.Request.ReuseDevicesOf). Nothing else is
	// placed against them.
	HeldDevices map[string][]corrosion.PCIDeviceRecord

	ImageHosts map[string][]string // imageName → hosts that have it (status=ready)

	// Mappings is every resource mapping as name → host → its addresses on
	// that host (address order), the form placement resolves a mapping
	// selector with. ResolveMappingAddress, which the owner allocates with,
	// takes the first address, and so does placement.
	Mappings map[string]map[string][]string

	// Capacity is the cluster-wide capacity policy; see placement.Request.Capacity.
	Capacity corrosion.CapacityPolicy

	// Observations is each host's effective-capacity observation, folded into
	// batch placement so runtime-only usage counts against headroom and an
	// incomplete/stale host is excluded — the same rules the single-VM Select
	// path applies.
	Observations []corrosion.HostCapacityObservation

	// RecordedDisks counts the disks recorded for each VM a deploy would
	// retry (one in a transient or error state): what of it was already made,
	// which a retry repairs rather than replaces.
	RecordedDisks map[string]int

	// NICSecurity is, for each VM of the stack being planned, its NICs with
	// the security-group binding and guard the firewall enforces now
	// (LoadStackNICSecurity). A deploy compares the file with these, not with
	// the create-time values in the stored spec
	// (compose.OverlayLiveNICSecurity). A VM missing here is compared with
	// its stored spec.
	NICSecurity map[string][]compose.LiveNIC

	// NICSecurityGate is what the deploying caller may restore of a NIC's
	// security (compose.ApplyNICSecurityGate). The zero value withholds
	// every restore that may weaken protection.
	NICSecurityGate compose.NICSecurityGate
}

// LoadClusterState queries Corrosion once and builds an immutable snapshot.
// capacity is the cluster-wide capacity policy — a parameter (not loaded here)
// because it comes from daemon config, not Corrosion; requiring it keeps any
// new caller from silently planning under default capacity.
func LoadClusterState(ctx context.Context, db *corrosion.Client, capacity corrosion.CapacityPolicy) (*ClusterState, error) {
	hosts, err := corrosion.ListHosts(ctx, db)
	if err != nil {
		return nil, err
	}

	vms, err := corrosion.ListVMs(ctx, db, "", "")
	if err != nil {
		return nil, err
	}

	containers, err := corrosion.ListContainers(ctx, db, "")
	if err != nil {
		return nil, err
	}

	networks, err := corrosion.ListNetworks(ctx, db)
	if err != nil {
		return nil, err
	}

	lbs, err := corrosion.ListLBConfigs(ctx, db)
	if err != nil {
		return nil, err
	}

	// Load available PCI devices per host.
	devices := make(map[string][]corrosion.PCIDeviceRecord, len(hosts))
	held := make(map[string][]corrosion.PCIDeviceRecord, len(hosts))
	for _, h := range hosts {
		if h.State != "active" {
			continue
		}
		devs, err := corrosion.GetAvailableDevicesWithTopology(ctx, db, h.Name, "")
		if err != nil {
			continue
		}
		devices[h.Name] = devs
		all, err := corrosion.ListPCIDevices(ctx, db, h.Name, "")
		if err != nil {
			continue
		}
		for _, d := range all {
			if d.VMName != "" {
				held[h.Name] = append(held[h.Name], d)
			}
		}
	}

	rms, err := corrosion.ListResourceMappings(ctx, db)
	if err != nil {
		return nil, err
	}
	mappings := make(map[string]map[string][]string, len(rms))
	for _, m := range rms {
		byHost := map[string][]string{}
		for _, d := range m.Devices { // address order within a host
			if d.Address == "" { // ResolveMappingAddress skips these too
				continue
			}
			byHost[d.HostName] = append(byHost[d.HostName], d.Address)
		}
		mappings[m.Name] = byHost
	}

	// Effective-capacity observations. Best-effort: a missing set degrades to
	// the DB-only arithmetic (exactly what the snapshot had before), never to
	// a failed plan.
	observations, err := corrosion.ListHostCapacityObservations(ctx, db)
	if err != nil {
		observations = nil
	}

	// Load image availability: which hosts have each image ready.
	images, err := corrosion.ListImages(ctx, db)
	if err != nil {
		return nil, err
	}
	imageHosts := make(map[string][]string, len(images))
	for _, img := range images {
		ihs, err := corrosion.GetImageHosts(ctx, db, img.Name)
		if err != nil {
			continue
		}
		for _, ih := range ihs {
			if ih.Status == "ready" {
				imageHosts[img.Name] = append(imageHosts[img.Name], ih.HostName)
			}
		}
	}

	recordedDisks := map[string]int{}
	for _, vm := range vms {
		if !compose.IsTransientOrErrorState(vm.State) {
			continue
		}
		disks, err := corrosion.GetVMDisks(ctx, db, vm.Name)
		if err != nil {
			return nil, fmt.Errorf("read the disks of %s: %w", vm.Name, err)
		}
		recordedDisks[vm.Name] = len(disks)
	}

	return &ClusterState{
		RecordedDisks: recordedDisks,
		Hosts:         hosts,
		VMs:           vms,
		Containers:    containers,
		Networks:      networks,
		LBs:           lbs,
		Devices:       devices,
		Mappings:      mappings,
		HeldDevices:   held,
		ImageHosts:    imageHosts,
		Capacity:      capacity,
		Observations:  observations,
	}, nil
}

// LoadStackNICSecurity reads the live NIC security of the stack's VMs into
// state.NICSecurity (corrosion.LiveNICSecurity: the current incarnation's
// guard record only, none for a NIC without one). Only the planned stack is
// read, so an unrelated stack's VM cannot fail the plan. A read failure fails
// the plan rather than comparing with create-time values.
func LoadStackNICSecurity(ctx context.Context, db *corrosion.Client, state *ClusterState, stack string) error {
	state.NICSecurity = map[string][]compose.LiveNIC{}
	for _, vm := range state.VMs {
		if vm.StackName != stack {
			continue
		}
		var sp struct {
			UUID string `json:"uuid"`
		}
		_ = json.Unmarshal([]byte(vm.Spec), &sp)
		live, err := corrosion.LiveNICSecurity(ctx, db, vm.Name, sp.UUID)
		if err != nil {
			return fmt.Errorf("read the NIC security of %s: %w", vm.Name, err)
		}
		state.NICSecurity[vm.Name] = live
	}
	return nil
}
