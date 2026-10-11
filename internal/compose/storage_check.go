package compose

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// CheckStorage reports every VM disk whose storage: names neither a volume the
// file declares nor one of pools (the storage pools that exist in the
// cluster), positioned where data writes it, with the name it most likely
// meant. A disk with no storage: uses the default local driver and is never
// reported. f is data as parsed by ParseBytes.
//
// It is separate from ParseBytes because only the daemon knows which pools
// exist; the file alone cannot tell a pool from a typo.
func CheckStorage(data []byte, f *File, pools []string) []Problem {
	if f == nil {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil // f came from data, which parsed; nothing to position against
	}
	ps := problems{idx: indexNodes(&doc)}

	known := map[string]bool{}
	var candidates []string
	for name := range f.Volumes {
		known[name] = true
		candidates = append(candidates, name)
	}
	for _, name := range pools {
		if !known[name] {
			known[name] = true
			candidates = append(candidates, name)
		}
	}
	sort.Strings(candidates)

	for _, vmName := range sortedKeys(f.VMs) {
		vm := f.VMs[vmName]
		if vm.Kind == WorkloadKindLXC || vm.Kind == WorkloadKindOCI {
			continue // container storage does not resolve through volumes or pools
		}
		base := "vms." + vmName
		if !ps.idx.has(base) && ps.idx.has("workloads."+vmName) {
			base = "workloads." + vmName
		}
		for _, diskName := range sortedKeys(vm.Disks) {
			st := vm.Disks[diskName].Storage
			if st == "" || known[st] {
				continue
			}
			hint := fmt.Sprintf("declare it under volumes:, or create the pool with `lv pool create %s`", st)
			if s := suggest(st, candidates); s != "" {
				hint = fmt.Sprintf("did you mean %q?", s)
			}
			ps.add(base+".disks."+diskName+".storage",
				fmt.Sprintf("storage %q is neither a volume of this file nor a storage pool", st), hint)
		}
	}
	if ps.empty() {
		return nil
	}
	return ps.err().(*ValidationError).Problems
}

// CheckFixedDeviceStorage reports every VM disk on a fixed-device storage — an
// iscsi volume of the file, or a pool named in fixed (the cluster's iscsi
// pools) — whose VM would put two instances on it at once: more than one
// replica, or an update strategy that creates the new instance beside the old
// (blue-green, snapshot-and-replace). An iscsi volume or pool is one LUN and
// holds one disk, so such a VM can never deploy; it is reported where its
// disk's storage is written instead of failing part-way through a rollout.
func CheckFixedDeviceStorage(data []byte, f *File, fixed map[string]bool) []Problem {
	if f == nil {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	ps := problems{idx: indexNodes(&doc)}
	isFixed := func(st string) bool {
		if v, ok := f.Volumes[st]; ok {
			return strings.EqualFold(v.Driver, "iscsi")
		}
		return fixed[st]
	}
	for _, vmName := range sortedKeys(f.VMs) {
		vm := f.VMs[vmName]
		if vm.Kind == WorkloadKindLXC || vm.Kind == WorkloadKindOCI {
			continue
		}
		why := ""
		switch {
		case vm.Replicas != nil && *vm.Replicas > 1:
			why = fmt.Sprintf("VM %q has %d replicas", vmName, *vm.Replicas)
		case vm.Update != nil && (vm.Update.Strategy == "blue-green" || vm.Update.Strategy == "snapshot-and-replace"):
			why = fmt.Sprintf("VM %q updates by %s, which creates the new instance beside the old", vmName, vm.Update.Strategy)
		default:
			continue
		}
		base := "vms." + vmName
		if !ps.idx.has(base) && ps.idx.has("workloads."+vmName) {
			base = "workloads." + vmName
		}
		for _, diskName := range sortedKeys(vm.Disks) {
			st := vm.Disks[diskName].Storage
			if st == "" || !isFixed(st) {
				continue
			}
			ps.add(base+".disks."+diskName+".storage",
				fmt.Sprintf("storage %q is one iSCSI LUN and holds one disk, but %s", st, why),
				"give the VM one replica and an update strategy that replaces it in place (rolling, recreate), or "+
					"put the disk on storage that allocates a disk per instance")
		}
	}
	if ps.empty() {
		return nil
	}
	return ps.err().(*ValidationError).Problems
}
