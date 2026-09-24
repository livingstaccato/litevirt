package compose

import (
	"fmt"
	"sort"

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
