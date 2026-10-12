package corrosion

import (
	"encoding/json"
	"slices"
	"strings"
)

// VMMigratePriority returns a VM's compose `migrate.priority` (proto
// MigrationPolicy.priority, tag 6) from its stored spec JSON. Higher is more
// important; unset, an empty spec or one that does not parse is 0, the
// documented default.
//
// The value travels inside vms.spec, which already replicates, so a build
// that does not read it (one older than this) simply ignores it: no column,
// proto tag or statement shape was added for it.
func VMMigratePriority(vm VMRecord) int32 {
	if vm.Spec == "" {
		return 0
	}
	var spec struct {
		Migrate *struct {
			Priority int32 `json:"priority"`
		} `json:"migrate"`
	}
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil || spec.Migrate == nil {
		return 0
	}
	return spec.Migrate.Priority
}

// SortVMsByMigratePriority orders vms in place, highest migrate.priority
// first, ties by name, and returns vms.
//
// The tie-break is the name, not the order the VMs came in. ListVMs has no
// ORDER BY, so it returns a replica's rows in its own insertion order, which
// differs between nodes that received the rows in a different order: two
// coordinators recovering the same host could otherwise walk equal-priority
// VMs differently. By name, every node agrees.
//
// Priority only ORDERS work. Every gate a recovery, a drain or a start passes
// (quorum, fencing, recovery claims, capacity) still decides whether each VM
// may act at all; a higher priority never lets a VM past one.
func SortVMsByMigratePriority(vms []VMRecord) []VMRecord {
	if len(vms) < 2 {
		return vms
	}
	prio := make(map[string]int32, len(vms))
	for _, vm := range vms {
		prio[vm.Name] = VMMigratePriority(vm)
	}
	slices.SortStableFunc(vms, func(a, b VMRecord) int {
		switch pa, pb := prio[a.Name], prio[b.Name]; {
		case pa > pb:
			return -1
		case pa < pb:
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return vms
}
