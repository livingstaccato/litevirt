package compose

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parse reads and validates a compose file from disk. Validation problems name
// the file.
func Parse(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read compose file: %w", err)
	}
	return ParseNamed(path, data)
}

// ParseBytes parses and validates compose YAML from a byte slice. Every
// problem found is returned together, as a *ValidationError.
func ParseBytes(data []byte) (*File, error) {
	return ParseNamed("", data)
}

// ParseNamed is ParseBytes for YAML read from the file name, which prefixes
// the position of every validation problem.
func ParseNamed(name string, data []byte) (*File, error) {
	f, err := parseWith(data, parseOpts{})
	var ve *ValidationError
	if errors.As(err, &ve) {
		ve.File = name
	}
	return f, err
}

func parseWith(data []byte, opts parseOpts) (*File, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse compose YAML: %w", err)
	}
	v := &validator{ps: problems{idx: indexNodes(&doc)}, origin: map[string]string{}, stored: opts.stored}

	var f File
	if root := documentRoot(&doc); root != nil {
		if !opts.stored {
			v.checkFileFields(root)
		}
		if err := root.Decode(&f); err != nil {
			// A field that did not decode leaves the file half-read;
			// checking the rest would report the gaps as problems of
			// their own.
			v.decodeError(err)
			return nil, v.ps.err()
		}
	}

	for name := range f.VMs {
		v.origin[name] = "vms"
	}
	for name := range f.Workloads {
		v.origin[name] = "workloads"
	}
	v.foldWorkloads(&f)
	// A broken extends leaves its children unmerged; checking them would
	// report what they would have inherited as missing.
	if v.resolveExtends(&f) {
		inferHealthTypes(&f)
		v.validate(&f)
	}
	if err := v.ps.err(); err != nil {
		return nil, err
	}
	return &f, nil
}

// validator collects every problem in one compose file.
type validator struct {
	ps problems
	// origin is the map each workload was written under: "vms" or
	// "workloads" (which the parser folds into VMs).
	origin map[string]string
	// stored: re-reading YAML accepted earlier (ParseStored); checks that
	// only guard against a person's mistakes are skipped.
	stored bool
}

// vm is the path of the workload called name.
func (v *validator) vm(name string) string {
	if o := v.origin[name]; o != "" {
		return o + "." + name
	}
	return "vms." + name
}

// decodeError turns a YAML decoding error into problems: one per field that
// did not decode, positioned at its line.
func (v *validator) decodeError(err error) {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		v.ps.add("", err.Error(), "")
		return
	}
	for _, e := range te.Errors {
		line, msg := 0, e
		if rest, ok := strings.CutPrefix(e, "line "); ok {
			if i := strings.Index(rest, ": "); i > 0 {
				if n, err := strconv.Atoi(rest[:i]); err == nil {
					line, msg = n, rest[i+2:]
				}
			}
		}
		path, col := v.ps.idx.atLine(line)
		v.ps.list = append(v.ps.list, Problem{Path: path, Line: line, Column: col, Message: msg})
	}
}

// foldWorkloads merges any `workloads:` entries into the canonical
// `VMs` map so the rest of the parser / planner only has to look at
// one place. Each entry's Kind defaults to "vm" — that's the legacy
// behaviour, indistinguishable from a `vms:` entry. Kinds "lxc" and
// "oci" pass through to the deploy dispatcher, which routes to the
// Containers runtime.
//
// Conflicts (same name in both `vms:` and `workloads:`) are an error
// rather than a silent overwrite — the operator's intent is ambiguous.
func (v *validator) foldWorkloads(f *File) {
	if len(f.Workloads) == 0 {
		return
	}
	if f.VMs == nil {
		f.VMs = make(map[string]VMDef, len(f.Workloads))
	}
	for name, wl := range f.Workloads {
		if _, dup := f.VMs[name]; dup {
			v.ps.add("workloads."+name, fmt.Sprintf("workload %q also appears under vms:", name), "pick one map")
			continue
		}
		if wl.Kind == "" {
			wl.Kind = WorkloadKindVM
		}
		switch wl.Kind {
		case WorkloadKindVM, WorkloadKindLXC, WorkloadKindOCI:
		default:
			v.ps.add("workloads."+name+".kind", fmt.Sprintf("unknown kind %q", wl.Kind), "want vm | lxc | oci")
			continue
		}
		f.VMs[name] = wl
	}
	// Wipe Workloads so downstream code doesn't double-process.
	f.Workloads = nil
}

// resolveExtends processes service inheritance. VMs with `extends: <base>`
// inherit all fields from the base, with child values taking precedence.
// Merge rules: scalars — child wins (zero-value = inherit). Maps — merge keys,
// child wins collisions. Slices — child replaces entirely. Pointer structs —
// child nil = inherit parent, child non-nil = use child's.
//
// Nothing is merged when any extends is broken: every broken one is
// reported, and ok is false.
func (v *validator) resolveExtends(f *File) (ok bool) {
	if len(f.VMs) == 0 {
		return true
	}
	broken := false

	// Build dependency graph and detect cycles via topological sort.
	// inDegree tracks how many extends-dependencies each VM has (0 or 1).
	inDegree := make(map[string]int)
	dependents := make(map[string][]string) // base → list of VMs that extend it

	for name := range f.VMs {
		inDegree[name] = 0
	}
	for name, vm := range f.VMs {
		if vm.Extends == "" {
			continue
		}
		if _, ok := f.VMs[vm.Extends]; !ok {
			v.ps.add(v.vm(name)+".extends", fmt.Sprintf("vm %q extends unknown vm %q", name, vm.Extends), "")
			broken = true
			continue
		}
		if vm.Extends == name {
			v.ps.add(v.vm(name)+".extends", fmt.Sprintf("vm %q extends itself", name), "")
			broken = true
			continue
		}
		inDegree[name]++
		dependents[vm.Extends] = append(dependents[vm.Extends], name)
	}

	// Kahn's algorithm for topological sort.
	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	var order []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		order = append(order, cur)
		for _, dep := range dependents[cur] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if len(order) != len(f.VMs) {
		var cyc []string
		for name, deg := range inDegree {
			if deg > 0 {
				cyc = append(cyc, name)
			}
		}
		sort.Strings(cyc)
		v.ps.add(v.vm(cyc[0])+".extends",
			fmt.Sprintf("extends cycle detected (involves %d vm(s): %s)", len(cyc), strings.Join(cyc, ", ")), "")
		broken = true
	}
	if broken {
		return false
	}

	// Apply inheritance in topological order (bases resolved before children).
	for _, name := range order {
		vm := f.VMs[name]
		if vm.Extends == "" {
			continue
		}
		base := f.VMs[vm.Extends]
		merged := mergeVMDef(base, vm)
		merged.Extends = "" // clear after resolution
		f.VMs[name] = merged
	}
	return true
}

// mergeVMDef merges a base VMDef into a child. Child values take precedence.
func mergeVMDef(base, child VMDef) VMDef {
	m := base // start with base, overlay child

	// Scalars — child wins if non-zero
	if child.Image != "" {
		m.Image = child.Image
	}
	if child.ISO != "" {
		m.ISO = child.ISO
	}
	if child.Firmware != "" {
		m.Firmware = child.Firmware
	}
	if child.Machine != "" {
		m.Machine = child.Machine
	}
	if child.CPU != 0 {
		m.CPU = child.CPU
	}
	if child.Memory != 0 {
		m.Memory = child.Memory
	}
	if child.MinMemory != 0 {
		m.MinMemory = child.MinMemory
	}
	if child.MaxMemory != 0 {
		m.MaxMemory = child.MaxMemory
	}
	if child.Onboot {
		m.Onboot = child.Onboot
	}
	if child.StartupOrder != 0 {
		m.StartupOrder = child.StartupOrder
	}
	if child.StartDelay != 0 {
		m.StartDelay = child.StartDelay
	}
	if child.StopDelay != 0 {
		m.StopDelay = child.StopDelay
	}
	if child.IPHint != "" {
		m.IPHint = child.IPHint
	}
	if child.StopGracePeriod != "" {
		m.StopGracePeriod = child.StopGracePeriod
	}

	// Pointer scalars — child non-nil wins
	if child.Replicas != nil {
		m.Replicas = child.Replicas
	}
	if child.GuestAgent != nil {
		m.GuestAgent = child.GuestAgent
	}

	// Slices — child replaces entirely
	if child.Network != nil {
		m.Network = child.Network
	}
	if child.Devices != nil {
		m.Devices = child.Devices
	}

	// Maps — merge keys, child wins collisions
	if child.Disks != nil {
		m.Disks = mergeMaps(base.Disks, child.Disks)
	}
	if child.Labels != nil {
		m.Labels = mergeStringMaps(base.Labels, child.Labels)
	}

	// Pointer structs — child non-nil replaces entirely
	if child.CloudInit != nil {
		m.CloudInit = child.CloudInit
	}
	if child.Placement != nil {
		m.Placement = child.Placement
	}
	if child.Migrate != nil {
		m.Migrate = child.Migrate
	}
	if child.Update != nil {
		m.Update = child.Update
	}
	if child.LoadBalancer != nil {
		m.LoadBalancer = child.LoadBalancer
	}
	if child.HealthCheck != nil {
		m.HealthCheck = child.HealthCheck
	}
	if child.Hooks != nil {
		m.Hooks = child.Hooks
	}
	if child.Resources != nil {
		m.Resources = child.Resources
	}
	if child.Restart != nil {
		m.Restart = child.Restart
	}
	if child.DependsOn != nil {
		m.DependsOn = child.DependsOn
	}

	return m
}

// mergeStringMaps merges two string→string maps. Child wins on collision.
func mergeStringMaps(base, child map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(child))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range child {
		out[k] = v
	}
	return out
}

// mergeMaps merges two string→DiskDef maps. Child wins on collision.
func mergeMaps[V any](base, child map[string]V) map[string]V {
	out := make(map[string]V, len(base)+len(child))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range child {
		out[k] = v
	}
	return out
}

// validate enforces consistency rules, reporting every problem found.
func validate(f *File) error {
	v := &validator{origin: map[string]string{}}
	v.validate(f)
	return v.ps.err()
}

// validate enforces consistency rules on a folded, extends-resolved file.
func (v *validator) validate(f *File) {
	if f.Name == "" {
		v.ps.add("name", "stack name is required", "add 'name: <stack-name>' to your compose file")
	}

	// Validate network definitions.
	for name, net := range f.Networks {
		if net.External {
			if net.Subnet != "" || net.DHCP || net.VNI != 0 || net.Type != "" {
				v.ps.add("networks."+name, "external network must not set subnet, dhcp, vni, or type", "")
			}
		}
	}

	// Collect all instance names to detect collisions with internal
	// temp naming conventions (e.g. "-next" suffix for cutover) (#46).
	allInstanceNames := map[string]string{} // instanceName → baseName
	for _, baseName := range sortedKeys(f.VMs) {
		vm := f.VMs[baseName]
		for r := 0; r < vm.EffectiveReplicas(); r++ {
			iname := vm.InstanceName(baseName, r)
			if owner, ok := allInstanceNames[iname]; ok && owner != baseName {
				v.ps.add(v.vm(baseName),
					fmt.Sprintf("instance name %q conflicts with workload %q", iname, owner),
					"choose a different name or replica count")
				continue
			}
			allInstanceNames[iname] = baseName
		}
	}
	for baseName, vm := range f.VMs {
		for r := 0; r < vm.EffectiveReplicas(); r++ {
			iname := vm.InstanceName(baseName, r)
			// Check if another VM's instance name collides with our "-next" pattern.
			for otherIName, otherBase := range allInstanceNames {
				if otherBase == baseName {
					continue
				}
				if otherIName == iname+"-next" {
					v.ps.add(v.vm(otherBase),
						fmt.Sprintf("instance name %q conflicts with the rolling update temporary name for %q", otherIName, iname),
						"choose a different name")
				}
			}
		}
	}

	for name, vm := range f.VMs {
		p := v.vm(name)

		// Resolve effective image name
		image := vm.Image
		if image == "" {
			image = vm.ISO
		}
		if image == "" {
			v.ps.add(p, "image or iso required", "set image: or iso:")
			continue
		}

		// Validate migration + storage consistency
		if vm.Migrate != nil && vm.Migrate.Strategy == "live" && !vm.Migrate.WithStorage {
			for diskName, disk := range vm.Disks {
				if disk.Storage == "" {
					v.ps.add(p+".disks."+diskName,
						"live migration without with-storage requires shared storage",
						"set storage: <volume> or migrate.with-storage: true")
				}
			}
		}

		// Auto-failover + local disks is a warning, not an error — noted in
		// the plan (see Plan).

		// LB: implicitly enable if VIP is set.
		// NOTE: VMDef is a value type in this map, so we must copy, mutate,
		// and write back. Apply the same pattern for any other mutations.
		if vm.LoadBalancer != nil && !vm.LoadBalancer.Enabled && vm.LoadBalancer.VIP != "" {
			vm.LoadBalancer.Enabled = true
			f.VMs[name] = vm
		}
		// LB validation
		if vm.LoadBalancer != nil && vm.LoadBalancer.Enabled {
			lb := p + ".loadbalancer"
			if vm.LoadBalancer.VIP == "" {
				v.ps.add(lb+".vip", "vip required when enabled", "")
			} else if _, _, err := net.ParseCIDR(vm.LoadBalancer.VIP); err != nil {
				v.ps.add(lb+".vip", fmt.Sprintf("vip must be valid CIDR, got %q", vm.LoadBalancer.VIP), "e.g. 10.0.0.50/24")
			}
			if len(vm.LoadBalancer.Ports) == 0 {
				v.ps.add(lb+".ports", "at least one port required", "")
			}
			for i, port := range vm.LoadBalancer.Ports {
				pp := fmt.Sprintf("%s.ports[%d]", lb, i)
				if port.Listen <= 0 {
					v.ps.add(pp+".listen", "listen must be > 0", "")
				}
				if port.Target <= 0 {
					v.ps.add(pp+".target", "target must be > 0", "")
				}
			}
		}

		// Healthcheck: a target the checker cannot interpret can never pass,
		// and with the default restart action it would restart the VM forever.
		hps := healthProblems(vm.HealthCheck)
		if !v.stored {
			hps = append(hps, healthTimingProblems(vm.HealthCheck, func(field string) bool {
				return v.ps.idx.has(p + ".healthcheck." + field)
			})...)
		}
		for _, hp := range hps {
			v.ps.add(joinPath(p+".healthcheck", hp.field), hp.msg, hp.hint)
		}

		// Replicas validation
		if vm.Replicas != nil && *vm.Replicas < 0 {
			v.ps.add(p+".replicas", "replicas must be >= 0", "")
		}
	}

	// Validate depends-on: targets must exist and no cycles.
	v.validateDependsOn(f)

	// Detect contradictory affinity/anti-affinity rules (#56).
	for _, c := range affinityConflicts(f) {
		v.ps.add(v.vm(c[0])+".placement", fmt.Sprintf(
			"placement constraints are contradictory: %q and %q are transitively co-located (affinity) "+
				"but also have anti-affinity — no placement satisfies all constraints", c[0], c[1]), "")
	}
}

// validateAffinityRules checks for contradictory affinity + anti-affinity
// constraints. If A has affinity with B, and B has affinity with C, but C
// has anti-affinity with A, the placement is unsatisfiable (#56).
func validateAffinityRules(f *File) error {
	if cs := affinityConflicts(f); len(cs) > 0 {
		return fmt.Errorf(
			"placement constraints are contradictory: %q and %q are transitively co-located (affinity) "+
				"but also have anti-affinity — no placement satisfies all constraints", cs[0][0], cs[0][1])
	}
	return nil
}

// affinityConflicts returns every (vm, anti-affinity target) pair that the
// transitive affinity closure puts on the same host, sorted.
func affinityConflicts(f *File) [][2]string {
	// Build affinity graph: edges mean "must be on same host".
	affinity := map[string]map[string]bool{}
	antiAffinity := map[string]map[string]bool{}

	for name, vm := range f.VMs {
		if vm.Placement == nil {
			continue
		}
		for _, target := range vm.Placement.Affinity {
			if affinity[name] == nil {
				affinity[name] = map[string]bool{}
			}
			affinity[name][target] = true
		}
		for _, target := range vm.Placement.AntiAffinity {
			if antiAffinity[name] == nil {
				antiAffinity[name] = map[string]bool{}
			}
			antiAffinity[name][target] = true
		}
	}

	// Compute transitive affinity closure (union-find style).
	// VMs in the same affinity group must all be co-located.
	group := map[string]string{} // vm → group leader
	var find func(string) string
	find = func(v string) string {
		if group[v] == "" || group[v] == v {
			return v
		}
		group[v] = find(group[v])
		return group[v]
	}
	union := func(a, b string) {
		ga, gb := find(a), find(b)
		if ga != gb {
			group[ga] = gb
		}
	}

	for vm, targets := range affinity {
		for t := range targets {
			union(vm, t)
		}
	}

	// Check: if any two VMs in the same affinity group also have anti-affinity,
	// the constraints are contradictory.
	var out [][2]string
	for vm, targets := range antiAffinity {
		for t := range targets {
			if find(vm) == find(t) {
				out = append(out, [2]string{vm, t})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// validateDependsOn checks that all depends-on targets exist and there are no cycles.
func (v *validator) validateDependsOn(f *File) {
	// Check all targets exist.
	for name, vm := range f.VMs {
		for target := range vm.DependsOn {
			if _, ok := f.VMs[target]; !ok {
				v.ps.add(v.vm(name)+".depends-on."+target, fmt.Sprintf("vm %q depends-on unknown vm %q", name, target), "")
			}
		}
	}

	// vm_healthy on a container means running (a container has no probe
	// verdict), which silently breaks the promise when the container declares
	// a healthcheck: nothing probes it. Refuse that pairing rather than wait
	// on a check that never runs.
	names := make([]string, 0, len(f.VMs))
	for name := range f.VMs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for target, def := range f.VMs[name].DependsOn {
			t, ok := f.VMs[target]
			if ok && def.Condition == "vm_healthy" && t.IsContainer() && t.HealthCheck != nil {
				v.ps.add(v.vm(name)+".depends-on."+target+".condition",
					fmt.Sprintf("%q is a container (kind %s), and container healthchecks are not probed, so vm_healthy cannot be met", target, t.Kind),
					"use condition vm_started, or remove the container's healthcheck")
			}
		}
	}

	// Cycle detection via topological sort (Kahn's algorithm). Unknown
	// targets are reported above and are not part of any cycle.
	inDegree := make(map[string]int)
	dependents := make(map[string][]string) // target → VMs that depend on it

	for name := range f.VMs {
		inDegree[name] = 0
	}
	for name, vm := range f.VMs {
		for target := range vm.DependsOn {
			if _, ok := f.VMs[target]; !ok {
				continue
			}
			inDegree[name]++
			dependents[target] = append(dependents[target], name)
		}
	}

	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	visited := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		visited++
		for _, dep := range dependents[cur] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if visited != len(f.VMs) {
		var cyc []string
		for name, deg := range inDegree {
			if deg > 0 {
				cyc = append(cyc, name)
			}
		}
		sort.Strings(cyc)
		v.ps.add(v.vm(cyc[0])+".depends-on",
			fmt.Sprintf("depends-on cycle detected (involves %s)", strings.Join(cyc, ", ")), "")
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parseMemoryString converts "8G", "512M", "1024" to MiB.
// Returns an error for malformed values like "8X" or "abc".
func parseMemoryString(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("empty memory value")
	}
	if strings.HasSuffix(s, "G") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "G"))
		if err != nil {
			return 0, fmt.Errorf("invalid memory value %q: %w", s, err)
		}
		return n * 1024, nil
	}
	if strings.HasSuffix(s, "M") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "M"))
		if err != nil {
			return 0, fmt.Errorf("invalid memory value %q: %w", s, err)
		}
		return n, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid memory value %q: %w", s, err)
	}
	return n, nil
}

// IsContainer reports whether the workload runs in the container runtime
// (kind lxc or oci) rather than as a VM.
func (vm *VMDef) IsContainer() bool {
	return vm.Kind == WorkloadKindLXC || vm.Kind == WorkloadKindOCI
}

// EffectiveReplicas returns 1 if replicas is nil (unset/omitted).
// Explicit replicas: 0 returns 0 (scale-to-zero) (#50).
func (vm *VMDef) EffectiveReplicas() int {
	if vm.Replicas == nil {
		return 1
	}
	return *vm.Replicas
}

// EffectiveGuestAgent returns true unless explicitly set to false.
func (vm *VMDef) EffectiveGuestAgent() bool {
	if vm.GuestAgent == nil {
		return vm.ISO == "" // default true for cloud images, false for ISO installs
	}
	return *vm.GuestAgent
}

// InstanceName returns the instance name for a replica.
// Single-replica VMs use the base name; multi-replica append "-N".
func (vm *VMDef) InstanceName(baseName string, replica int) string {
	if vm.EffectiveReplicas() == 1 {
		return baseName
	}
	return fmt.Sprintf("%s-%d", baseName, replica+1)
}
