package compose

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// NameCollision is the refusal for a planned create whose name a workload
// outside this stack already holds. exists says what holds it (`vm "v1" already
// exists`); owner is that workload's stack, "" for one outside any stack.
// Shared by the server's plan and `lv compose diff`, so both say the same.
func NameCollision(exists, owner string) string {
	where := "outside any stack"
	if owner != "" {
		where = fmt.Sprintf("in stack %q", owner)
	}
	return exists + " " + where + " — rename it in this file or delete it there"
}

// OpKind is the type of change in an execution plan.
type OpKind string

const (
	OpCreate   OpKind = "create"
	OpUpdate   OpKind = "update"
	OpDelete   OpKind = "delete"
	OpNoChange OpKind = "no-change"
)

// Op is a single planned operation.
type Op struct {
	Kind      OpKind
	VMName    string
	Detail    string
	Warning   string    // non-fatal advisory (e.g. local disk + failover)
	DependsOn DependsOn // boot-order dependencies (from compose)
	// Retry marks an update planned because the workload is in a transient or
	// error state (a previous deploy did not finish), not because its spec
	// changed.
	Retry bool
	// Base is the compose name of the workload (db for replica db-2), which
	// is what a depends-on entry names. Empty for a delete, whose definition
	// may be gone from the file.
	Base string
	// Change is the op's desired-vs-stored classification, and Classified
	// says Build had the stored spec to make it. With it, Change is what
	// decided the op's kind, and it is the one the executor applies.
	Change     ChangePlan
	Classified bool
}

// ComposeName is the name a depends-on entry refers to the op's workload by:
// its compose name, or — for an op built without one — its instance name.
func (o Op) ComposeName() string {
	if o.Base != "" {
		return o.Base
	}
	return o.VMName
}

// Plan is the ordered set of operations to converge the cluster to the desired state.
type Plan struct {
	StackName string
	Ops       []Op
}

// CurrentVM is the caller-supplied current state of a running VM instance.
type CurrentVM struct {
	Name          string
	Image         string
	CPU           int
	MemMiB        int
	State         string
	HostName      string
	CloudInitHash string // sha256 of userdata+networkconfig, empty if none
	// Spec is the VM's full stored spec when the caller has it. With it, the
	// desired-vs-stored comparison (Classify) alone decides whether the VM
	// changed, and CPU/MemMiB/Image/CloudInitHash are not consulted; without
	// it only those four are compared and an edit to any other field
	// (cpu-mode, labels, disk topology, …) is invisible.
	Spec *pb.VMSpec
}

// Build produces an execution plan by diffing desired (compose file) vs current state.
func Build(f *File, current []CurrentVM) (*Plan, error) {
	plan := &Plan{StackName: f.Name}

	// Index current VMs by name for fast lookup.
	currentByName := map[string]CurrentVM{}
	for _, vm := range current {
		currentByName[vm.Name] = vm
	}

	// Track which current VMs are still desired (to find deletions).
	desired := map[string]bool{}

	// Sort VM definition keys for deterministic iteration order.
	// Without this, Go map iteration randomizes the order VMs are sent to
	// SelectBatch, causing different placements between dry-run and execute.
	sortedVMKeys := make([]string, 0, len(f.VMs))
	for k := range f.VMs {
		sortedVMKeys = append(sortedVMKeys, k)
	}
	sort.Strings(sortedVMKeys)

	for _, baseName := range sortedVMKeys {
		vmDef := f.VMs[baseName]
		replicas := vmDef.EffectiveReplicas()
		for r := 0; r < replicas; r++ {
			instanceName := vmDef.InstanceName(baseName, r)
			desired[instanceName] = true

			cur, exists := currentByName[instanceName]
			if !exists {
				op := Op{Kind: OpCreate, VMName: instanceName, Base: baseName,
					Detail: fmt.Sprintf("create %s (image=%s cpu=%d mem=%dMiB)",
						instanceName, vmDef.Image, vmDef.CPU, int(vmDef.Memory)),
					DependsOn: vmDef.DependsOn}

				// Advisory: local disk + restart-any failover
				if vmDef.Migrate != nil && vmDef.Migrate.OnHostFailure == "restart-any" {
					for _, disk := range vmDef.Disks {
						if disk.Storage == "" {
							op.Warning = fmt.Sprintf(
								"on-host-failure: restart-any with local disk %q — data loss risk on host failure", instanceName)
							break
						}
					}
				}
				plan.Ops = append(plan.Ops, op)
				continue
			}

			// What changed. With the stored spec, Classify decides — the
			// comparison the executor applies, so a VM is never planned as an
			// update the executor has nothing to apply for (and planned again on
			// every later deploy). It compares the file with the spec the VM was
			// deployed from, not with what the host reports it using now: a
			// ballooned guest or a vCPU taken offline is not a change to the
			// file. The coarse comparison is for a caller without the stored
			// spec (a container, or a spec that does not parse).
			changed := false
			detail := ""
			var change ChangePlan
			classified := cur.Spec != nil
			if classified {
				desired, err := BuildVMSpec(instanceName, baseName, &vmDef, f)
				if err != nil {
					return nil, fmt.Errorf("build spec for %s: %w", instanceName, err)
				}
				change = Classify(desired, cur.Spec, StoredDisksFromSpec(cur.Spec))
				if change.Max() != ActionNoChange {
					detail = " " + change.Reasons()
					changed = true
				}
			} else {
				if vmDef.CPU != 0 && cur.CPU != vmDef.CPU {
					detail += fmt.Sprintf(" cpu %d→%d", cur.CPU, vmDef.CPU)
					changed = true
				}
				memMiB := int(vmDef.Memory)
				if memMiB != 0 && cur.MemMiB != memMiB {
					detail += fmt.Sprintf(" memory %dMiB→%dMiB", cur.MemMiB, memMiB)
					changed = true
				}
				if vmDef.Image != "" && cur.Image != vmDef.Image {
					detail += fmt.Sprintf(" image %s→%s", cur.Image, vmDef.Image)
					changed = true
				}
				if vmDef.CloudInit != nil && cur.CloudInitHash != "" {
					if cloudInitHash(vmDef.CloudInit) != cur.CloudInitHash {
						detail += " cloud-init changed"
						changed = true
					}
				} else if vmDef.CloudInit != nil && cur.CloudInitHash == "" {
					detail += " cloud-init added"
					changed = true
				}
			}
			warning := ""
			if vmDef.CloudInit == nil && (cur.Spec.GetCloudInit() != nil || (cur.Spec == nil && cur.CloudInitHash != "")) {
				warning = cloudInitKeptWarning
			}

			// VMs in transient or error states are not in a stable steady
			// state — even if their spec matches, the previous deploy didn't
			// finish cleanly (e.g., daemon was killed mid-create, libvirt
			// failed mid-define). Treat as OpUpdate so the deploy executor
			// re-attempts. Without this, a partial deploy leaves a permanent
			// "exists but doesn't actually run" zombie row that no further
			// `compose up` can recover.
			if IsTransientOrErrorState(cur.State) {
				plan.Ops = append(plan.Ops, Op{
					Kind:       OpUpdate,
					VMName:     instanceName,
					Detail:     fmt.Sprintf("retry %s (was state=%s)", instanceName, cur.State),
					DependsOn:  vmDef.DependsOn,
					Base:       baseName,
					Retry:      true,
					Warning:    warning,
					Change:     change,
					Classified: classified,
				})
			} else if changed {
				// An update carries its depends-on like a create: it is held
				// back when a dependency is not met, and the dependency is
				// waited on for it.
				plan.Ops = append(plan.Ops, Op{
					Kind:       OpUpdate,
					VMName:     instanceName,
					Detail:     fmt.Sprintf("update %s:%s", instanceName, detail),
					DependsOn:  vmDef.DependsOn,
					Base:       baseName,
					Warning:    warning,
					Change:     change,
					Classified: classified,
				})
			} else {
				plan.Ops = append(plan.Ops, Op{
					Kind:       OpNoChange,
					VMName:     instanceName,
					Detail:     fmt.Sprintf("%s: no changes", instanceName),
					Base:       baseName,
					Warning:    warning,
					Classified: classified,
				})
			}
		}
	}

	// Anything in current but not desired → delete.
	// Only delete VMs that belong to this stack (name prefix match for replicated VMs).
	for _, cur := range current {
		if !desired[cur.Name] {
			plan.Ops = append(plan.Ops, Op{
				Kind:   OpDelete,
				VMName: cur.Name,
				Detail: fmt.Sprintf("delete %s (no longer in compose)", cur.Name),
			})
		}
	}

	return plan, nil
}

// cloudInitKeptWarning is the plan's note on a VM whose cloud-init is no
// longer in the file. Leaving it out keeps what is stored, as leaving out any
// field does: cloud-init ran at the VM's first boot and is not run again for
// the same VM, so dropping it from the file changes nothing in the guest, and
// nothing short of replacing the VM — its disks with it — would undo what it
// did. No update is planned for it.
const cloudInitKeptWarning = "cloud-init is no longer in the file; the VM keeps the cloud-init it was created with " +
	"(it ran at first boot and removing it changes nothing in the guest — only a new VM starts without it)"

// EffectiveUpdate is the update strategy a workload instance is updated with:
// its own `update:` block, else the stack default (the first VM, by compose
// name, with an `update:` block), else recreate. The planner and the executor
// both read it here, so they cannot pick different defaults.
func EffectiveUpdate(f *File, instance string) UpdateDef {
	if def, _ := FindVMDef(f, instance); def != nil && def.Update != nil {
		return *def.Update
	}
	names := make([]string, 0, len(f.VMs))
	for n := range f.VMs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if u := f.VMs[n].Update; u != nil {
			return *u
		}
	}
	return UpdateDef{Strategy: "recreate"}
}

// Summary returns a human-readable one-line summary of the plan.
func (p *Plan) Summary() string {
	var creates, updates, deletes, nochange int
	for _, op := range p.Ops {
		switch op.Kind {
		case OpCreate:
			creates++
		case OpUpdate:
			updates++
		case OpDelete:
			deletes++
		case OpNoChange:
			nochange++
		}
	}
	return fmt.Sprintf("Plan: %d to create, %d to update, %d to delete, %d unchanged",
		creates, updates, deletes, nochange)
}

// isTransientOrErrorState reports whether a VM is in a state that means
// the previous lifecycle action didn't reach a steady end. Such VMs need
// a redeploy to retry; "matches spec" alone is not safe because the row
// can lie (e.g., disk allocated but no libvirt domain).
//
// Stable states (running / stopped / paused / fenced / migrating) are
// treated as steady-state. Migrating is intentionally excluded from
// "needs retry" because a redeploy mid-migration would interrupt it.
// IsTransientOrErrorState reports whether a workload in this state is left
// over from a deploy (or lifecycle operation) that did not finish, so the next
// deploy retries it.
func IsTransientOrErrorState(state string) bool {
	switch state {
	case "creating", "starting", "stopping", "rebuilding", "error", "failed":
		return true
	}
	return false
}

// cloudInitHash returns a stable hash of a CloudInitDef for change detection.
func cloudInitHash(ci *CloudInitDef) string {
	h := sha256.New()
	h.Write([]byte(ci.UserData))
	h.Write([]byte{0})
	h.Write([]byte(ci.NetworkConfig))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// CloudInitHash exports the cloud-init hash for callers building CurrentVM.
func CloudInitHash(userdata, networkconfig string) string {
	h := sha256.New()
	h.Write([]byte(userdata))
	h.Write([]byte{0})
	h.Write([]byte(networkconfig))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// CloudInitHashFromSpec returns the CurrentVM.CloudInitHash for a stored VM
// spec (the JSON the daemon persists for a VM), or "" when the spec carries no
// cloud-init. It hashes the same two fields as cloudInitHash does for the
// compose definition, so an unchanged file re-applied to the VM it created
// compares equal.
//
// The spec stores the block itself, under `cloud_init`; no precomputed hash
// field exists in it. A planner that read one anyway saw "" for every VM and
// planned "cloud-init added" — an update, executed as delete + create — on
// every re-apply of a cloud-init stack.
func CloudInitHashFromSpec(specJSON string) string {
	if specJSON == "" {
		return ""
	}
	var raw struct {
		CloudInit *struct {
			Userdata      string `json:"userdata"`
			Networkconfig string `json:"networkconfig"`
		} `json:"cloud_init"`
	}
	if err := json.Unmarshal([]byte(specJSON), &raw); err != nil || raw.CloudInit == nil {
		return ""
	}
	return CloudInitHash(raw.CloudInit.Userdata, raw.CloudInit.Networkconfig)
}

// DependsOnTarget reports whether a depends-on entry naming dep refers to the
// workload whose compose name is composeName. Dependencies are matched by
// compose name only — "db" matches db and its replicas db-1, db-2 (all of
// compose name db), never a workload named db-backup. Every depends-on match
// goes through here.
func DependsOnTarget(dep, composeName string) bool {
	return dep == composeName
}

// BaseName is the compose name of a workload instance in f (db for replica
// db-2), or the instance name itself when f defines no such instance.
func BaseName(f *File, instance string) string {
	if _, base := FindVMDef(f, instance); base != "" {
		return base
	}
	return instance
}

// TopologicalSortOps orders the create and update ops in dependency order —
// together, so a create that depends on a VM being updated comes after that
// update — taking the lowest-named ready op at each step. No-change and
// delete ops keep their relative order after them.
func TopologicalSortOps(ops []Op) []Op {
	var active, others []Op
	for _, op := range ops {
		if op.Kind == OpCreate || op.Kind == OpUpdate {
			active = append(active, op)
		} else {
			others = append(others, op)
		}
	}

	// VM names are instance names (web-1); DependsOn uses compose names (db).
	byName := map[string]*Op{}
	inDegree := map[string]int{}
	for i := range active {
		byName[active[i].VMName] = &active[i]
		inDegree[active[i].VMName] = 0
	}
	dependents := map[string][]string{} // dependency → ops that depend on it
	for i := range active {
		op := &active[i]
		for depBase := range op.DependsOn {
			for name, other := range byName {
				if DependsOnTarget(depBase, other.ComposeName()) {
					inDegree[op.VMName]++
					dependents[name] = append(dependents[name], op.VMName)
				}
			}
		}
	}

	// Kahn's algorithm, taking the lowest-named ready op at each step. The
	// ready set comes from map iteration, so without a fixed choice ops with no
	// ordering between them ran in a different order on every deploy of an
	// unchanged file — different output, a different partial-failure shape,
	// and nothing an operator could reproduce.
	var ready []string
	for name, deg := range inDegree {
		if deg == 0 {
			ready = append(ready, name)
		}
	}
	sorted := make([]Op, 0, len(ops))
	for len(ready) > 0 {
		sort.Strings(ready)
		cur := ready[0]
		ready = ready[1:]
		sorted = append(sorted, *byName[cur])
		for _, dep := range dependents[cur] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				ready = append(ready, dep)
			}
		}
	}

	// A cycle (validation rejects them; the replica-prefix match can in
	// principle invent one) leaves ops unsorted: append them in their order.
	if len(sorted) < len(active) {
		seen := map[string]bool{}
		for _, op := range sorted {
			seen[op.VMName] = true
		}
		for _, op := range active {
			if !seen[op.VMName] {
				sorted = append(sorted, op)
			}
		}
	}

	return append(sorted, others...)
}

// HasChanges returns true if the plan contains any actionable operations.
func (p *Plan) HasChanges() bool {
	for _, op := range p.Ops {
		if op.Kind != OpNoChange {
			return true
		}
	}
	return false
}
