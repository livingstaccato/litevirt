package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/rolling"
)

// serverOps adapts *Server to rolling.Ops so the rolling update engine
// can drive VM lifecycle without knowing about gRPC internals.
type serverOps struct {
	s *Server
}

var _ rolling.Ops = (*serverOps)(nil)

// recreateAs deletes the VM named `target` (failing on any error other than
// not-found — a delete that couldn't tear down must NOT be followed by a create that
// leaves the old runtime alive) then creates it from a clone of `desired` renamed to
// `target`. It DESTROYS the target's disks, so the rolling engine only reaches it
// under an explicit recreate-class strategy.
func (o *serverOps) recreateAs(ctx context.Context, target string, desired *pb.VMSpec) error {
	if desired == nil {
		return fmt.Errorf("recreate %q: no desired spec", target)
	}
	if _, err := o.s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: target}); err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("delete %s before recreate: %w", target, err)
	}
	spec := proto.Clone(desired).(*pb.VMSpec)
	spec.Name = target
	_, err := o.s.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec})
	return err
}

func (o *serverOps) RecreateVM(ctx context.Context, name string, desired *pb.VMSpec) error {
	return o.recreateAs(ctx, name, desired)
}

func (o *serverOps) CreateNextVM(ctx context.Context, name string, desired *pb.VMSpec) error {
	return o.recreateAs(ctx, name+"-next", desired)
}

func (o *serverOps) ReconfigureVM(ctx context.Context, name string, desired *pb.VMSpec, plan compose.ChangePlan) error {
	return o.s.reconfigureWithRestart(ctx, name, desired, plan)
}

func (o *serverOps) ResizeVMLive(ctx context.Context, name string, desired *pb.VMSpec) error {
	// Route through the owner-forwarding RPCs so a rolling in-place resize works when
	// the VM is on a peer of the deploy entry node (resizeVMLive itself is owner-local
	// and aborts on a non-owner). UpdateVM does the live cpu grow (gated on live_resize)
	// and SetVMMemory the balloon — both forward to the owner. Only the changed
	// dimension(s) are sent: an unchanged cpu would take UpdateVM off its live fast path
	// onto the stopped-redefine path.
	vm, err := corrosion.GetVM(ctx, o.s.db, name)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", name)
	}
	cur := &pb.VMSpec{}
	if vm.Spec != "" {
		if uerr := json.Unmarshal([]byte(vm.Spec), cur); uerr != nil {
			return status.Errorf(codes.Internal, "parse stored spec for %q: %v", name, uerr)
		}
	}
	if desired.Cpu != 0 && desired.Cpu != cur.Cpu {
		if _, err := o.s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: name, Cpu: desired.Cpu}); err != nil {
			return err
		}
	}
	if desired.MemoryMib != 0 && desired.MemoryMib != cur.MemoryMib {
		if _, err := o.s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: name, TargetMib: desired.MemoryMib}); err != nil {
			return err
		}
	}
	return nil
}

func (o *serverOps) ApplyLiveMetadata(ctx context.Context, name string, desired *pb.VMSpec, fields []string) error {
	return o.s.applyLiveMetadata(ctx, name, desired, fields)
}

func (o *serverOps) DeleteVM(ctx context.Context, name string) error {
	if _, err := o.s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: name}); err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	return nil
}

func (o *serverOps) StopVM(ctx context.Context, name string) error {
	_, err := o.s.StopVM(ctx, &pb.StopVMRequest{Name: name})
	return err
}

func (o *serverOps) StartVM(ctx context.Context, name string) error {
	_, err := o.s.StartVM(ctx, &pb.StartVMRequest{Name: name})
	return err
}

// WaitHealthy is the rolling engine's health wait: the depends-on "vm_healthy"
// condition, bounded by the strategy's health-wait rather than depends-on's
// ten-minute default.
func (o *serverOps) WaitHealthy(ctx context.Context, name string, timeout time.Duration) error {
	if err := o.s.waitForConditionWithin(ctx, name, "vm_healthy", timeout); err != nil {
		return fmt.Errorf("%s did not become healthy within health-wait %s: %w", name, timeout, err)
	}
	return nil
}

// useRollingUpdate returns the update strategy if the compose file specifies
// a non-recreate strategy, or "" if inline recreate should be used.
func useRollingUpdate(f *compose.File) string {
	for _, vm := range f.VMs {
		if vm.Update != nil && vm.Update.Strategy != "" && vm.Update.Strategy != "recreate" {
			return vm.Update.Strategy
		}
	}
	return ""
}

// vmUpdateDef returns the effective update strategy for a VM: its own `update:`
// block, else the stack default (first VM with an explicit update block), else
// recreate.
func vmUpdateDef(f *compose.File, name string) compose.UpdateDef {
	if def, _ := compose.FindVMDef(f, name); def != nil && def.Update != nil {
		return *def.Update
	}
	for _, vm := range f.VMs {
		if vm.Update != nil {
			return *vm.Update
		}
	}
	return compose.UpdateDef{Strategy: "recreate"}
}

// deployFailures collects the VM actions of one deploy that failed, in the
// order they failed. Each failure is also sent to the client as an "error"
// progress message naming the VM — the stream itself still ends OK, so that
// message is the only way a client can count it — and the set decides the
// stack's stored state and audit result.
type deployFailures struct {
	stream grpc.ServerStreamingServer[pb.DeployProgress]
	names  []string
	seen   map[string]bool
}

func newDeployFailures(stream grpc.ServerStreamingServer[pb.DeployProgress]) *deployFailures {
	return &deployFailures{stream: stream, seen: map[string]bool{}}
}

// fail records vm as failed and sends its "error" phase. The returned error is
// a stream send failure only.
func (d *deployFailures) fail(vm string, err error) error {
	return d.failWithDetail(vm, "", err)
}

// failWithDetail is fail with a Detail on the "error" message, for failures
// the rolling engine reports as progress.
func (d *deployFailures) failWithDetail(vm, detail string, err error) error {
	if !d.seen[vm] {
		d.seen[vm] = true
		d.names = append(d.names, vm)
	}
	return d.stream.Send(&pb.DeployProgress{Phase: "error", VmName: vm, Detail: detail, Error: err.Error()})
}

// dependsOnGate enforces depends-on while a deploy runs. Before a create or
// update starts, each dependency of it must meet the condition it asked for:
// a dependency this deploy created (or recreated) and already waited on
// counts; any other — one updated by the rolling engine, or one this deploy
// leaves unchanged — is waited on then. A dependency whose condition is not
// met (its create or recreate failed, or the wait timed out) holds the
// dependent back: it is reported as a failed action — naming the dependency,
// the condition and why it was not met — and neither created nor updated. A
// held-back workload is itself unmet, so the block is transitive. Workloads
// that depend on nothing that failed proceed, and an unchanged workload waits
// on nothing.
type dependsOnGate struct {
	s      *Server
	f      *compose.File
	stream grpc.ServerStreamingServer[pb.DeployProgress]
	all    []planner.VMAction // every workload of the plan, unchanged ones included
	unmet  map[string]string  // compose base name → why its condition was not met
	met    map[string]int     // instance → highest condition level verified
	// rolledOut marks the VMs this deploy handed to the rolling engine.
	rolledOut map[string]bool
}

func newDependsOnGate(s *Server, f *compose.File, actions []planner.VMAction, stream grpc.ServerStreamingServer[pb.DeployProgress]) *dependsOnGate {
	return &dependsOnGate{s: s, f: f, stream: stream, all: actions, unmet: map[string]string{}, met: map[string]int{}, rolledOut: map[string]bool{}}
}

// conditionLevel ranks the depends-on conditions: vm_healthy implies
// vm_started.
func conditionLevel(cond string) int {
	if cond == "vm_healthy" {
		return 2
	}
	return 1
}

func dependencyCondition(def compose.DependencyDef) string {
	if def.Condition == "" {
		return "vm_started"
	}
	return def.Condition
}

// baseName maps a planned workload (an instance name such as db-2) to the
// compose name dependents refer to it by.
func (g *dependsOnGate) baseName(vm string) string {
	return compose.BaseName(g.f, vm)
}

// markMet records that vm was verified to meet cond in this deploy.
func (g *dependsOnGate) markMet(vm, cond string) {
	if l := conditionLevel(cond); l > g.met[vm] {
		g.met[vm] = l
	}
}

// markUnmet records that vm is not in the state its dependents were promised.
// For a replicated workload one failed replica is enough: a dependent waits
// for every replica.
func (g *dependsOnGate) markUnmet(vm string, err error) {
	base := g.baseName(vm)
	if _, ok := g.unmet[base]; ok {
		return
	}
	reason := err.Error()
	if base != vm {
		reason = vm + ": " + reason
	}
	g.unmet[base] = reason
}

func sortedDeps(action planner.VMAction) []string {
	deps := make([]string, 0, len(action.DependsOn))
	for dep := range action.DependsOn {
		deps = append(deps, dep)
	}
	sort.Strings(deps)
	return deps
}

// blocked returns the error a dependent of an unmet workload is failed with,
// or nil when no dependency of action is known to be unmet.
func (g *dependsOnGate) blocked(action planner.VMAction) error {
	for _, dep := range sortedDeps(action) {
		if reason, ok := g.unmet[dep]; ok {
			return fmt.Errorf("blocked: depends-on %s (condition %s) was not met: %s",
				dep, dependencyCondition(action.DependsOn[dep]), reason)
		}
	}
	return nil
}

// ensure waits for every dependency instance of action that has not been
// verified at the condition action needs, marking it unmet if the wait fails.
func (g *dependsOnGate) ensure(ctx context.Context, action planner.VMAction) {
	for _, dep := range sortedDeps(action) {
		cond := dependencyCondition(action.DependsOn[dep])
		for _, d := range g.all {
			if _, ok := g.unmet[dep]; ok {
				break
			}
			if d.Kind == planner.OpDelete || !compose.DependsOnTarget(dep, g.baseName(d.VMName)) || g.met[d.VMName] >= conditionLevel(cond) {
				continue
			}
			_ = g.stream.Send(&pb.DeployProgress{
				Phase:  "waiting",
				VmName: action.VMName,
				Detail: fmt.Sprintf("waiting for %s to be %s", d.VMName, cond),
			})
			if err := g.wait(ctx, d, cond); err != nil {
				slog.Warn("depends-on wait failed", "dependency", d.VMName, "dependent", action.VMName, "error", err)
				g.markUnmet(d.VMName, fmt.Errorf("depends-on wait for %s: %w", cond, err))
				break
			}
			g.markMet(d.VMName, cond)
		}
	}
}

// wait waits for dependency d to meet cond. A VM the rolling engine updated
// in this deploy is waited on for its strategy's health-wait when the
// strategy sets one; anything else for depends-on's default.
func (g *dependsOnGate) wait(ctx context.Context, d planner.VMAction, cond string) error {
	if g.rolledOut[d.VMName] {
		if hw := vmUpdateDef(g.f, d.VMName).HealthWait; hw != "" {
			if timeout, err := time.ParseDuration(hw); err == nil && timeout > 0 {
				return g.s.waitForConditionWithin(ctx, d.VMName, cond, timeout)
			}
		}
	}
	return g.s.waitForWorkloadCondition(ctx, d, cond)
}

// hold makes sure every dependency of action meets its condition, and reports
// action as blocked — marking it unmet in turn — when one does not. It returns
// true when the action must be skipped, and a stream send failure only as its
// error.
func (g *dependsOnGate) hold(ctx context.Context, action planner.VMAction, failures *deployFailures) (bool, error) {
	berr := g.blocked(action)
	if berr == nil {
		g.ensure(ctx, action)
		berr = g.blocked(action)
	}
	if berr == nil {
		return false, nil
	}
	slog.Warn("deploy action blocked by an unmet dependency", "workload", action.VMName, "error", berr)
	g.markUnmet(action.VMName, berr)
	return true, failures.failWithDetail(action.VMName, "skipped: a dependency was not met", berr)
}

// waitCreated waits, after a create or recreate, for the condition the
// workload's dependents need (action.WaitFor). It returns the failed-action
// error, or nil when there was nothing to wait for or the wait passed.
func (g *dependsOnGate) waitCreated(ctx context.Context, action planner.VMAction) error {
	if action.WaitFor == "" {
		return nil
	}
	if err := g.s.waitDependsOn(ctx, action, g.stream); err != nil {
		slog.Warn("depends-on wait failed", "vm", action.VMName, "error", err)
		g.markUnmet(action.VMName, err)
		return err
	}
	g.markMet(action.VMName, action.WaitFor)
	return nil
}

// deleteWorkloadIgnoringGone deletes a planned workload, treating NotFound as
// success: the plan wanted it gone and it is.
func (s *Server) deleteWorkloadIgnoringGone(ctx context.Context, a planner.VMAction) error {
	if err := s.deleteWorkload(ctx, a); err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	return nil
}

// waitDependsOn waits for a just-created workload to satisfy the condition its
// dependents need. A wait that fails is a failed action: the workload is not in
// the state the rest of the stack was told to expect.
func (s *Server) waitDependsOn(ctx context.Context, action planner.VMAction, stream grpc.ServerStreamingServer[pb.DeployProgress]) error {
	_ = stream.Send(&pb.DeployProgress{
		Phase:  "waiting",
		VmName: action.VMName,
		Detail: fmt.Sprintf("waiting for %s", action.WaitFor),
	})
	if err := s.waitForWorkloadCondition(ctx, action, action.WaitFor); err != nil {
		return fmt.Errorf("depends-on wait for %s: %w", action.WaitFor, err)
	}
	return nil
}

// recreateInline deletes then re-creates a workload for an update. A delete
// that could not tear the workload down must NOT be followed by a create: the
// old runtime may still be alive (the same rule as serverOps.recreateAs). It
// returns the failed-action error.
func (s *Server) recreateInline(ctx context.Context, action planner.VMAction, f *compose.File, gate *dependsOnGate) error {
	if delErr := s.deleteWorkloadIgnoringGone(ctx, action); delErr != nil {
		slog.Warn("deploy update delete failed", "workload", action.VMName, "error", delErr)
		gate.markUnmet(action.VMName, fmt.Errorf("delete before recreate failed: %w", delErr))
		return fmt.Errorf("delete before recreate: %w", delErr)
	}
	if vmErr := s.deployCreatePlanned(ctx, action, f); vmErr != nil {
		slog.Warn("deploy update recreate failed", "workload", action.VMName, "host", action.TargetHost, "error", vmErr)
		gate.markUnmet(action.VMName, fmt.Errorf("recreate failed: %w", vmErr))
		return vmErr
	}
	// A recreated workload is as new to its dependents as a created one.
	return gate.waitCreated(ctx, action)
}

// createPlanned creates a workload and waits for the condition its dependents
// need. It returns the failed-action error.
func (s *Server) createPlanned(ctx context.Context, action planner.VMAction, f *compose.File, gate *dependsOnGate) error {
	if vmErr := s.deployCreatePlanned(ctx, action, f); vmErr != nil {
		slog.Warn("deploy create failed", "vm", action.VMName, "host", action.TargetHost, "error", vmErr)
		gate.markUnmet(action.VMName, fmt.Errorf("create failed: %w", vmErr))
		return vmErr
	}
	return gate.waitCreated(ctx, action)
}

// executeInlineActions processes all workload actions sequentially, in the
// planner's dependency order, using inline delete-then-create for updates.
// Failed actions are recorded in failures; the returned error is a stream
// failure only.
func (s *Server) executeInlineActions(ctx context.Context, f *compose.File, resolved *planner.ResolvedPlan, stream grpc.ServerStreamingServer[pb.DeployProgress], failures *deployFailures) error {
	gate := newDependsOnGate(s, f, resolved.VMs, stream)
	for _, action := range resolved.VMs {
		if action.Kind == planner.OpNoChange {
			continue
		}
		if action.Kind != planner.OpDelete {
			if skip, sendErr := gate.hold(ctx, action, failures); sendErr != nil {
				return sendErr
			} else if skip {
				continue
			}
		}

		if err := stream.Send(&pb.DeployProgress{
			Phase:  "applying",
			VmName: action.VMName,
			Detail: action.Detail,
		}); err != nil {
			return err
		}

		var actErr error
		switch action.Kind {
		case planner.OpCreate:
			actErr = s.createPlanned(ctx, action, f, gate)
		case planner.OpUpdate:
			// By the planned mechanism: in place, reconfigure + restart, or
			// (a change of identity, or a container) recreate.
			actErr = s.applyPlannedUpdate(ctx, action, f, gate)
		case planner.OpDelete:
			if delErr := s.deleteWorkloadIgnoringGone(ctx, action); delErr != nil {
				slog.Warn("deploy delete failed", "workload", action.VMName, "error", delErr)
				actErr = delErr
			}
		}
		if actErr != nil {
			if sendErr := failures.fail(action.VMName, actErr); sendErr != nil {
				return sendErr
			}
			continue
		}

		if err := stream.Send(&pb.DeployProgress{
			Phase:       "done",
			VmName:      action.VMName,
			ProgressPct: 100,
		}); err != nil {
			return err
		}
	}
	return nil
}

// dependencyWaves splits the plan's creates and updates into waves: each wave
// holds the actions none of whose dependencies still has an action to run, in
// planned order. With no depends-on between them, everything is one wave.
func dependencyWaves(f *compose.File, actions []planner.VMAction) [][]planner.VMAction {
	base := func(vm string) string { return compose.BaseName(f, vm) }
	var pending []planner.VMAction
	for _, a := range actions {
		if a.Kind == planner.OpCreate || a.Kind == planner.OpUpdate {
			pending = append(pending, a)
		}
	}
	var waves [][]planner.VMAction
	for len(pending) > 0 {
		waiting := map[string]bool{} // base names with an action still to run
		for _, a := range pending {
			waiting[base(a.VMName)] = true
		}
		var wave, rest []planner.VMAction
		for _, a := range pending {
			ready := true
			for dep := range a.DependsOn {
				if waiting[dep] {
					ready = false
					break
				}
			}
			if ready {
				wave = append(wave, a)
			} else {
				rest = append(rest, a)
			}
		}
		if len(wave) == 0 { // a cycle validation should have refused
			wave, rest = rest, nil
		}
		waves = append(waves, wave)
		pending = rest
	}
	return waves
}

// executeWithRollingUpdates runs the plan in dependency waves. Within a wave
// creates execute first (scale-up), then container updates (recreated inline:
// the rolling engine is VM-only), then the VM updates are delegated to the
// rolling update engine. Every action waits for its dependencies — including
// ones the engine updated in an earlier wave — before it starts. Deletes
// execute last (scale-down).
func (s *Server) executeWithRollingUpdates(ctx context.Context, f *compose.File, resolved *planner.ResolvedPlan, stream grpc.ServerStreamingServer[pb.DeployProgress], failures *deployFailures) error {
	var deletes []planner.VMAction
	for _, a := range resolved.VMs {
		if a.Kind == planner.OpDelete {
			deletes = append(deletes, a)
		}
	}

	gate := newDependsOnGate(s, f, resolved.VMs, stream)
	for _, wave := range dependencyWaves(f, resolved.VMs) {
		var creates, ctUpdates, updates []planner.VMAction
		for _, a := range wave {
			switch {
			case a.Kind == planner.OpCreate:
				creates = append(creates, a)
			case a.IsContainer:
				ctUpdates = append(ctUpdates, a)
			default:
				updates = append(updates, a)
			}
		}

		for _, action := range creates {
			if skip, _ := gate.hold(ctx, action, failures); skip {
				continue
			}
			_ = stream.Send(&pb.DeployProgress{Phase: "applying", VmName: action.VMName, Detail: action.Detail})
			if err := s.createPlanned(ctx, action, f, gate); err != nil {
				_ = failures.fail(action.VMName, err)
				continue
			}
			_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: action.VMName, ProgressPct: 100})
		}

		for _, action := range ctUpdates {
			if skip, _ := gate.hold(ctx, action, failures); skip {
				continue
			}
			_ = stream.Send(&pb.DeployProgress{Phase: "applying", VmName: action.VMName, Detail: action.Detail})
			if err := s.recreateInline(ctx, action, f, gate); err != nil {
				_ = failures.fail(action.VMName, err)
				continue
			}
			_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: action.VMName, ProgressPct: 100})
		}

		if err := s.rollingUpdateWave(ctx, f, updates, stream, failures, gate); err != nil {
			return err
		}
	}

	// Execute deletes (scale-down).
	for _, action := range deletes {
		_ = stream.Send(&pb.DeployProgress{Phase: "applying", VmName: action.VMName, Detail: action.Detail})
		if delErr := s.deleteWorkloadIgnoringGone(ctx, action); delErr != nil {
			slog.Warn("deploy delete failed", "workload", action.VMName, "error", delErr)
			_ = failures.fail(action.VMName, delErr)
			continue
		}
		_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: action.VMName, ProgressPct: 100})
	}

	return nil
}

// rollingUpdateWave hands one wave's VM updates to the rolling engine.
// Fail-fast: a rolling error is returned, so the deploy stops BEFORE any later
// wave and the scale-down deletes — a failed update never deletes a VM the
// update didn't intend to — and the Deploy handler skips UpsertStack on the
// returned error, leaving the prior stack record/hash untouched.
func (s *Server) rollingUpdateWave(ctx context.Context, f *compose.File, updates []planner.VMAction, stream grpc.ServerStreamingServer[pb.DeployProgress], failures *deployFailures, gate *dependsOnGate) error {
	if len(updates) == 0 {
		return nil
	}
	strategy := useRollingUpdate(f)
	_ = stream.Send(&pb.DeployProgress{
		Phase:  "rolling-update",
		Detail: fmt.Sprintf("strategy=%s vms=%d", strategy, len(updates)),
	})

	// Skip VMs on draining/fenced hosts — drain handles those separately (#19).
	drainingHosts := map[string]bool{}
	if hosts, herr := corrosion.ListHosts(ctx, s.db); herr == nil {
		for _, h := range hosts {
			if h.State == "draining" || h.State == "fenced" {
				drainingHosts[h.Name] = true
			}
		}
	}

	actions := make([]rolling.VMAction, 0, len(updates))
	for _, a := range updates {
		// A VM whose dependency was not met is not handed to the engine: it
		// keeps running as it is.
		if skip, _ := gate.hold(ctx, a, failures); skip {
			continue
		}
		if drainingHosts[a.TargetHost] {
			_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: a.VMName, Detail: "skipped — host is draining/fenced"})
			continue
		}
		actions = append(actions, rolling.VMAction{
			Name:          a.VMName,
			Strategy:      vmUpdateDef(f, a.VMName),
			Plan:          a.Plan,
			Desired:       a.Spec,
			ForceRecreate: a.Apply == compose.ActionRecreate,
			Repair:        a.Repair,
		})
	}
	if len(actions) == 0 {
		return nil
	}

	for _, a := range actions {
		gate.rolledOut[a.Name] = true
	}
	ops := &serverOps{s: s}
	// An "error" the engine reports goes through failures, like every other
	// failed action: some are not fatal to the engine (a blue-green blue that
	// could not be removed after its green is serving, a snapshot-and-replace
	// -next that did not come up), and those are the only record that the
	// stack has not converged. They also leave the VM unmet for its dependents.
	rerr := rolling.Run(ctx, ops, f.Name, actions, func(p rolling.Progress) {
		if p.Phase == "error" && p.Err != nil {
			gate.markUnmet(p.VMName, p.Err)
			_ = failures.failWithDetail(p.VMName, p.Detail, p.Err)
			return
		}
		errStr := ""
		if p.Err != nil {
			errStr = p.Err.Error()
		}
		_ = stream.Send(&pb.DeployProgress{Phase: p.Phase, VmName: p.VMName, Detail: p.Detail, Error: errStr})
	})
	if rerr != nil {
		s.audit(ctx, "stack.rolling_update", f.Name, rerr.Error(), "error")
		return rerr
	}
	return nil
}
