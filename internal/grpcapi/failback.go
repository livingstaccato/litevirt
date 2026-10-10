package grpcapi

// Failback after maintenance: `lv host failback`, `lv host undrain --failback`,
// `lv cluster failback`, a VM's placement.failback (docs/migration-failover.md,
// "Failback").
//
// A drain records, for every VM it moves off a host, a drain_origin record: the
// host it left, the host it went to, and the VM's creation time and ownership
// epoch right after the move (internal/corrosion/failback.go). Failback moves a
// VM back only while that record still describes it exactly. Every ownership
// transfer bumps the epoch, so a VM an operator has since migrated by hand, that
// a failover has recovered, or that a later drain has moved again no longer
// matches and stays where it is. A VM that was never drained has no record and
// is never touched, whatever its host.
//
// Opt-in is three-way, and any one suffices: the cluster policy (`lv cluster
// failback on`), the VM's own placement.failback, or the operator asking for
// this run (all). Nothing moves back on its own otherwise.
//
// The move is the ordinary live migration (MigrateVM), so everything it checks
// holds: the destination's admission, the split-brain gate, the CPU
// preflight. Before it, the host is validated as a placement target through
// the same hard-filter pipeline as placement (capacity, labels, devices,
// anti-affinity, per-node limits). VMs move one at a time with a pause between
// moves (failbackPause), which is the rate bound.
//
// A VM failback cannot move live (a host-local disk, which a live move would
// have to copy, or a stopped VM) is reported and left, with its record, for
// `lv migrate`.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// failbackPause is how long a run waits after a move before the next one, so a
// returning host is not hit by every migration at once. A variable so tests
// need not wait.
var failbackPause = 20 * time.Second

// Failback result statuses (pb.FailbackProgress.Status).
const (
	failbackMoved     = "moved"
	failbackWouldMove = "would-move"
	failbackSkipped   = "skipped"
	failbackFailed    = "failed"
)

type failbackOpts struct {
	all    bool
	dryRun bool
}

// failbackRuns holds the hosts a failback is running for.
type failbackRuns struct {
	mu      sync.Mutex
	running map[string]bool
}

func (f *failbackRuns) begin(host string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.running == nil {
		f.running = map[string]bool{}
	}
	if f.running[host] {
		return false
	}
	f.running[host] = true
	return true
}

func (f *failbackRuns) end(host string) {
	f.mu.Lock()
	delete(f.running, host)
	f.mu.Unlock()
}

// recordDrainOrigin notes that a drain of from moved vmName to to. It records
// only a VM the drain really left on to, and says so in the log when it cannot:
// failback is then unavailable for that VM, which is the safe direction.
func (s *Server) recordDrainOrigin(ctx context.Context, vmName, from, to string) {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil || vm.HostName != to {
		return
	}
	err = corrosion.PutDrainOrigin(ctx, s.db, corrosion.DrainOrigin{
		VM: vmName, From: from, To: to, Epoch: vm.OwnerEpoch, CreatedAt: vm.CreatedAt,
	}, "drain")
	if err != nil {
		slog.Info("drain: not recorded for failback", "vm", vmName, "from", from, "to", to, "error", err)
	}
}

// spendDrainOrigin collects vmName's drain record, when it has one: a live
// migration has just moved the VM, so the record no longer describes where it
// is. A read first, so a migration of a VM no drain moved writes nothing.
func (s *Server) spendDrainOrigin(ctx context.Context, vmName string) {
	rows, err := s.db.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL AND value != '{}'`,
		"drain_origin/"+vmName)
	if err != nil || len(rows) == 0 {
		return
	}
	if err := corrosion.CollectDrainOrigin(ctx, s.db, vmName, "migrate"); err != nil {
		slog.Warn("migrate: could not spend the drain record; failback may move this VM back", "vm", vmName, "error", err)
	}
}

// FailbackHost moves the VMs a drain moved off host back to it.
func (s *Server) FailbackHost(req *pb.FailbackHostRequest, stream pb.LiteVirt_FailbackHostServer) error {
	ctx := stream.Context()
	if err := RequireRole(ctx, "admin"); err != nil {
		return err
	}
	if req.GetName() == "" {
		return status.Error(codes.InvalidArgument, "host name required")
	}
	return s.runFailback(ctx, req.GetName(), failbackOpts{all: req.GetAll(), dryRun: req.GetDryRun()},
		func(p *pb.FailbackProgress) error { return stream.Send(p) })
}

// autoFailback is what an undrain starts: a failback of the VMs that opted in,
// in the background, when there is anything to move. It returns at once.
func (s *Server) autoFailback(ctx context.Context, host string) {
	origins, err := corrosion.ListDrainOrigins(ctx, s.db, host)
	if err != nil || len(origins) == 0 {
		return
	}
	// Only when something would move: the policy is on, or a VM with a record
	// opted in. An undrain that has nothing to do starts nothing.
	if p, perr := corrosion.GetFailbackPolicy(ctx, s.db); perr != nil || !p.Enabled {
		optedIn := false
		for _, o := range origins {
			vm, gerr := corrosion.GetVM(ctx, s.db, o.VM)
			if gerr != nil || vm == nil || vm.Spec == "" {
				continue
			}
			var spec pb.VMSpec
			if json.Unmarshal([]byte(vm.Spec), &spec) == nil && spec.GetPlacement().GetFailback() {
				optedIn = true
				break
			}
		}
		if !optedIn {
			return
		}
	}
	bg := context.WithValue(context.WithoutCancel(ctx), ctxKeyRole, "admin")
	bg = context.WithValue(bg, ctxKeyUsername, "system:failback")
	go func() {
		err := s.runFailback(bg, host, failbackOpts{}, func(p *pb.FailbackProgress) error {
			slog.Info("failback", "host", host, "vm", p.VmName, "status", p.Status, "reason", p.Reason)
			return nil
		})
		if err != nil {
			slog.Warn("failback ended early", "host", host, "error", err)
		}
	}()
}

func (s *Server) runFailback(ctx context.Context, host string, opts failbackOpts, emit func(*pb.FailbackProgress) error) error {
	h, err := corrosion.GetHost(ctx, s.db, host)
	if err != nil || h == nil {
		return status.Errorf(codes.NotFound, "host %q not found", host)
	}
	if h.State != "active" {
		return status.Errorf(codes.FailedPrecondition,
			"host %q is %s: failback returns VMs to an active host (`lv host undrain %s` first)", host, h.State, host)
	}
	if !s.failbacks.begin(host) {
		return status.Errorf(codes.FailedPrecondition, "a failback to host %q is already running", host)
	}
	defer s.failbacks.end(host)

	origins, err := corrosion.ListDrainOrigins(ctx, s.db, host)
	if err != nil {
		return status.Errorf(codes.Internal, "read drain records: %v", err)
	}
	policy, err := corrosion.GetFailbackPolicy(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Internal, "read failback policy: %v", err)
	}
	sort.Slice(origins, func(i, j int) bool { return origins[i].VM < origins[j].VM })

	moved := false
	for _, o := range origins {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A VM is evaluated against the host's CURRENT state: an operator may
		// have drained it again while an earlier VM was moving.
		if cur, gerr := corrosion.GetHost(ctx, s.db, host); gerr != nil || cur == nil || cur.State != "active" {
			return emit(&pb.FailbackProgress{VmName: o.VM, FromHost: o.To, Status: failbackSkipped,
				Reason: "host " + host + " is no longer active; stopped"})
		}
		if moved && !opts.dryRun {
			select {
			case <-time.After(failbackPause):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		res := s.failbackOne(ctx, host, o, policy.Enabled, opts)
		if res.Status == failbackMoved {
			moved = true
		}
		if err := emit(res); err != nil {
			return err
		}
	}
	return nil
}

// failbackOne decides and, unless dry, performs one VM's move back to host.
func (s *Server) failbackOne(ctx context.Context, host string, o corrosion.DrainOrigin, policyOn bool, opts failbackOpts) *pb.FailbackProgress {
	res := &pb.FailbackProgress{VmName: o.VM, FromHost: o.To}
	skip := func(why string) *pb.FailbackProgress { res.Status, res.Reason = failbackSkipped, why; return res }
	// stale: the record can never apply again, so it is collected.
	stale := func(why string) *pb.FailbackProgress {
		if err := corrosion.CollectDrainOrigin(ctx, s.db, o.VM, "failback"); err != nil {
			slog.Debug("failback: could not collect a stale record", "vm", o.VM, "error", err)
		}
		return skip(why)
	}

	vm, err := corrosion.GetVM(ctx, s.db, o.VM)
	if err != nil || vm == nil {
		return stale("the VM no longer exists")
	}
	if vm.CreatedAt != o.CreatedAt {
		return stale("the VM was deleted and created again since the drain")
	}
	if vm.HostName != o.To || vm.OwnerEpoch != o.Epoch {
		return stale(fmt.Sprintf("the VM was moved since the drain put it on %s (it is on %s): "+
			"it was moved for another reason and stays where it is", o.To, vm.HostName))
	}

	var spec pb.VMSpec
	if vm.Spec != "" {
		_ = json.Unmarshal([]byte(vm.Spec), &spec)
	}
	if !opts.all && !policyOn && !spec.GetPlacement().GetFailback() {
		return skip("not opted in: set placement.failback on the VM, `lv cluster failback on`, or run `lv host failback " + host + " --all`")
	}
	if spec.GetPlacement().GetNoMigrate() || spec.GetMigrate().GetStrategy() == pb.MigrateStrategy_MIGRATE_NONE {
		return skip("the VM opted out of migration")
	}
	if pin := spec.GetPlacement().GetHost(); pin != "" && pin != host {
		return skip("the VM is pinned to " + pin)
	}
	if vm.State != "running" {
		return skip(fmt.Sprintf("the VM is %s: failback moves a running VM live; move it with `lv migrate %s %s --cold`", vm.State, vm.Name, host))
	}
	disks, derr := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if derr != nil {
		return skip("cannot read the VM's disks: " + derr.Error())
	}
	for _, d := range disks {
		if isHostLocalDisk(d) {
			return skip(fmt.Sprintf("disk %s is on host-local storage, which a live move does not carry: "+
				"`lv migrate %s %s --cold`, or `--with-storage`", d.DiskName, vm.Name, host))
		}
	}
	if err := placement.ValidatePinned(ctx, s.db, buildDrainPlacementRequest(*vm, "", s.capacity), host); err != nil {
		return skip("the host is not a valid placement for it now: " + err.Error())
	}
	if opts.dryRun {
		res.Status = failbackWouldMove
		return res
	}

	err = s.MigrateVM(&pb.MigrateVMRequest{
		VmName: vm.Name, TargetHost: host, Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	}, &discardMigrateStream{ctx: ctx})
	if err != nil {
		s.recordVMEvent(ctx, vm.Name, "vm.failback", "error", "failback to "+host+" failed: "+err.Error())
		res.Status, res.Reason = failbackFailed, status.Convert(err).Message()
		return res
	}
	if cerr := corrosion.CollectDrainOrigin(ctx, s.db, vm.Name, "failback"); cerr != nil && !errors.Is(cerr, corrosion.ErrClusterPolicyGateClosed) {
		slog.Warn("failback: moved, but the drain record was not collected", "vm", vm.Name, "error", cerr)
	}
	s.recordVMEvent(ctx, vm.Name, "vm.failback", "ok", fmt.Sprintf("moved back to %s from %s after maintenance", host, o.To))
	s.audit(ctx, "vm.failback", vm.Name, fmt.Sprintf("%s -> %s", o.To, host), "ok")
	res.Status = failbackMoved
	return res
}

// GetFailbackPolicy reports the cluster failback policy.
func (s *Server) GetFailbackPolicy(ctx context.Context, _ *emptypb.Empty) (*pb.FailbackPolicyStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	return s.failbackPolicyStatus(ctx)
}

// SetFailbackPolicy turns the cluster failback policy on or off. It refuses
// until failover_scope_v1 has latched, as every cluster_policies write does: a
// peer that cannot decode the table would stall on the write.
func (s *Server) SetFailbackPolicy(ctx context.Context, req *pb.SetFailbackPolicyRequest) (*pb.FailbackPolicyStatus, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if !s.failoverScopeSettable() {
		return nil, status.Error(codes.FailedPrecondition,
			"the failback policy cannot be changed until failover_scope_v1 has latched on every host: "+
				"finish rolling every host (and every host in maintenance) to this release first")
	}
	if err := corrosion.SetFailbackPolicy(ctx, s.db, req.GetEnabled(), callerUsername(ctx)); err != nil {
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "set failback policy: %v", err)
	}
	s.audit(ctx, "cluster.failback", "failback", fmt.Sprintf("failback policy enabled=%t", req.GetEnabled()), "ok")
	return s.failbackPolicyStatus(ctx)
}

func (s *Server) failbackPolicyStatus(ctx context.Context) (*pb.FailbackPolicyStatus, error) {
	p, err := corrosion.GetFailbackPolicy(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read failback policy: %v", err)
	}
	return &pb.FailbackPolicyStatus{
		Enabled: p.Enabled, SetBy: p.SetBy, UpdatedAt: p.UpdatedAt, Settable: s.failoverScopeSettable(),
	}, nil
}

// SetFailbackPauseForTest sets the pause between failback moves and returns what
// restores it. Tests only.
func SetFailbackPauseForTest(d time.Duration) (restore func()) {
	old := failbackPause
	failbackPause = d
	return func() { failbackPause = old }
}
