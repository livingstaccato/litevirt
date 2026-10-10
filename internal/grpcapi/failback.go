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
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// failbackPause is how long a run waits after a move before the next one, so a
// returning host is not hit by every migration at once. A variable so tests
// need not wait.
var failbackPause = 20 * time.Second

// failbackNotActiveWait and failbackNotActiveTries bound the wait for the
// VM's owner to hear that the returning host is active again: an undrain
// writes the host's state on one node, and the owner, which decides the move on
// its own replica, can be a moment behind. Only that refusal is waited out.
var (
	failbackNotActiveWait  = 500 * time.Millisecond
	failbackNotActiveTries = 30
)

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

// failbackRun is one failback on this daemon for one host: its results so far,
// whether it has finished, and a way to wait for more. A run is kept after it
// finishes, so the command that follows the run an undrain started sees every
// result even if the run was quicker than the command.
type failbackRun struct {
	host    string
	all     bool
	started time.Time

	mu      sync.Mutex
	results []*pb.FailbackProgress
	done    bool
	err     error
	wake    chan struct{} // closed and replaced whenever the run changes
}

func newFailbackRun(host string, all bool) *failbackRun {
	return &failbackRun{host: host, all: all, started: time.Now(), wake: make(chan struct{})}
}

func (r *failbackRun) emit(p *pb.FailbackProgress) {
	r.mu.Lock()
	r.results = append(r.results, p)
	close(r.wake)
	r.wake = make(chan struct{})
	r.mu.Unlock()
}

func (r *failbackRun) finish(err error) {
	r.mu.Lock()
	r.done, r.err = true, err
	close(r.wake)
	r.wake = make(chan struct{})
	r.mu.Unlock()
}

// follow sends every result, past and to come, until the run is done or ctx is.
func (r *failbackRun) follow(ctx context.Context, send func(*pb.FailbackProgress) error) error {
	next := 0
	for {
		r.mu.Lock()
		batch := append([]*pb.FailbackProgress(nil), r.results[next:]...)
		done, err, wake := r.done, r.err, r.wake
		r.mu.Unlock()
		for _, p := range batch {
			if serr := send(p); serr != nil {
				return serr
			}
		}
		next += len(batch)
		if done && len(batch) == 0 {
			return err
		}
		if done {
			continue
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// failbackRuns holds the latest run per host on this daemon.
type failbackRuns struct {
	mu   sync.Mutex
	runs map[string]*failbackRun
}

// start registers a new run for host, unless one is still running.
func (f *failbackRuns) start(host string, all bool) (*failbackRun, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur := f.runs[host]; cur != nil {
		cur.mu.Lock()
		running := !cur.done
		cur.mu.Unlock()
		if running {
			return cur, false
		}
	}
	if f.runs == nil {
		f.runs = map[string]*failbackRun{}
	}
	r := newFailbackRun(host, all)
	f.runs[host] = r
	return r, true
}

func (f *failbackRuns) latest(host string) *failbackRun {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[host]
}

// failbackFeatureGate is the one place failback asks whether every host runs
// the build that advances a VM's placement generation and cancels its drain
// record whenever its host changes. Until it passes, no record is written and nothing
// fails back, and an undrain behaves exactly as it always has. PROVISIONAL: it
// stands on the durable failover_scope_v1 latch, which builds from before this
// feature also advertise, so on a mixed cluster it does not yet guarantee what
// it is named for. The cluster's single release token replaces its body before
// this ships; nothing else in failback knows how the answer is reached.
func (s *Server) failbackFeatureGate(ctx context.Context) error {
	if s.gate != nil && s.gate.DurablyLatched(capabilities.FailoverScopeV1) {
		return nil
	}
	return status.Error(codes.FailedPrecondition,
		"failback waits for the upgrade: not every host runs the release that records what a drain moved. "+
			"Finish rolling every host (and every host in maintenance) to this release")
}

// recordDrainOrigin notes that a drain of from moved vmName to to. It records
// only a VM the drain really left on to, and only once the failback
// feature gate passes; failback is otherwise unavailable for that VM, the safe direction.
func (s *Server) recordDrainOrigin(ctx context.Context, vmName, from, to string) {
	if s.failbackFeatureGate(ctx) != nil {
		slog.Info("drain: not recorded for failback: the upgrade has not finished on every host", "vm", vmName)
		return
	}
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil || vm.HostName != to {
		return
	}
	gen, _ := corrosion.GetPlacementGen(ctx, s.db, vmName)
	err = corrosion.PutDrainOrigin(ctx, s.db, corrosion.DrainOrigin{
		VM: vmName, From: from, To: to, Epoch: vm.OwnerEpoch, CreatedAt: vm.CreatedAt, Gen: gen,
	}, "drain")
	if err != nil {
		slog.Info("drain: not recorded for failback", "vm", vmName, "from", from, "to", to, "error", err)
	}
}

// failbackPreconditionMarker begins the message of the owner-side refusal of a
// failback move, which failbackOne reports as a skip rather than a failure.
const failbackPreconditionMarker = "failback precondition:"

// checkDrainExpectation is the owner's half of a failback move, made under the
// VM's lock against this host's own replica: this host owns the VM and is the
// host the caller saw it on, the owner epoch is the one recorded, and the VM's
// placement generation is the one the drain recorded. Every change of the VM's
// host advances the generation in the batch that changes it, so the owner has
// the generation of the move that made it the owner; this does not depend on
// the drain's record, which may be the last thing a drained host wrote before it
// went away, having reached nobody. The daemon that decided to move the VM read
// a replica that may lag; the host that owns it cannot lag about where the VM
// is.
func (s *Server) checkDrainExpectation(ctx context.Context, req *pb.MigrateVMRequest, vm *corrosion.VMRecord) error {
	refuse := func(why string) error {
		return status.Errorf(codes.FailedPrecondition, "%s %s: it is not where the drain left it", failbackPreconditionMarker, why)
	}
	if req.GetExpectHost() != s.hostName || vm.HostName != s.hostName {
		return refuse(fmt.Sprintf("the VM was moved since the drain (the caller saw it on %s, it is on %s)", req.GetExpectHost(), vm.HostName))
	}
	if vm.OwnerEpoch != req.GetExpectOwnerEpoch() {
		return refuse("the VM's ownership changed since the drain")
	}
	// The generation, not the record: the owner cannot own the VM without having
	// the generation of the move that made it the owner, whereas the drained
	// host's record may be the last thing that host wrote before it went away.
	gen, err := corrosion.GetPlacementGen(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read the placement generation of %q: %v", vm.Name, err)
	}
	if gen != req.GetExpectPlacementGen() {
		return refuse("the VM's placement changed since the drain")
	}
	return nil
}

// FailbackHost moves the VMs a drain moved off host back to it, or follows the
// run an undrain started.
func (s *Server) FailbackHost(req *pb.FailbackHostRequest, stream pb.LiteVirt_FailbackHostServer) error {
	ctx := stream.Context()
	if err := RequireRole(ctx, "admin"); err != nil {
		return err
	}
	host := req.GetName()
	if host == "" {
		return status.Error(codes.InvalidArgument, "host name required")
	}
	if req.GetFollow() {
		run := s.failbacks.latest(host)
		if run == nil {
			return status.Errorf(codes.NotFound, "no failback to %q has run on %s", host, s.hostName)
		}
		return run.follow(ctx, stream.Send)
	}
	if err := s.failbackPreflight(ctx, host); err != nil {
		return err
	}
	run, ok := s.failbacks.start(host, req.GetAll())
	if !ok {
		return status.Errorf(codes.FailedPrecondition,
			"a failback to host %q is already running on %s (started %s): follow it with `lv host failback %s --follow`",
			host, s.hostName, run.started.Format(time.RFC3339), host)
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		run.finish(s.runFailback(rctx, run, failbackOpts{all: req.GetAll(), dryRun: req.GetDryRun()}))
	}()
	return run.follow(ctx, stream.Send)
}

// failbackPreflight refuses a failback that cannot run at all: the token has
// not latched, the host is unknown or not active.
func (s *Server) failbackPreflight(ctx context.Context, host string) error {
	if err := s.failbackFeatureGate(ctx); err != nil {
		return err
	}
	h, err := corrosion.GetHost(ctx, s.db, host)
	if err != nil || h == nil {
		return status.Errorf(codes.NotFound, "host %q not found", host)
	}
	if h.State != "active" {
		return status.Errorf(codes.FailedPrecondition,
			"host %q is %s: failback returns VMs to an active host (`lv host undrain %s` first)", host, h.State, host)
	}
	return nil
}

// autoFailback is what an undrain starts: a failback of the VMs that opted in,
// in the background, when there is anything to move. It returns at once and
// says, for the undrain's reply, what it did.
func (s *Server) autoFailback(ctx context.Context, host string, h *pb.Host) {
	policy, perr := corrosion.GetFailbackPolicy(ctx, s.db)
	if s.failbackFeatureGate(ctx) != nil {
		if perr == nil && policy.Enabled {
			h.FailbackNote = "failback waits for the upgrade: not every host runs the release that records drains, " +
				"so nothing was recorded for the cluster failback policy to move back; this undrain behaved as it always has"
		}
		return
	}
	origins, err := corrosion.ListDrainOrigins(ctx, s.db, host)
	if err != nil || len(origins) == 0 {
		return
	}
	// Only when something would move: the policy is on, or a VM with a record
	// opted in.
	optedIn := perr == nil && policy.Enabled
	for _, o := range origins {
		if optedIn {
			break
		}
		vm, gerr := corrosion.GetVM(ctx, s.db, o.VM)
		if gerr != nil || vm == nil || vm.Spec == "" {
			continue
		}
		var spec pb.VMSpec
		if json.Unmarshal([]byte(vm.Spec), &spec) == nil && spec.GetPlacement().GetFailback() {
			optedIn = true
		}
	}
	if !optedIn {
		h.FailbackNote = fmt.Sprintf("%d VM(s) a drain moved from %s have not opted in to failback; "+
			"`lv host failback %s --all` moves them back", len(origins), host, host)
		return
	}
	run, ok := s.failbacks.start(host, false)
	if !ok {
		h.FailbackStarted = true
		h.FailbackNote = "a failback to " + host + " is already running on " + s.hostName
		return
	}
	h.FailbackStarted = true
	h.FailbackNote = fmt.Sprintf("failback of up to %d VM(s) started in the background on %s; "+
		"it ends if that daemon restarts, and `lv host failback %s` finishes what is left", len(origins), s.hostName, host)
	// The run is the daemon's own, not the undrain caller's: an explicit system
	// identity and none of the caller's metadata, so a session that expires
	// during a long run cannot fail its later moves and every hop is audited as
	// the system.
	bg := context.WithValue(context.Background(), ctxKeyRole, "admin")
	bg = context.WithValue(bg, ctxKeyUsername, "system:failback")
	go func() {
		err := s.runFailback(bg, run, failbackOpts{})
		if err != nil {
			slog.Warn("failback ended early", "host", host, "error", err)
		}
		run.finish(err)
	}()
}

func (s *Server) runFailback(ctx context.Context, run *failbackRun, opts failbackOpts) error {
	host := run.host
	if err := s.failbackPreflight(ctx, host); err != nil {
		return err
	}
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
			run.emit(&pb.FailbackProgress{VmName: o.VM, FromHost: o.To, Status: failbackSkipped,
				Reason: "host " + host + " is no longer active; stopped"})
			return nil
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
		// Every result that is not a plain "not opted in" is on the VM's own
		// events, so a skip is findable after the run, not only in a log.
		if !opts.dryRun && !strings.HasPrefix(res.Reason, "not opted in") {
			result := "ok"
			if res.Status == failbackFailed {
				result = "error"
			}
			if res.Status != failbackMoved && res.Status != failbackWouldMove { // a move records its own event
				s.recordVMEvent(ctx, o.VM, "vm.failback", result, fmt.Sprintf("failback to %s: %s: %s", host, res.Status, res.Reason))
			}
		}
		run.emit(res)
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
	if gen, _ := corrosion.GetPlacementGen(ctx, s.db, o.VM); vm.HostName != o.To || vm.OwnerEpoch != o.Epoch || gen != o.Gen {
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

	if why := s.ownerCannotCheck(ctx, o.To); why != "" {
		return skip(why)
	}
	for try := 0; ; try++ {
		err = s.MigrateVM(&pb.MigrateVMRequest{
			VmName: vm.Name, TargetHost: host, Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
			// The owner checks, under the VM's lock and on its own replica, that
			// the VM is still exactly where the drain left it (checkDrainExpectation).
			ExpectDrainRecord: true, ExpectHost: o.To, ExpectOwnerEpoch: o.Epoch, ExpectPlacementGen: o.Gen,
		}, &discardMigrateStream{ctx: ctx})
		if err == nil || try >= failbackNotActiveTries || !strings.Contains(err.Error(), "is not active") {
			break
		}
		select {
		case <-time.After(failbackNotActiveWait):
		case <-ctx.Done():
			err = ctx.Err()
		}
		if ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		msg := status.Convert(err).Message()
		if strings.Contains(msg, failbackPreconditionMarker) {
			res.Status, res.Reason = failbackSkipped, strings.TrimSpace(strings.TrimPrefix(msg[strings.Index(msg, failbackPreconditionMarker):], failbackPreconditionMarker))
			return res
		}
		s.recordVMEvent(ctx, vm.Name, "vm.failback", "error", "failback to "+host+" failed: "+err.Error())
		res.Status, res.Reason = failbackFailed, msg
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

// ownerCannotCheck says why the VM's owner cannot be trusted to check a failback
// move's preconditions ("" when it can): an owner on a release that predates
// them ignores the expect_* fields and would migrate the VM unconditionally, so
// the VM is skipped, never moved. This host is its own owner when it is the VM's
// host; any other is asked, with Ping, which every release answers.
func (s *Server) ownerCannotCheck(ctx context.Context, owner string) string {
	if owner == s.hostName {
		return ""
	}
	client, closer, err := s.dialPeer(ctx, owner)
	if err != nil {
		return "cannot reach the VM's host " + owner + " to confirm it checks the move: " + err.Error()
	}
	defer closer()
	resp, err := client.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		return "cannot ask the VM's host " + owner + " whether it checks the move: " + err.Error()
	}
	if !resp.GetMigratePreconditions() {
		return "the VM's host " + owner + " runs an older release that cannot check that the VM is still where the drain left it: " +
			"finish the upgrade, or move it with `lv migrate`"
	}
	return ""
}
