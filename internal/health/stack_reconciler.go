package health

import (
	"context"
	"log/slog"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/protobuf/types/known/emptypb"
)

const stackReconcileInterval = 30 * time.Second

// stackTeardownGrace is how long a teardown is left to the compose down that
// began it before the reconciler takes it up. DeleteStack marks the stack
// "deleting" before it deletes anything (so a crashed teardown is finished
// here), and every host runs this loop: with no grace a reconciler took up a
// teardown 0.1 s after it began and raced it member by member (lab 2
// 2026-10-17, anomaly 2).
const stackTeardownGrace = 60 * time.Second

// StackCleaner is the interface for resource cleanup operations.
// Implemented by grpcapi.Server.
type StackCleaner interface {
	// DeleteVMForStackCleanup, NOT DeleteVM. This loop has no identity, and DeleteVM is
	// RBAC-gated — calling it directly fails "no authenticated principal" every time and
	// the retry loop spins forever. The implementation attaches a system principal.
	DeleteVMForStackCleanup(ctx context.Context, req *pb.DeleteVMRequest) (*emptypb.Empty, error)
	// DeleteContainerForStackCleanup is the same for a stack's container.
	DeleteContainerForStackCleanup(ctx context.Context, req *pb.DeleteContainerRequest) (*emptypb.Empty, error)
	RemoveLBForStack(ctx context.Context, stackName string, vms []corrosion.VMRecord)
	DeprovisionNetworkByName(ctx context.Context, name string) error
	ExternalNetworkNames(ctx context.Context, stackName string) (map[string]bool, error)
}

// StackReconciler watches for stacks in "deleting" state and retries
// resource cleanup until all resources are gone, then tombstones the stack.
type StackReconciler struct {
	hostName string
	db       *corrosion.Client
	cleaner  StackCleaner

	// now is the clock (time.Now; tests replace it). deletingSeen is, per
	// stack in "deleting", the updated_at it was seen with and when this
	// host first saw that value (teardownInFlight).
	now          func() time.Time
	deletingSeen map[string]deletingSighting
}

// deletingSighting is a stack's teardown stamp and when this host first saw it.
type deletingSighting struct {
	updatedAt string
	at        time.Time
}

// NewStackReconciler creates a stack reconciler.
func NewStackReconciler(hostName string, db *corrosion.Client) *StackReconciler {
	return &StackReconciler{
		hostName:     hostName,
		db:           db,
		now:          time.Now,
		deletingSeen: map[string]deletingSighting{},
	}
}

// SetCleaner registers the cleanup implementation (typically grpcapi.Server).
func (r *StackReconciler) SetCleaner(c StackCleaner) {
	r.cleaner = c
}

// Start begins the reconcile loop. Blocks until ctx is cancelled.
func (r *StackReconciler) Start(ctx context.Context) {
	ticker := time.NewTicker(stackReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcile(ctx)
		}
	}
}

func (r *StackReconciler) reconcile(ctx context.Context) {
	if r.cleaner == nil {
		return
	}

	stacks, err := corrosion.ListDeletingStacks(ctx, r.db)
	if err != nil {
		slog.Error("stack-reconciler: list deleting stacks", "error", err)
		return
	}

	listed := make(map[string]bool, len(stacks))
	for _, stack := range stacks {
		listed[stack.Name] = true
		if r.teardownInFlight(stack) {
			slog.Debug("stack-reconciler: teardown began recently; left to the compose down running it",
				"stack", stack.Name, "updated_at", stack.UpdatedAt)
			continue
		}
		r.reconcileStack(ctx, stack)
	}
	for name := range r.deletingSeen {
		if !listed[name] {
			delete(r.deletingSeen, name)
		}
	}

	// Rows a torn-down stack still owns (handed to it by a concurrent
	// teardown that read it as live) go to a live stack that asks for them,
	// or go.
	if orphan, err := corrosion.SweepOrphanStackRows(ctx, r.db, compose.StoredStackWants); err != nil {
		slog.Warn("stack-reconciler: sweep the rows of torn-down stacks", "error", err)
	} else {
		r.reportOrphanDeny(ctx, orphan)
	}

	// A live stack that asks for the cluster default-deny gets it back when
	// the cluster has none, e.g. after its owner went down while this
	// stack's deploy was in flight.
	if err := corrosion.ReassertStackDefaultDeny(ctx, r.db, compose.StoredStackWants); err != nil {
		slog.Warn("stack-reconciler: re-assert the cluster default-deny a stack asks for", "error", err)
	}
}

// teardownInFlight reports a stack whose teardown began less than
// stackTeardownGrace ago: its updated_at (stamped by SetStackState when
// DeleteStack marked it "deleting") is younger than the grace by this host's
// clock, and this host has not yet seen that same stamp for the grace.
//
// The second half is what bounds the wait. updated_at comes from the
// coordinator's clock, and one running ahead of this host's would keep the
// stamp young for as long as it is ahead; a stamp that sits unchanged for the
// grace is taken up whatever it says. Only a new stamp — a teardown begun
// again — restarts the grace, so a stack is left only while compose down keeps
// being re-run, each run a teardown of its own.
func (r *StackReconciler) teardownInFlight(stack corrosion.StackRecord) bool {
	now := r.now()
	seen, ok := r.deletingSeen[stack.Name]
	if !ok || seen.updatedAt != stack.UpdatedAt {
		seen = deletingSighting{updatedAt: stack.UpdatedAt, at: now}
		r.deletingSeen[stack.Name] = seen
	}
	if now.Sub(seen.at) >= stackTeardownGrace {
		return false
	}
	began, ok := corrosion.ParseUpdatedAt(stack.UpdatedAt)
	return ok && now.Sub(began) < stackTeardownGrace
}

func (r *StackReconciler) reconcileStack(ctx context.Context, stack corrosion.StackRecord) {
	slog.Info("stack-reconciler: cleaning up stack", "stack", stack.Name)

	// 1. Delete remaining VMs.
	vms, err := corrosion.ListVMs(ctx, r.db, stack.Name, "")
	if err != nil {
		slog.Error("stack-reconciler: list VMs", "stack", stack.Name, "error", err)
		return
	}

	remainingVMs := 0
	for _, vm := range vms {
		// Bound to the incarnation listed as the stack's: the host that
		// deletes it deletes nothing else of that name, and a VM that is no
		// longer this one is left alone (WARN) and listed afresh next pass.
		if _, err := r.cleaner.DeleteVMForStackCleanup(ctx, &pb.DeleteVMRequest{
			Name: vm.Name, ExpectedStack: stack.Name, ExpectedCreatedAt: vm.CreatedAt,
		}); err != nil {
			slog.Warn("stack-reconciler: delete VM failed, will retry",
				"stack", stack.Name, "vm", vm.Name, "error", err)
			remainingVMs++
		}
	}

	// 1b. Delete remaining containers (tagged with the stack label).
	remainingCTs := 0
	cts, err := corrosion.ListContainersByStack(ctx, r.db, stack.Name)
	if err != nil {
		slog.Warn("stack-reconciler: list containers failed, will retry",
			"stack", stack.Name, "error", err)
		remainingCTs++
	}
	for _, ct := range cts {
		if _, err := r.cleaner.DeleteContainerForStackCleanup(ctx,
			&pb.DeleteContainerRequest{HostName: ct.HostName, Name: ct.Name, Force: true}); err != nil {
			slog.Warn("stack-reconciler: delete container failed, will retry",
				"stack", stack.Name, "container", ct.Name, "host", ct.HostName, "error", err)
			remainingCTs++
		}
	}

	// 2. Ensure LB config is soft-deleted and processes are stopped.
	lbName := stack.Name + "-lb"
	_ = corrosion.SoftDeleteLBConfig(ctx, r.db, lbName)
	r.cleaner.RemoveLBForStack(ctx, stack.Name, vms)

	// While a workload is left, its networks stay: a network tombstone reaches
	// every host and would tear the network down under that workload.
	if remainingVMs > 0 || remainingCTs > 0 {
		slog.Info("stack-reconciler: stack still has workloads, networks kept; will retry",
			"stack", stack.Name, "remaining_vms", remainingVMs, "remaining_containers", remainingCTs)
		return
	}

	// 3. Deprovision remaining networks.
	// When the stored compose cannot be read, which networks are external
	// (not the stack's to delete) is unknown: deprovision none, and keep the
	// stack in "deleting" rather than tombstone it with networks unaccounted
	// for.
	externalNets, extErr := r.cleaner.ExternalNetworkNames(ctx, stack.Name)
	if extErr != nil {
		slog.Error("stack-reconciler: networks not deprovisioned, stack kept in deleting",
			"stack", stack.Name, "error", extErr)
		return
	}
	nets, _ := corrosion.ListNetworks(ctx, r.db)
	for _, nr := range nets {
		if nr.StackName == stack.Name && !externalNets[nr.Name] {
			// A workload the stack did not create on it keeps the network.
			if users, err := corrosion.ForeignWorkloadsOnNetwork(ctx, r.db, nr.Name, stack.Name); err != nil || len(users) > 0 {
				slog.Warn("stack-reconciler: keeping a stack network that workloads the stack did not create use",
					"stack", stack.Name, "network", nr.Name, "users", users, "error", err)
				if err != nil {
					return // unknown: retry, stack kept in deleting
				}
				continue
			}
			if err := r.cleaner.DeprovisionNetworkByName(ctx, nr.Name); err != nil {
				slog.Warn("stack-reconciler: network deprovision failed, will retry",
					"stack", stack.Name, "network", nr.Name, "error", err)
			}
		}
	}

	// 4. All workloads are gone: tombstone the stack.
	// Hard-delete the LB config now that everything is cleaned up.
	_ = corrosion.SoftDeleteLBConfig(ctx, r.db, lbName)
	corrosion.SoftDeleteLBBackends(ctx, r.db, lbName)

	// The stack's firewall rows and backup repos go with it, as in a
	// DeleteStack that completes; left behind, a security group holds its name
	// against the next deploy of the same file. A failure keeps the stack
	// 'deleting', so the next pass retries.
	if err := corrosion.DeleteStackFirewall(ctx, r.db, stack.Name, compose.StoredStackWants); err != nil {
		slog.Warn("stack-reconciler: tombstone the stack's firewall failed, will retry", "stack", stack.Name, "error", err)
		return
	}
	if err := corrosion.DeleteStackBackupRepos(ctx, r.db, stack.Name, compose.StoredStackWants); err != nil {
		slog.Warn("stack-reconciler: unregister the stack's backup repos failed, will retry", "stack", stack.Name, "error", err)
		return
	}

	if err := corrosion.DeleteStackRecord(ctx, r.db, stack.Name); err != nil {
		slog.Error("stack-reconciler: tombstone stack failed", "stack", stack.Name, "error", err)
		return
	}

	slog.Info("stack-reconciler: stack fully cleaned up", "stack", stack.Name)
}
