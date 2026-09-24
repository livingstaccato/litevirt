package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

func fencerReturning(method string, success bool) Fencer {
	return func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: method, Detail: "stub " + method, Success: success}
	}
}

// seedDownHost is one host quorum agrees is down, carrying a restart-any VM, plus
// a healthy peer to receive it. labels are applied to the down host.
func seedDownHost(t *testing.T, strategy string, labels map[string]string) (*corrosion.Client, context.Context) {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "down", Address: "10.0.0.40", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: strategy},
		{Name: "alive", Address: "10.0.0.41", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	for k, v := range labels {
		if err := corrosion.SetHostLabel(ctx, db, "down", k, v); err != nil {
			t.Fatalf("SetHostLabel: %v", err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm", HostName: "down", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	for _, o := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'down', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			o, offlineThreshold); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}
	return db, ctx
}

var requireConfirmation = map[string]string{corrosion.LabelFenceRequiresConfirmation: "true"}

func vmHost(t *testing.T, db *corrosion.Client, ctx context.Context) string {
	t.Helper()
	vm, err := corrosion.GetVM(ctx, db, "vm")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	return vm.HostName
}

func hostState(t *testing.T, db *corrosion.Client, ctx context.Context) string {
	t.Helper()
	h, err := corrosion.GetHost(ctx, db, "down")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	return h.State
}

// With the label, an SSH fence that reported success is not enough to move the
// host's workloads.
//
// An SSH "success" means a shell accepted a poweroff command. Nothing looks
// afterwards: a shutdown that hangs — on a stuck unmount, a wedged NFS client —
// leaves the host up with its VMs running, and the coordinator that ran the
// fence would already have started them somewhere else. This label is the
// operator's per-host "do not reschedule on a fence nobody verified".
func TestFenceRequiresConfirmation_AnUnverifiedFenceDoesNotReschedule(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", requireConfirmation)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(fencerReturning("ssh", true))

	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q on an unverified SSH fence of a host that requires confirmation", got)
	}
	// Not "fenced": that state is the cluster's statement that the host is
	// known to be off, and nothing established that.
	if got := hostState(t, db, ctx); got == "fenced" {
		t.Errorf("host state = %q after an unverified fence; want it NOT recorded as fenced", got)
	}
}

// Without the label, nothing changes: an SSH success still reschedules. This is
// the default, and the reason the setting is opt-in — distrusting SSH removes
// automatic recovery from every SSH-fenced host.
func TestFenceRequiresConfirmation_DefaultIsUnchanged(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(fencerReturning("ssh", true))

	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM on %q; without the label an SSH success must reschedule exactly as before", got)
	}
}

// A VERIFIED fence is unaffected by the label: IPMI observed the host off,
// which is the confirmation.
func TestFenceRequiresConfirmation_AVerifiedFenceStillReschedules(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", requireConfirmation)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(fencerReturning("ipmi", true))

	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM on %q; an IPMI-verified fence satisfies the label", got)
	}
}

// best-effort is covered too: its lenient success reports Method "ssh", and its
// proceed-after-failure reports "best-effort-ssh". Neither verified anything.
func TestFenceRequiresConfirmation_CoversBestEffort(t *testing.T) {
	for _, method := range []string{"ssh", "best-effort-ssh"} {
		db, ctx := seedDownHost(t, "best-effort", requireConfirmation)
		c := newTestCoordinator("coordinator", db)
		c.SetFencer(fencerReturning(method, true))

		c.run(ctx)

		if got := vmHost(t, db, ctx); got != "down" {
			t.Errorf("best-effort fence reporting %q moved the VM to %q despite the label", method, got)
		}
	}
}

// The gate itself honours an operator confirmation. Tested at recoverFenced,
// not through run(): a fence cycle that has already refused a host does not
// revisit it, so today a confirmation written AFTER the refusal never reaches
// this gate — the #252 strand, shared with manual and safe-fence hosts. This
// pins what the gate does once something does bring the host back to it.
func TestFenceRequiresConfirmation_TheGateAcceptsAnOperatorConfirmation(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", requireConfirmation)
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "op", HostName: "down", Method: "manual", Result: "manual-confirmed",
	}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}
	c := newTestCoordinator("coordinator", db)
	h, err := corrosion.GetHost(ctx, db, "down")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if !c.acquireLease(ctx) {
		t.Fatal("precondition: acquire the lease")
	}

	c.recoverFenced(ctx, h, fence.Result{Method: "ssh", Success: true})

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM on %q; an operator confirmation satisfies the label", got)
	}
}
