// A paused copy a move left on its target, while the move is unresolved.
//
// A live move whose source fails before the ownership commit can leave the
// guest paused on its target: paused mid-migration, or paused after the
// cutover. That copy may hold the only state written since the cutover, and
// failover holds such a VM (failover_migrating_row_test.go), raising
// vm.migration_unresolved toward the target. A lease holder on an older
// build does not hold it: it reschedules the migrating row like any other,
// and when placement picks the target, the row arrives there pending. The
// target's reconciler then found a domain "that exists but is not running",
// destroyed it and booted the VM afresh from its disks: the paused guest,
// and with it whatever ran after the cutover, was gone.
//
// While vm.migration_unresolved is open toward this host, the reconciler
// leaves a paused copy alone, and the condition stays open while it is
// there: an operator resumes it (the guest runs here, and is recorded so) or
// discards it (`virsh destroy`; the VM is then started here from its disks),
// and either way exactly one copy runs.
package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// daemonReconciler is n's reconciler with the ownership probes the daemon
// wires: each peer's runtime inventory, and Layer 3's certificate check.
func daemonReconciler(n *Node) *health.Reconciler {
	r := n.Reconciler()
	r.SetPeerRuntimeChecker(n.Server.CheckPeerVMRuntime)
	r.SetSettleVerifier(n.Server.VerifySettleProof)
	return r
}

// olderLeaseHolderReschedules writes what a lease holder on a build before
// the migrating-row hold writes for mg1 recovered off its fenced source:
// re-keyed to b, pending (the legacy reschedule).
func olderLeaseHolderReschedules(t *testing.T, c *Cluster, a, b *Node) {
	t.Helper()
	if err := corrosion.RescheduleVMHost(context.Background(), a.DB, "mg1", b.Name, "pending"); err != nil {
		t.Fatalf("reschedule mg1 to %s: %v", b.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
}

// settlePasses runs, n times, each survivor's reconciler and the sweep that
// resolves a settled vm.migration_unresolved, as the daemon runs them.
func settlePasses(t *testing.T, c *Cluster, n int, a, b *Node) {
	t.Helper()
	ctx := context.Background()
	ra, rb := daemonReconciler(a), daemonReconciler(b)
	for i := 0; i < n; i++ {
		rb.ReconcileOnce(ctx)
		ra.ReconcileOnce(ctx)
		c.WaitConverged(t, convergeTimeout, a, b)
		b.Server.ResolveSettledMigrationsOnce(ctx)
		a.Server.ResolveSettledMigrationsOnce(ctx)
		c.WaitConverged(t, convergeTimeout, a, b)
	}
}

// requirePausedCopyKept: b still holds mg1 paused, nothing was done to that
// domain, nothing of mg1 is on a, and vm.migration_unresolved is open.
func requirePausedCopyKept(t *testing.T, a, b *Node) {
	t.Helper()
	detail := mg1Views(t, a, b)
	if st, err := b.Virt.DomainStateReason("mg1"); err != nil || st.Reason != "paused" {
		t.Fatalf("%s's paused copy of mg1 is gone: state %+v (err %v)\n  %s", b.Name, st, err, detail)
	}
	for _, ev := range b.Virt.EventLog() {
		if ev.Domain == "mg1" {
			t.Fatalf("%s acted on its paused copy of mg1 (%s %s) while its move is unresolved\n  %s", b.Name, ev.Op, ev.Note, detail)
		}
	}
	if a.Virt.DomainExists("mg1") {
		t.Fatalf("%s holds a domain of mg1\n  %s", a.Name, detail)
	}
	for _, n := range []*Node{a, b} {
		if !migrationUnresolvedOpen(t, n) {
			t.Fatalf("%s: vm.migration_unresolved was resolved while %s holds the paused copy\n  %s", n.Name, b.Name, detail)
		}
	}
}

// TestFleet_MigratingRow_PausedTargetCopyIsKeptWhenAnOlderLeaseHolderReschedulesIt:
// mg1's source fails mid-move with the guest paused on its target b. This
// build's recovery holds it (vm.migration_unresolved). A lease holder on an
// older build then reschedules it to b. b's reconciler keeps the paused copy
// and the condition stays open, across passes. The operator's two exits each
// end with exactly one running copy:
//
//   - resumed: the guest runs on b, its row is recorded running there, and
//     the condition is resolved;
//   - discarded (`virsh destroy` on b): the condition is resolved, and the VM
//     is started on b from its disks;
//   - nic-guard-resumed: mg1 was handed over paused for its NIC guards, so b
//     holds a record that it resumes the guest. While the row names the
//     source it does not; once the reschedule names b, b's resumer resumes
//     it by itself, which is the "resumed" exit: one copy, on b.
//
// Mutations: drop the reconciler's hold (unresolved_move_hold.go) — b
// destroys the paused copy and boots mg1 afresh, red; drop the resolution
// hold (resolveMigrationUnresolvedIfSettled) — b's sweep resolves the
// condition, and the next pass destroys the copy, red.
func TestFleet_MigratingRow_PausedTargetCopyIsKeptWhenAnOlderLeaseHolderReschedulesIt(t *testing.T) {
	for _, exit := range []string{"resumed", "discarded", "nic-guard-resumed"} {
		t.Run(exit, func(t *testing.T) {
			clock := NewVirtualClock(time.Now().UTC())
			c, a, b, victim := migratingRowFleet(t, clock, false, libvirtfake.StatePaused)
			runRecovery(t, c, clock, false, a, b)
			assertControlRecovered(t, c, a, victim)
			requireHeldNaming(t, a, b, victim, "holds a domain of it in state")

			if exit == "nic-guard-resumed" {
				// The move handed mg1 over paused for its NIC guards: b
				// recorded, before it arrived, that it lets the guest run
				// once they are in force (nic_guard_held.go).
				if _, err := c.PeerClient(a, b).ArmNICFirewall(context.Background(),
					&pb.ArmNICFirewallRequest{VmName: "mg1", PausedHandover: true}); err != nil {
					t.Fatalf("arm mg1's paused hand-over on %s: %v", b.Name, err)
				}
				if held := b.Server.HeldGuestsForTests(); len(held) != 1 || held[0] != "mg1" {
					t.Fatalf("%s holds %v, want mg1", b.Name, held)
				}
				// While the row names the fenced source, b's resumer does
				// not resume it: the move's commit is not recorded.
				b.Server.ResumeHeldGuestsOnce(context.Background())
				if st, _ := b.Virt.RawState("mg1"); st != libvirtfake.StatePaused {
					t.Fatalf("%s's resumer let mg1 run (%s) while its row names %s", b.Name, st, victim.Name)
				}
			}
			olderLeaseHolderReschedules(t, c, a, b)
			settlePasses(t, c, 3, a, b)
			requirePausedCopyKept(t, a, b)

			switch exit {
			case "resumed":
				b.Virt.SetState("mg1", libvirtfake.StateRunning) // `virsh resume mg1` on b
			case "discarded":
				b.Virt.SetState("mg1", libvirtfake.StateShutdown) // `virsh destroy mg1` on b
			case "nic-guard-resumed":
				// The row names b now, so b's NIC-guard resumer lets the
				// guest it held run, by itself: the resume exit.
				b.Server.ResumeHeldGuestsOnce(context.Background())
				if st, _ := b.Virt.RawState("mg1"); st != libvirtfake.StateRunning {
					t.Fatalf("%s's resumer did not let mg1 run once its row names it: %s", b.Name, st)
				}
			}
			settlePasses(t, c, 3, a, b)
			detail := mg1Views(t, a, b)
			if on := runningOn(c, "mg1"); len(on) != 1 || on[0] != b.Name {
				t.Fatalf("mg1 runs on %v, want exactly %s\n  %s", on, b.Name, detail)
			}
			if vm := vmOn(t, a, "mg1"); vm.HostName != b.Name || vm.State != "running" {
				t.Fatalf("mg1's row is not recorded running on %s\n  %s", b.Name, detail)
			}
			for _, n := range []*Node{a, b} {
				if migrationUnresolvedOpen(t, n) {
					t.Fatalf("%s: vm.migration_unresolved is still open once the copy was %s\n  %s", n.Name, exit, detail)
				}
			}
		})
	}
}

// TestFleet_MigratingRow_PausedCopyWithNoUnresolvedMoveIsReplaced: the
// control. The same paused domain on b, and the same reschedule of mg1 to b,
// but no unresolved move recorded toward b (the source and the lease holder
// are both on an older build, which raise no vm.migration_unresolved): b's
// reconciler replaces the domain and starts mg1, as before. Exactly one copy
// runs. The hold is keyed on the unresolved move, not on any paused domain.
//
// Mutation: hold every paused domain, whatever the condition says — red.
func TestFleet_MigratingRow_PausedCopyWithNoUnresolvedMoveIsReplaced(t *testing.T) {
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, _ := migratingRowFleet(t, clock, false, libvirtfake.StatePaused)
	olderLeaseHolderReschedules(t, c, a, b)
	if migrationUnresolvedOpen(t, b) {
		t.Fatal("vm.migration_unresolved is open: the control needs none")
	}
	settlePasses(t, c, 3, a, b)
	detail := mg1Views(t, a, b)
	if on := runningOn(c, "mg1"); len(on) != 1 || on[0] != b.Name {
		t.Fatalf("mg1 runs on %v, want exactly %s: with no unresolved move the reconciler starts it\n  %s", on, b.Name, detail)
	}
	if _, ok := firstEvent(b, "destroy", "mg1"); !ok {
		t.Fatalf("%s started mg1 without replacing its paused domain\n  %s", b.Name, detail)
	}
}
