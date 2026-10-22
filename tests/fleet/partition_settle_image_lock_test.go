package fleet

// Lab 2, B4 (v1.10.0-rc1, 2026-10-22): a restart-any VM on an NFS pool. The
// minority host pauses it; the majority waits out the pause and reschedules it;
// the destination's start fails with QEMU's `Failed to get "write" lock`,
// because the paused QEMU on the old host still holds the image. After the heal
// settle declined to destroy the paused copy until the replacement ran, and the
// replacement could not run until the paused copy was gone: zero running
// copies until an operator ran `virsh destroy`.
//
// libvirtfake.ImageLocks models the lock: a live or paused domain holds its
// declared image on every member.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// shareImage joins every node's hypervisor to one image-lock registry and
// declares vm's disk on it: the VM's image on a shared pool.
func shareImage(c *Cluster, vm string) {
	l := libvirtfake.NewImageLocks()
	for _, n := range c.Nodes {
		l.Join(n.Virt)
	}
	l.Declare(vm, "/mnt/nfs/"+vm+"-root.qcow2")
}

func countEvents(n *Node, op, vm string) int {
	k := 0
	for _, ev := range n.Virt.EventLog() {
		if ev.Op == op && ev.Domain == vm {
			k++
		}
	}
	return k
}

// runOwnerCopy is the owner's copy of vm as a daemon leaves it: running, at a
// graduated owner epoch, its definition carrying its UUID and its disk on the
// shared pool. The pause record names the domain by that UUID, which is what
// lets settle tell it is still the copy the pause holds.
func runOwnerCopy(t *testing.T, owner *Node, vm, uuid string) {
	t.Helper()
	owner.Virt.SetInactiveXML(vm, `<domain type='kvm'><name>`+vm+`</name><uuid>`+uuid+`</uuid>`+
		`<memory unit='MiB'>1024</memory><vcpu>1</vcpu><devices><disk type='file' device='disk'>`+
		`<source file='/mnt/nfs/`+vm+`-root.qcow2'/><target dev='vda' bus='virtio'/></disk></devices></domain>`)
	owner.Virt.SetState(vm, libvirtfake.StateRunning)
	if err := owner.Virt.SetDomainOwnerEpoch(vm, 1, true); err != nil {
		t.Fatal(err)
	}
}

// lockRefused reports the first majority node whose start of vm the image
// lock refused.
func lockRefused(nodes []*Node, vm string) *Node {
	for _, n := range nodes {
		if _, ok := firstEvent(n, "start-refused", vm); ok {
			return n
		}
	}
	return nil
}

// TestFleet_PartitionSettle_APausedCopyReleasesTheImageLock is B4: after the
// heal, the minority destroys the copy its partition pause holds, on the
// certified claim alone, without waiting for the replacement to run, and the
// destination's retried start then succeeds. Exactly one copy runs at the end;
// two never run at once; the old host never runs it again.
//
// During the partition no copy runs: the paused one holds the image, so the
// replacement cannot start. That is the pause itself (partition-pause.md §3):
// the old host cannot learn of the claim until the heal.
//
// Mutation: require the destination to run the replacement before a paused
// copy settles (settleDecide's SelfPaused return) — the copy stays paused,
// nothing runs, and the wait for one running copy goes red.
func TestFleet_PartitionSettle_APausedCopyReleasesTheImageLock(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-nfs", owner.Name, "restart-any")
	if err := corrosion.GraduateVMOwnerEpoch(ctx, owner.DB, "pp-nfs"); err != nil {
		t.Fatalf("graduate pp-nfs: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	shareImage(c, "pp-nfs")
	runOwnerCopy(t, owner, "pp-nfs", "6f1c2a3e-0000-4000-8000-0000000000b4")
	genesisByTick(t, c, c.Nodes[2])
	enableRecoveryClaims(t, c)

	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{c.Nodes[2].Name: true}})
	rs := sampleRunning(t, c, "pp-nfs")
	minority, majority := c.Nodes[:2], c.Nodes[2:]
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	c.SplitGossip(minority, majority)

	// The majority decides and certifies the move, and its destination's
	// start is refused on the image the paused copy holds.
	var dest *Node
	eventually(t, ppRecoverBound, "the replacement's start to be refused on the image lock", func() bool {
		dest = lockRefused(majority, "pp-nfs")
		return dest != nil
	})
	if st, _ := owner.Virt.RawState("pp-nfs"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: %s's copy is %s, want paused", owner.Name, st)
	}
	// The destination keeps retrying the refused start: the proof stays in
	// flight and the row pending, never failed or parked in error.
	eventually(t, time.Minute, "the destination to retry the refused start", func() bool {
		return countEvents(dest, "start-refused", "pp-nfs") >= 3
	})
	rows, err := dest.DB.Query(ctx, `SELECT id, status FROM runtime_action_proofs
		WHERE target_name = 'pp-nfs' AND dest_host = ? AND claim_certificate != '' AND deleted_at IS NULL`, dest.Name)
	if err != nil || len(rows) == 0 {
		t.Fatalf("setup: no certified proof moves pp-nfs to %s (%v)", dest.Name, err)
	}
	for _, r := range rows {
		if st := r.String("status"); st != corrosion.ProofPrepared && st != corrosion.ProofInProgress {
			t.Fatalf("proof %s is %s after a refused start; an image lock is transient, the start must be retried", r.String("id"), st)
		}
	}
	if row := vmOn(t, dest, "pp-nfs"); row == nil || row.HostName != dest.Name || row.State == "error" {
		t.Fatalf("pp-nfs's row on %s is %+v; want it pending on %s, not in error", dest.Name, row, dest.Name)
	}
	// Zero copies run while the partition lasts: the paused one holds the
	// image, and its host cannot learn of the claim until the heal.
	if got := runningOn(c, "pp-nfs"); len(got) != 0 {
		t.Fatalf("pp-nfs runs on %v while the paused copy holds its image", got)
	}
	if row := vmOn(t, owner, "pp-nfs"); row == nil || row.HostName != owner.Name {
		t.Fatalf("setup: the claim reached %s before the heal (row %+v)", owner.Name, row)
	}

	rs.markNow()
	c.HealGossip()
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	eventually(t, 2*time.Minute, "pp-nfs to run on "+dest.Name+" after the heal", func() bool {
		got := runningOn(c, "pp-nfs")
		return len(got) == 1 && got[0] == dest.Name
	})
	if _, ok := firstEvent(owner, "destroy", "pp-nfs"); !ok {
		t.Fatalf("%s released pp-nfs's image without a destroy", owner.Name)
	}
	rs.mu.Lock()
	at, ran := rs.since[owner.Name]
	maxRun := rs.max
	rs.mu.Unlock()
	if ran {
		t.Fatalf("%s ran pp-nfs again at %s after the heal", owner.Name, at.Format("15:04:05.000"))
	}
	if maxRun > 1 {
		t.Fatalf("pp-nfs ran on more than one host at once")
	}
	eventually(t, 30*time.Second, "vm_settled and the partition.settle audit row on "+owner.Name, func() bool {
		cond, ok, err := corrosion.GetHealthCondition(ctx, owner.DB, corrosion.PartitionPauseEvaluator,
			corrosion.CondVMSettled, "vm", "pp-nfs@"+owner.Name)
		if err != nil || !ok || cond.ConfirmedAt == "" {
			return false
		}
		rows, err := owner.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'partition.settle' AND target = 'pp-nfs' AND host_name = ?`, owner.Name)
		return err == nil && len(rows) > 0
	})
}

// TestFleet_PartitionSettle_AnUncommittedMoveKeepsThePausedCopy is B4 where
// the recovery did NOT commit: no voter generation is adopted, so the
// majority's move carries no certificate. Settle acts on a certificate only
// (F9), so the paused copy is kept — not destroyed, not resumed — even though
// it holds the image the uncertified replacement needs. vm_settle_declined
// names the missing certificate; the operator decides.
//
// Mutation: let a paused copy settle on any live proof for the row's host,
// certified or not — the copy is destroyed and this goes red.
func TestFleet_PartitionSettle_AnUncommittedMoveKeepsThePausedCopy(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-nfs-u", owner.Name, "restart-any")
	if err := corrosion.GraduateVMOwnerEpoch(ctx, owner.DB, "pp-nfs-u"); err != nil {
		t.Fatalf("graduate pp-nfs-u: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	shareImage(c, "pp-nfs-u")
	runOwnerCopy(t, owner, "pp-nfs-u", "6f1c2a3e-0000-4000-8000-0000000000b5")
	// No genesis and no enableRecoveryClaims: the derived voter set.

	newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{c.Nodes[2].Name: true}})
	rs := sampleRunning(t, c, "pp-nfs-u")
	minority, majority := c.Nodes[:2], c.Nodes[2:]
	c.SplitGossip(minority, majority)

	var dest *Node
	eventually(t, ppRecoverBound, "the replacement's start to be refused on the image lock", func() bool {
		dest = lockRefused(majority, "pp-nfs-u")
		return dest != nil
	})
	rows, err := dest.DB.Query(ctx, `SELECT id FROM runtime_action_proofs
		WHERE target_name = 'pp-nfs-u' AND claim_certificate != ''`)
	if err != nil || len(rows) != 0 {
		t.Fatalf("setup: %d certified proofs for pp-nfs-u (%v); a derived voter set decides no claim", len(rows), err)
	}

	rs.markNow()
	c.HealGossip()
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	eventually(t, ppRecoverBound, "vm_settle_declined on "+owner.Name, func() bool {
		if _, ok := firstEvent(owner, "destroy", "pp-nfs-u"); ok {
			t.Fatalf("%s destroyed pp-nfs-u without a certificate", owner.Name)
		}
		cond, ok, err := corrosion.GetHealthCondition(ctx, owner.DB, corrosion.PartitionPauseEvaluator,
			corrosion.CondVMSettleDeclined, "vm", "pp-nfs-u@"+owner.Name)
		if err != nil || !ok || cond.Lifecycle != corrosion.ConditionConfirmed {
			return false
		}
		var ev struct {
			ReasonClass string `json:"reason_class"`
		}
		return json.Unmarshal([]byte(cond.Evidence), &ev) == nil &&
			(ev.ReasonClass == "no_certificate" || ev.ReasonClass == "proof_uncertified")
	})
	// Held over several more reconcile passes (300 ms each), not one instant.
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if st, _ := owner.Virt.RawState("pp-nfs-u"); st != libvirtfake.StatePaused {
			t.Fatalf("%s's copy is %s after the heal, want still paused: the move was never certified", owner.Name, st)
		}
		if _, ok := firstEvent(owner, "destroy", "pp-nfs-u"); ok {
			t.Fatalf("%s destroyed pp-nfs-u without a certificate", owner.Name)
		}
	}
	rs.mu.Lock()
	maxRun := rs.max
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-nfs-u ran on more than one host at once")
	}
}
