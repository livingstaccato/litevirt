// Fleet scenarios for the follow-ups to colonelpanik/litevirt#258's shared
// disk rule: what happens to a promoted VM after its promotion.
package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Review R4-I2: a partial promotion, then the promoted VM's next start built
// from its disk rows. Failover promotes set4 on the replica host without its
// shared (NFS) data1, its old owner fenced by a fence that proves nothing, and
// data1's row still names that owner. The replica host then reboots, and
// onboot rebuilds set4's domain from every live row — which attached data1
// unjudged: two writers, if the old owner's qemu still ran. It is left out
// now, set4 still starts, and `lv inspect` says why and what to do. Once the
// old owner is confirmed off, `lv restart` attaches it.
//
// Mutation "attach every row" (JudgeSharedDiskRows withholds nothing) — red.
// Mutation "no re-judge at start" (rejudgeSharedDisksForStart does nothing) —
// red at the restart.
func TestFleet_PartialPromotionThenOnbootLeavesTheSharedDiskOut(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	victim, replicaHost, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	sched := replicaSetVM(t, c, victim, replicaHost, "set4")
	nfs := filepath.Join(c.tmpRoot, "nfs")
	if err := os.MkdirAll(nfs, 0o755); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(nfs, "set4-data1.qcow2")
	if err := os.Rename(filepath.Join(c.tmpRoot, victim.Name, "set4-data1.qcow2"), shared); err != nil {
		t.Fatal(err)
	}
	if err := victim.DB.Execute(ctx, `UPDATE vm_disks SET path = ?, storage_type = 'nfs', storage_volume = 'nfs'
		WHERE vm_name = 'set4' AND disk_name = 'data1'`, shared); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "set4", Cpu: 1, MemoryMib: 256, Onboot: true})
	if err := victim.DB.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'set4'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	if err := victim.Server.RunReplication(ctx, sched, time.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("replicate set4: %v", err)
	}

	failVictim(t, coord, victim, replicaHost, coord)
	if xml := replicaHost.Virt.DefinedXML("set4"); xml == "" || strings.Contains(xml, shared) {
		t.Fatalf("want set4 promoted on %s without data1; domain:\n%s", replicaHost.Name, xml)
	}

	// The replica host reboots: the domain is down, and set4 is onboot.
	if err := replicaHost.Virt.DestroyDomain("set4"); err != nil {
		t.Fatal(err)
	}
	rec := health.NewReconciler(replicaHost.Name, t.TempDir(), replicaHost.DB, replicaHost.Virt)
	rec.SetSharedDiskWithheldReporter(replicaHost.Server.ReportSharedDiskWithheld, replicaHost.Server.ClearSharedDiskWithheld)
	rec.StartOnbootVMs(ctx)
	if st, _ := replicaHost.Virt.DomainState("set4"); st != "running" {
		t.Fatalf("onboot did not start set4 (state %q)", st)
	}
	if xml := replicaHost.Virt.DefinedXML("set4"); strings.Contains(xml, shared) {
		t.Fatalf("onboot attached data1 while %s is not proven off:\n%s", victim.Name, xml)
	}
	rows, _ := corrosion.GetVMDisks(ctx, replicaHost.DB, "set4")
	for _, r := range rows {
		if r.DiskName == "data1" && (r.HostName != victim.Name || r.Path != shared) {
			t.Errorf("data1 row = %+v, want it untouched", r)
		}
	}
	insp, err := c.SelfClient(coord).InspectVM(ctx, &pb.InspectVMRequest{Name: "set4"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"data1", victim.Name + " is fenced, but not proven powered off",
		"`lv host fence-confirm " + victim.Name + "`", "then `lv restart set4`"} {
		if !strings.Contains(insp.GetSharedDiskWithheld(), want) {
			t.Errorf("inspect shared_disk_withheld = %q, want %q", insp.GetSharedDiskWithheld(), want)
		}
	}

	// The remedy: the old owner confirmed off, then a restart. The fence
	// failover recorded is moved a minute back first: fencing_log stamps to
	// the second, and a confirmation in the same second ties with it, which
	// the weaker row wins.
	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx, `UPDATE fencing_log SET timestamp = ? WHERE host_name = ?`,
			time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), victim.Name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.SelfClient(coord).FenceHost(ctx, &pb.FenceHostRequest{Name: victim.Name, Confirmed: true, ConfirmManualOnly: true}); err != nil {
		t.Fatalf("fence-confirm %s: %v", victim.Name, err)
	}
	if _, err := c.SelfClient(coord).RestartVM(ctx, &pb.RestartVMRequest{Name: "set4"}); err != nil {
		t.Fatalf("restart set4: %v", err)
	}
	if xml := replicaHost.Virt.DefinedXML("set4"); !strings.Contains(xml, shared) {
		t.Fatalf("the restart after the confirmation did not attach data1:\n%s", xml)
	}
	if st, _ := replicaHost.Virt.DomainState("set4"); st != "running" {
		t.Errorf("set4 after the restart = %q, want running", st)
	}
	insp, err = c.SelfClient(coord).InspectVM(ctx, &pb.InspectVMRequest{Name: "set4"})
	if err != nil || insp.GetSharedDiskWithheld() != "" {
		t.Errorf("inspect shared_disk_withheld = %q (%v) after the attaching restart, want cleared", insp.GetSharedDiskWithheld(), err)
	}
}

// pbf1Fleet is db on victim with a replica of every disk on both a and b, its
// schedule auto-promoting to b. With claims: voters {a, b, victim}, recovery
// claims enforced everywhere. The victim is then killed and replication
// between a and b blocked — the window before either side's commit arrives —
// while claim RPCs still reach their peer.
func pbf1Fleet(t *testing.T, clock *VirtualClock, withClaims bool) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	setup := func(c *Cluster, a, b, victim *Node) {
		ctx := context.Background()
		sched := replicaSetVM(t, c, victim, a, "db")
		if err := victim.Server.RunReplication(ctx, sched, time.Now().Add(-10*time.Minute)); err != nil {
			t.Fatalf("replicate db to %s: %v", a.Name, err)
		}
		dr := filepath.Join(c.tmpRoot, b.Name, "data", "dr")
		if err := os.MkdirAll(dr, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertStoragePool(ctx, b.DB, corrosion.StoragePoolRecord{
			HostName: b.Name, Name: "dr", Driver: "local", Target: dr, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		sched.TargetHost = b.Name
		if err := corrosion.UpsertBackupSchedule(ctx, victim.DB, sched); err != nil {
			t.Fatal(err)
		}
		if err := victim.Server.RunReplication(ctx, sched, time.Now().Add(-5*time.Minute)); err != nil {
			t.Fatalf("replicate db to %s: %v", b.Name, err)
		}
	}
	if withClaims {
		c, a, b, victim = claimFleetWith(t, clock, 3258, setup)
	} else {
		c = New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 3258})
		a, b, victim = c.Nodes[0], c.Nodes[1], c.Nodes[2]
		setup(c, a, b, victim)
		c.WaitConverged(t, convergeTimeout)
		c.Kill(victim)
		PublishHealth(t, a, victim.Name, 5, clock.Now())
		PublishHealth(t, b, victim.Name, 5, clock.Now())
		c.WaitConverged(t, convergeTimeout, a, b)
	}
	c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
	return c, a, b, victim
}

// runs reports whether n runs db.
func runs(n *Node) bool {
	st, err := n.Virt.DomainState("db")
	return err == nil && st == "running"
}

// Review PB-F1: an operator's promotion and failover's recovery of the same VM
// never both start it. The operator promotes db on a (its replica there,
// --force) while b's coordinator recovers it by auto-promoting on b (its
// replica there) — different replica hosts, inside the window before either
// commit replicates, the case nothing serialized. With recovery claims the
// two are one decision: whichever claims first starts the VM, and the other
// is refused (the operator's promotion, naming the decision to wait for) or
// stands down (the coordinator, which learns the operator's decision).
//
// The claims-off arm is the witness: there both start db, which is what the
// issue reported and what keeps the enforced arms from passing vacuously.
//
// Mutation "no operator claim" (claimOperatorPromote not called) — red on
// both enforced arms (two owners).
func TestFleet_OperatorPromoteAndCoordinatorRecoveryNeverBothStartTheVM(t *testing.T) {
	if testing.Short() {
		t.Skip("fleet")
	}
	for _, tc := range []struct {
		name           string
		claims         bool
		operatorFirst  bool
		wantA, wantB   bool
		operatorRefuse string
	}{
		{"claims, coordinator first", true, false, false, true, "has decided its recovery"},
		{"claims, operator first", true, true, true, false, ""},
		{"no claims, operator first (witness: two owners)", false, true, true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			c, a, b, _ := pbf1Fleet(t, clock, tc.claims)
			cs := c.NewCoordinators(clock)
			cs.ByNode[b.Name].Promoter = b.Server
			operator := func() error {
				st, err := c.SelfClient(a).PromoteReplica(ctx, &pb.PromoteReplicaRequest{
					VmName: "db", TargetHost: a.Name, TargetPool: "dr", Force: true, NoLocalize: true})
				if err != nil {
					return err
				}
				for {
					if _, err := st.Recv(); err != nil {
						if err == io.EOF {
							return nil
						}
						return err
					}
				}
			}

			var opErr error
			if tc.operatorFirst {
				opErr = operator()
				cs.Tick(ctx, b)
			} else {
				cs.Tick(ctx, b)
				opErr = operator()
			}

			if tc.operatorRefuse != "" {
				if opErr == nil || !strings.Contains(opErr.Error(), tc.operatorRefuse) {
					t.Errorf("operator promotion = %v, want it refused (%q)", opErr, tc.operatorRefuse)
				}
			} else if opErr != nil {
				t.Errorf("operator promotion: %v", opErr)
			}
			if got := runs(a); got != tc.wantA {
				t.Errorf("db running on %s (the operator's promotion) = %v, want %v", a.Name, got, tc.wantA)
			}
			if got := runs(b); got != tc.wantB {
				t.Errorf("db running on %s (the coordinator's promotion) = %v, want %v", b.Name, got, tc.wantB)
			}
			if tc.claims && runs(a) && runs(b) {
				t.Fatal("two hosts run db: the operator's promotion and the coordinator's recovery both started it")
			}
		})
	}
}

// Review I2: an operator's promotion whose claim was decided but which failed
// before the VM started no longer holds the VM's recovery forever. It
// releases its claim on the way out; b's coordinator, which learns the
// operator's decision, asks a to abandon it, a signs (its start fence was
// never recorded), and the coordinator recovers db at the next attempt.
// Neither host runs db at the end.
//
// Mutation "no release and no coordinator path" (releaseOperatorClaim and the
// supersedeEvidence operator branch removed) — red: the coordinator stands
// down and db is never recovered.
func TestFleet_AFailedOperatorPromotionLetsTheCoordinatorRecoverTheVM(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, _ := pbf1Fleet(t, clock, true)
	cs := c.NewCoordinators(clock)
	cs.ByNode[b.Name].Promoter = b.Server

	a.Virt.FailStartDomain = func(string) error { return io.ErrUnexpectedEOF }
	st, err := c.SelfClient(a).PromoteReplica(ctx, &pb.PromoteReplicaRequest{
		VmName: "db", TargetHost: a.Name, TargetPool: "dr", Force: true, NoLocalize: true})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if err == nil || err == io.EOF {
		t.Fatal("the operator's promotion succeeded with StartDomain failing on a")
	}
	a.Virt.FailStartDomain = nil

	cs.Tick(ctx, b)

	vm, err := corrosion.GetVM(ctx, b.DB, "db")
	if err != nil || vm == nil {
		t.Fatalf("GetVM on %s: %v", b.Name, err)
	}
	rows, err := b.DB.Query(ctx, `SELECT id, action, dest_host, claim_certificate FROM runtime_action_proofs
		WHERE target_name = 'db' AND coordinator = ? AND deleted_at IS NULL`, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	recovered := false
	for _, r := range rows {
		if r.String("claim_certificate") != "" {
			recovered = true
		}
	}
	if !recovered && !runs(b) {
		t.Fatalf("b's coordinator did not recover db after a's failed promotion (row %+v, proofs %d)", vm, len(rows))
	}
	if runs(a) && runs(b) {
		t.Fatal("two hosts run db")
	}
	if runs(a) {
		t.Error("a runs db, whose promotion failed")
	}
}

// Review I-1, end to end: the operator's promotion on a fails at StartDomain
// while a's libvirt connection is down (every read fails too), so qemu may be
// running there. a keeps its start fence and refuses the coordinator's
// abandonment request, so b's coordinator does not recover db elsewhere: the
// VM waits for an operator, and never runs twice.
//
// Mutation "unfence on any read error" — red: b recovers db.
func TestFleet_AnAmbiguousOperatorStartFailureIsNeverRecoveredElsewhere(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, _ := pbf1Fleet(t, clock, true)
	cs := c.NewCoordinators(clock)
	cs.ByNode[b.Name].Promoter = b.Server

	a.Virt.FailStartDomain = func(string) error { return io.ErrUnexpectedEOF }
	a.Virt.FailDomainState = func(string) error { return io.ErrUnexpectedEOF }
	st, err := c.SelfClient(a).PromoteReplica(ctx, &pb.PromoteReplicaRequest{
		VmName: "db", TargetHost: a.Name, TargetPool: "dr", Force: true, NoLocalize: true})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if err == nil || err == io.EOF {
		t.Fatal("the operator's promotion succeeded with StartDomain failing on a")
	}

	cs.Tick(ctx, b)

	rows, err := b.DB.Query(ctx, `SELECT id FROM runtime_action_proofs
		WHERE target_name = 'db' AND coordinator = ? AND claim_certificate != '' AND deleted_at IS NULL`, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || runs(b) {
		t.Fatalf("b recovered db past an operator start on a that may be running (%d certified proofs, runs=%v)", len(rows), runs(b))
	}
}
