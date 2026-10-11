// Fleet scenarios for the follow-ups to colonelpanik/litevirt#258's shared
// disk rule: what happens to a promoted VM after its promotion.
package fleet

import (
	"context"
	"encoding/json"
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
