package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A restart-same VM held on its host for its host-local disk does not block
// adding that machine back after `lv host rm --dead`: main admitted it (the
// claim path had moved the VM, onto a blank disk), and the hold's own exit is
// the machine coming back. The VM stays recorded on it, the hold stays open
// and says what happens next, and the machine starts the VM once it is back
// and active.
//
// Mutation: drop the vm_failover_held exclusion from
// WorkloadsBlockingReadmission — the admission is refused naming vm/rs-held.
func TestFleet_ReaddBringsBackAHeldRestartSameVM(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2914})
	a, b, e, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	disks := []corrosion.DiskRecord{{
		VMName: "rs-held", DiskName: "root", HostName: d.Name, Path: "/var/lib/litevirt/disks/rs-held-root.qcow2",
		StorageType: "local",
	}}
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "rs-held", HostName: d.Name, State: "running", Spec: `{"on_host_failure":"restart-same"}`,
	}, nil, disks); err != nil {
		t.Fatal(err)
	}
	// What the coordinator's hold records (restart_same.go).
	if _, err := health.RecordHeldForHost(ctx, a.DB, a.Name, "rs-held", d.Name, disks, time.Now()); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)

	c.Kill(d)
	if err := corrosion.InsertFenceLog(ctx, a.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	withOperatorPKI(t, a)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	survivors := []*Node{a, b, e}
	adoptAll(t, c, 2, survivors...)
	c.WaitConverged(t, convergeTimeout, survivors...)

	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: "0a0b0c0d0e0f",
	}); err != nil {
		t.Fatalf("admitting %s back with only a held restart-same VM recorded on it: %v", d.Name, err)
	}
	if vm := vmOn(t, a, "rs-held"); vm == nil || vm.HostName != d.Name || vm.State != "running" {
		t.Fatalf("rs-held after %s was admitted again = %+v, want it still recorded running on %s", d.Name, vm, d.Name)
	}
	held, err := health.HeldForHostOf(ctx, a.DB, "rs-held")
	if err != nil || held == nil || held.Host != d.Name || !strings.Contains(held.Fix, "lv host undrain "+d.Name) {
		t.Fatalf("hold after the re-add = %+v (err %v), want it open, naming %s and how it becomes active", held, err, d.Name)
	}
}
