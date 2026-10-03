// Fleet scenario: a host removed for good with workloads still recorded on it
// is not given back to a new machine until those workloads have moved.
//
// On the kvm003 lab (drill 6, main-b3368d7c) node-5 was removed with
// `lv host rm --dead` while vm/s5 and vm/o4 were still recorded on it, and
// added back as a rebuilt machine two minutes later. The re-admission gave the
// name a live hosts row again, which ended both recovery paths at once: the
// coordinator's removed-host pass selects workloads on names with no live row,
// and the voters refuse a supersede for a host that has one
// (RemovedHostEvidence). Then the new machine's reconciler found s5 "marked
// running but not in libvirt", recreated its root overlay from the backing
// image and started it, with no claim and no proof. Container blct on node-4
// became a ghost row: `lv ct start` failed with "No container config
// specified".
//
// The rows belong to the machine that was removed, not to the one that takes
// its name. They are recovered by the normal claim path, which needs the name
// to stay removed, so AdmitHost refuses the name while any of them remain.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_ReaddWaitsForTheRemovedHostsWorkloads: d dies with vm-old on it, is
// confirmed off and removed for good. `lv host add` of its name is refused
// while vm-old is still recorded on d, naming it; the claim path then recovers
// vm-old onto a survivor with one owner, and the add goes through.
//
// Mutation: drop the refusal in AdmitHost — the admission is accepted while
// vm-old is still recorded on d, and the removed-host pass never moves it.
func TestFleet_ReaddWaitsForTheRemovedHostsWorkloads(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2606})
	a, b, e, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	insertVM(t, a, "vm-old", d.Name)
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)

	// d dies, is confirmed off and removed for good.
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

	// The machine is rebuilt and `lv host add` admits it before vm-old has
	// moved: refused, and the name stays removed.
	admit := func() error {
		_, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
			Name: d.Name, Address: d.Address, CertSerial: "0a0b0c0d0e0f",
		})
		return err
	}
	err := admit()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "vm/vm-old") {
		t.Fatalf("admitting %s while vm-old is still recorded on it: %v, want FailedPrecondition naming vm/vm-old", d.Name, err)
	}
	if h, _ := corrosion.GetHost(ctx, a.DB, d.Name); h != nil {
		t.Fatalf("the refused admission left %s a live row: %+v", d.Name, h)
	}

	// The removed-host pass recovers vm-old by claim, as for any host removed
	// for good, once the CRL has reached the voters.
	syncCRL(t, survivors...)
	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.Tick(ctx, a)
	pr, cert := pendingCert(t, a, "vm-old")
	if pr.DestHost == d.Name || cert.SourceHost != d.Name {
		t.Fatalf("vm-old's recovery: dest %s, source %s", pr.DestHost, cert.SourceHost)
	}
	dest := c.Node(pr.DestHost)
	c.WaitConverged(t, convergeTimeout, survivors...)
	claimReconciler(t, dest).ReconcileOnce(ctx)
	c.WaitConverged(t, convergeTimeout, survivors...)
	if vm := vmOn(t, a, "vm-old"); vm.HostName == d.Name {
		t.Fatalf("vm-old is still recorded on %s after its recovery: %+v", d.Name, vm)
	}
	owners := 0
	for _, n := range survivors {
		if st, _ := n.Virt.DomainState("vm-old"); st == string(libvirtfake.StateRunning) {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners of vm-old after its recovery, want 1", owners)
	}

	// Nothing of the old machine's is left on the name: the add goes through.
	if err := admit(); err != nil {
		t.Fatalf("admit %s once its workloads have moved: %v", d.Name, err)
	}
}
