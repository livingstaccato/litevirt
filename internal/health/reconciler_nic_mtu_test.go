package health

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A VM the reconciler defines on this host (a failover start, an autostart)
// renders its NIC MTU against THIS host's bridge: `bridge` takes the bridge's
// MTU here, and an explicit MTU this host's bridge does not equal fails the
// start, naming the bridge and the host, rather than defining a guest whose
// frames the bridge drops.
//
// Mutation: drop the reader from domainXMLFor (read the test host's real
// interfaces) — both cases go red.
func TestDomainXMLFor_NICMTUAgainstThisHostsBridge(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, fake, _ := sharedDiskReconciler(t, db)
	fake.SetBridgeMTU("br0", 9000)
	vm := corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running", CPUActual: 1, MemActual: 512}
	if err := corrosion.InsertVM(ctx, db, vm,
		[]corrosion.InterfaceRecord{{VMName: "vm1", NetworkName: "br0", MAC: "52:54:00:aa:bb:cc"}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	render := func(mtu int32) (string, string) {
		spec := &pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512,
			Network: []*pb.NetworkAttachment{{Name: "br0", Mac: "52:54:00:aa:bb:cc", Mtu: mtu}}}
		x, _, failure := r.domainXMLFor(ctx, vm, spec, nil)
		return x, failure
	}
	if x, failure := render(1); failure != "" || !strings.Contains(x, `<mtu size="9000">`) {
		t.Errorf("bridge NIC on a 9000 bridge: failure=%q\n%s", failure, x)
	}
	if _, failure := render(1500); !strings.Contains(failure, "NIC 0 MTU 1500 does not match bridge br0 MTU 9000 on host node-a") {
		t.Errorf("explicit 1500 on a 9000 bridge: failure = %q", failure)
	}
}
