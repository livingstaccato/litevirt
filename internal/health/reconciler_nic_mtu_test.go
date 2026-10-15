package health

import (
	"context"
	"errors"
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

// A bridge whose MTU cannot be read when the reconciler defines the VM here
// (a bridge being recreated) is a transient start failure, retried on a later
// pass; a bridge whose MTU differs is the operator's to fix, and is not.
//
// Mutation: return retryable=false for every NIC MTU render failure — the
// unreadable case goes red.
func TestDomainXMLFor_UnreadableBridgeIsRetryable(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, fake, _ := sharedDiskReconciler(t, db)
	vm := corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running", CPUActual: 1, MemActual: 512}
	if err := corrosion.InsertVM(ctx, db, vm,
		[]corrosion.InterfaceRecord{{VMName: "vm1", NetworkName: "br0", MAC: "52:54:00:aa:bb:cc"}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	spec := &pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "br0", Mac: "52:54:00:aa:bb:cc", Mtu: 9000}}}

	fake.FailBridgeMTU("br0", errors.New("no such network interface"))
	if _, retryable, failure := r.domainXMLFor(ctx, vm, spec, nil); !retryable || !strings.Contains(failure, "read the MTU of bridge br0") {
		t.Errorf("unreadable bridge: retryable=%v failure=%q, want a retryable failure naming the bridge", retryable, failure)
	}

	fake.FailBridgeMTU("br0", nil)
	fake.SetBridgeMTU("br0", 1500)
	if _, retryable, failure := r.domainXMLFor(ctx, vm, spec, nil); retryable || !strings.Contains(failure, "does not match bridge br0") {
		t.Errorf("mismatched bridge: retryable=%v failure=%q, want a non-retryable mismatch", retryable, failure)
	}
}
