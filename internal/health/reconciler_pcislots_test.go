package health

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestReconciler_StartPendingVM_SparePCIeRootPortsReachTheDefinedDomain is the
// Reconciler-side analogue of the Server's CreateVM test: the reconciler
// builds its own lv.VMConfig independently (startPendingVM, not
// baseDomainConfig), so its own SetSparePCIeRootPorts wiring needs its own
// proof — deleting the r.ensureSparePCIeRootPorts(vm.Name) top-up after its
// define would pass every other reconciler test.
func TestReconciler_StartPendingVM_SparePCIeRootPortsReachTheDefinedDomain(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetSparePCIeRootPorts(5)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", vm, err)
	}
	r.startPendingVM(ctx, *vm)

	domXML, err := fake.DumpXMLInactive("vm1")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	if n := strings.Count(domXML, `model="pcie-root-port"`); n != 5 {
		t.Fatalf("defined domain has %d pcie-root-port controllers, want 5 (configured via SetSparePCIeRootPorts):\n%s", n, domXML)
	}
}
