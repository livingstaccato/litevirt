package grpcapi

import (
	"errors"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestRegenerate_FailedDetachKeepsSurvivingNICModel(t *testing.T) {
	const mac = "52:54:00:aa:00:77"
	for _, path := range []string{"UpdateVM", "reconcile"} {
		t.Run(path, func(t *testing.T) {
			s := hotplugDiskServer(t)
			enableHardwareV2(t, s)
			ctx := adminCtx()
			spec := &pb.VMSpec{Name: "failed-detach", Cpu: 1, MemoryMib: 512, Machine: "pc", Network: []*pb.NetworkAttachment{{Name: "lan", Model: "e1000", Mac: mac}}}
			vm := corrosion.VMRecord{Name: spec.Name, HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 512, Spec: seedSpecJSON(t, spec)}
			if err := corrosion.InsertVMWithHardware(ctx, s.db, vm, []corrosion.InterfaceRecord{{VMName: vm.Name, NetworkName: "lan", MAC: mac}}, nil, []corrosion.NICRecord{{VMName: vm.Name, ID: corrosion.DeterministicNICID(vm.Name, mac), NetworkName: "lan", MAC: mac, Model: "virtio"}}, nil, false); err != nil {
				t.Fatal(err)
			}
			if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, vm.Name), nil); err != nil {
				t.Fatal(err)
			}
			before, err := s.virt.DumpXMLInactive(vm.Name)
			if err != nil {
				t.Fatal(err)
			}
			if nicModelsByMAC(t, before)[mac] != "e1000" {
				t.Fatal("fixture did not preserve legacy spec model before detach")
			}
			writes := 0
			s.opJournal.FailWrite = func(string) error { writes++; return errors.New("injected journal write failure before unplug") }
			_, err = s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: vm.Name, NicMac: mac})
			s.opJournal.FailWrite = nil
			if status.Code(err) != codes.Unavailable || writes != 1 {
				t.Fatalf("expected actual pre-effect journal failure: writes=%d err=%v", writes, err)
			}
			headers, err := s.db.Query(ctx, `SELECT id FROM operations WHERE resource_id = ? AND operation_kind = ?`, vm.Name, string(corrosion.OpDeviceDetach))
			if err != nil || len(headers) != 1 {
				t.Fatalf("retained failed header: %v %v", headers, err)
			}
			steps, err := s.db.Query(ctx, `SELECT step_name FROM operation_steps WHERE operation_id = ? AND step_name = ?`, headers[0].String("id"), corrosion.OpStepFailed)
			if err != nil || len(steps) != 1 {
				t.Fatalf("failed terminal step: %v %v", steps, err)
			}
			if mustGetVM(t, s, vm.Name).ActiveOperationID != "" {
				t.Fatal("failed detach retained barrier")
			}
			nics, err := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
			if err != nil || len(nics) != 1 || nics[0].MAC != mac {
				t.Fatalf("failed detach changed surviving NIC: %v %v", nics, err)
			}
			if path == "UpdateVM" {
				_, err = s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: vm.Name, Machine: "q35"})
			} else {
				_ = s.virt.UndefineDomain(vm.Name, false)
				err = s.reconcileDomainDefinition(ctx, mustGetVM(t, s, vm.Name), nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := s.virt.DumpXMLInactive(vm.Name)
			if err != nil {
				t.Fatal(err)
			}
			if got := nicModelsByMAC(t, after)[mac]; got != "e1000" {
				t.Fatalf("failed-before-effect detach changed surviving NIC model to %q; want e1000", got)
			}
		})
	}
}
