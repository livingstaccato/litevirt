package grpcapi

import (
	"encoding/json"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"reflect"
	"strings"
	"testing"
	"time"
)

func provenanceNICVM(t *testing.T, s *Server, name, model, stack string, mac string) {
	t.Helper()
	spec := &pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 512, Machine: "pc", Network: []*pb.NetworkAttachment{{Name: "lan", Model: model, Mac: mac}}}
	if err := corrosion.InsertVMWithHardware(adminCtx(), s.db, corrosion.VMRecord{Name: name, HostName: s.hostName, State: "stopped", StackName: stack, CPUActual: 1, MemActual: 512, Spec: seedSpecJSON(t, spec)}, []corrosion.InterfaceRecord{{VMName: name, NetworkName: "lan", MAC: mac}}, nil, []corrosion.NICRecord{{VMName: name, ID: corrosion.DeterministicNICID(name, mac), NetworkName: "lan", MAC: mac, Model: model}}, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileDomainDefinition(adminCtx(), mustGetVM(t, s, name), nil); err != nil {
		t.Fatal(err)
	}
}

func TestNICDetach_CompletionPersistsOriginalIncarnation(t *testing.T) {
	const mac = "52:54:00:aa:00:81"
	for _, failWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "bound_completion", true: "mandatory_facts_failure"}[failWrite], func(t *testing.T) {
			s := hotplugDiskServer(t)
			enableHardwareV2(t, s)
			ctx := adminCtx()
			provenanceNICVM(t, s, "bound", "e1000", "stack", mac)
			before := mustGetVM(t, s, "bound")
			if failWrite {
				if _, err := s.db.DB().Exec(`CREATE TRIGGER reject_nic_completion_facts BEFORE INSERT ON operation_steps WHEN NEW.step_name='completed' AND NEW.facts<>'' BEGIN SELECT RAISE(ABORT,'injected mandatory provenance failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "bound", NicMac: mac})
			if failWrite {
				if err == nil {
					t.Error("new detach reported success despite unavailable mandatory completion provenance")
				}
				after := mustGetVM(t, s, "bound")
				if after.ActiveOperationID == "" {
					t.Error("mandatory provenance failure cleared actual barrier")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			rows, err := s.db.Query(ctx, `SELECT s.facts,s.owner_epoch FROM operation_steps s JOIN operations o ON o.id=s.operation_id WHERE o.resource_id=? AND o.operation_kind=? AND s.step_name=?`, "bound", string(corrosion.OpDeviceDetach), corrosion.OpStepCompleted)
			if err != nil || len(rows) != 1 {
				t.Fatal(rows, err)
			}
			var facts struct {
				Version int    `json:"version"`
				Stamp   string `json:"vm_created_at"`
				MAC     string `json:"mac"`
				Epoch   int64  `json:"owner_epoch"`
			}
			if err := json.Unmarshal([]byte(rows[0].String("facts")), &facts); err != nil || facts.Version != 1 || facts.Stamp != before.CreatedAt || facts.MAC != mac || facts.Epoch != before.OwnerEpoch {
				t.Errorf("real completed detach lacks original bound provenance: facts=%q err=%v", rows[0].String("facts"), err)
			}
		})
	}
}

func TestNICModel_AmbiguousLegacyRefusesBeforeReplacingXML(t *testing.T) {
	const mac = "52:54:00:aa:00:82"
	for _, path := range []string{"UpdateVM", "reconcile"} {
		t.Run(path, func(t *testing.T) {
			s := hotplugDiskServer(t)
			enableHardwareV2(t, s)
			ctx := adminCtx()
			provenanceNICVM(t, s, "legacy-model", "e1000", "stack", mac)
			if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "legacy-model", NicMac: mac}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "legacy-model", Nic: &pb.NetworkAttachment{Name: "lan", Model: "virtio", Mac: mac}}); err != nil {
				t.Fatal(err)
			}
			// Retain the actual successful history, but reproduce pre-upgrade empty
			// facts; neither an immutable header nor its clock binds that incarnation.
			if _, err := s.db.DB().Exec(`UPDATE operation_steps SET facts='' WHERE operation_id IN (SELECT id FROM operations WHERE resource_id='legacy-model' AND operation_kind=?)`, string(corrosion.OpDeviceDetach)); err != nil {
				t.Fatal(err)
			}
			before, err := s.virt.DumpXMLInactive("legacy-model")
			if err != nil {
				t.Fatal(err)
			}
			if path == "UpdateVM" {
				_, err = s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "legacy-model", Machine: "q35"})
			} else {
				err = s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "legacy-model"), nil)
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "provenance") {
				t.Error("ambiguous legacy successful detach silently selected a driver", err)
			}
			after, derr := s.virt.DumpXMLInactive("legacy-model")
			if derr != nil || after != before {
				t.Error("ambiguous regeneration changed existing domain before refusal", derr)
			}
		})
	}
}

func TestRecoverNICDetach_UnboundOrRecreatedJournalHasNoEffects(t *testing.T) {
	for _, tc := range []string{"unstamped_original", "unstamped_recreated", "old_stamp_recreated"} {
		t.Run(tc, func(t *testing.T) {
			s, fake, ctx, mac := seedAttachedNIC(t)
			original := mustGetVM(t, s, "vm1")
			stamp := ""
			if tc == "old_stamp_recreated" {
				stamp = original.CreatedAt
			}
			opID, _, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach, detachNICRequestHash("vm1", mac), []string{corrosion.OpStepReserved}, map[string]string{"mac": mac, "nic_id": corrosion.DeterministicNICID("vm1", mac), "vm_created_at": stamp})
			if tc != "unstamped_original" {
				oldJournal, found, err := s.opJournal.Read(opID)
				if err != nil || !found {
					t.Fatal(err)
				}
				nics, err := corrosion.MergedVMNICs(ctx, s.db, "vm1")
				if err != nil {
					t.Fatal(err)
				}
				if err := corrosion.DeleteVM(ctx, s.db, "vm1"); err != nil {
					t.Fatal(err)
				}
				replacement := corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "running", Spec: original.Spec, CreatedAt: "2040-01-01T00:00:00.123456789Z"}
				if err := corrosion.InsertVMWithHardware(ctx, s.db, replacement, nil, nil, nics, nil, false); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.DB().Exec(`UPDATE vms SET created_at=? WHERE name=?`, replacement.CreatedAt, "vm1"); err != nil {
					t.Fatal(err)
				}
				beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach, detachNICRequestHash("vm1", mac), []string{corrosion.OpStepReserved}, oldJournal.Artifacts)
				if err := s.opJournal.Write(*oldJournal); err != nil {
					t.Fatal(err)
				}
				if mustGetVM(t, s, "vm1").CreatedAt == original.CreatedAt {
					t.Fatal("actual recreated row did not change incarnation")
				}
			}
			snapshot := func() []byte {
				var all []any
				for _, q := range []string{`SELECT * FROM vms WHERE name='vm1'`, `SELECT * FROM vm_nics WHERE vm_name='vm1'`, `SELECT * FROM operation_steps ORDER BY operation_id,owner_epoch,step_name`} {
					rows, err := s.db.Query(ctx, q)
					if err != nil {
						t.Fatal(err)
					}
					all = append(all, rows)
				}
				b, _ := json.Marshal(all)
				return b
			}
			before := snapshot()
			xml, _ := fake.DumpXML("vm1")
			inactive, _ := fake.DumpXMLInactive("vm1")
			calls := fake.UnplugRequests("vm1")
			journal, _, _ := s.opJournal.Read(opID)
			s.RecoverHardwareOperations(ctx)
			if fake.UnplugRequests("vm1") != calls {
				t.Error("unbound/old-incarnation journal performed an actual new unplug")
			}
			afterXML, _ := fake.DumpXML("vm1")
			afterInactive, _ := fake.DumpXMLInactive("vm1")
			if xml != afterXML || inactive != afterInactive {
				t.Error("unbound recovery changed current domain")
			}
			if string(before) != string(snapshot()) {
				t.Error("unbound recovery mutated rows/completion/barrier")
			}
			afterJournal, found, err := s.opJournal.Read(opID)
			if err != nil || !found || !reflect.DeepEqual(journal, afterJournal) {
				t.Error("unbound recovery consumed/rewrote original journal", err)
			}
		})
	}
}

func TestNICSwap_BoundEvidenceSurvivesOwnerChangeAndReaping(t *testing.T) {
	for _, stack := range []string{"", "stack"} {
		for _, from := range []string{"virtio", "e1000"} {
			t.Run(stack+"/"+from, func(t *testing.T) {
				s := hotplugDiskServer(t)
				enableHardwareV2(t, s)
				ctx := adminCtx()
				const name = "retained"
				const mac = "52:54:00:aa:00:93"
				to := "virtio"
				if from == to {
					to = "e1000"
				}
				provenanceNICVM(t, s, name, from, stack, mac)
				before := mustGetVM(t, s, name)
				if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: name, NicMac: mac}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: name, Nic: &pb.NetworkAttachment{Name: "lan", Model: to, Mac: mac}}); err != nil {
					t.Fatal(err)
				}
				check := func(label string) {
					t.Helper()
					x, err := s.virt.DumpXMLInactive(name)
					if err != nil || nicModelsByMAC(t, x)[mac] != to {
						t.Fatalf("%s: model not retained: %s %v", label, x, err)
					}
				}
				check("immediate attach")
				if stack != "" && mustGetVM(t, s, name).Spec != before.Spec {
					t.Fatal("stack spec changed during swap")
				}
				if _, err := s.db.DB().Exec(`UPDATE vms SET vm_owner_epoch=vm_owner_epoch+3 WHERE name=?`, name); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.DB().Exec(`UPDATE operation_steps SET updated_at='2020-01-01T00:00:00Z' WHERE operation_id IN (SELECT id FROM operations WHERE resource_id=?)`, name); err != nil {
					t.Fatal(err)
				}
				n, failed, err := corrosion.ReapTerminalOperations(ctx, s.db, time.Hour)
				if err != nil || len(failed) != 0 || n != 2 {
					t.Fatalf("actual reaper n=%d failures=%v err=%v", n, failed, err)
				}
				if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: name, Machine: "q35"}); err != nil {
					t.Fatal(err)
				}
				check("later update")
				if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, name), nil); err != nil {
					t.Fatal(err)
				}
				check("later reconcile")
			})
		}
	}
}

func TestRecoverNICDetach_BoundCompletionRequiresFacts(t *testing.T) {
	s, fake, ctx, mac := seedAttachedNIC(t)
	before := mustGetVM(t, s, "vm1")
	opID, _ := wedgeNICDetach(t, ctx, s, mac)
	if _, err := s.db.DB().Exec(`CREATE TRIGGER reject_recovery_facts BEFORE INSERT ON operation_steps WHEN NEW.step_name='completed' AND NEW.facts<>'' BEGIN SELECT RAISE(ABORT,'injected recovery provenance failure'); END`); err != nil {
		t.Fatal(err)
	}
	s.RecoverHardwareOperations(ctx)
	assertNICGone(t, fake, mac)
	if mustGetVM(t, s, "vm1").ActiveOperationID != opID {
		t.Fatal("facts failure released actual barrier")
	}
	if _, found, err := s.opJournal.Read(opID); err != nil || !found {
		t.Fatal("facts failure consumed journal", err)
	}
	if _, err := s.db.DB().Exec(`DROP TRIGGER reject_recovery_facts`); err != nil {
		t.Fatal(err)
	}
	s.RecoverHardwareOperations(ctx)
	if mustGetVM(t, s, "vm1").ActiveOperationID != "" {
		t.Fatal("bound retry did not complete")
	}
	if _, found, err := s.opJournal.Read(opID); err != nil || found {
		t.Fatal("bound retry retained journal", err)
	}
	rows, err := s.db.Query(ctx, `SELECT facts FROM operation_steps WHERE operation_id=? AND step_name='completed'`, opID)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	var facts map[string]any
	if err := json.Unmarshal([]byte(rows[0].String("facts")), &facts); err != nil || facts["vm_created_at"] != before.CreatedAt || facts["mac"] != mac {
		t.Fatal("recovery lacks original completed facts", facts, err)
	}
}
