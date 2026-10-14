package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// startingVM is "hb" in starting on test-host (1536 MiB allocatable), its
// row's actuals 1 vCPU / 1024 MiB — counted against the host
// (corrosion.SumVMResourcesByHost) — and its domain defined, shut off.
func startingVM(t *testing.T, s *Server) *libvirtfake.Fake {
	t.Helper()
	fake := libvirtfake.New()
	s.virt = fake
	admissionHost(t, s)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "hb", HostName: "test-host", State: "starting", CPUActual: 1, MemActual: 1024,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "hb", Cpu: 1, MemoryMib: 1024}),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>hb</name><memory unit='KiB'>1048576</memory><vcpu>1</vcpu></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("hb", libvirtfake.StateDefined)
	return fake
}

// Re-review 2 I-1: a repair of a VM in starting that grows it (`lv update
// --restart-if-needed`) is admitted for what it adds to the row's actuals,
// which host usage already counts. Past the host's capacity it is refused;
// --allow-overcommit needs vm.overcommit, and is audited.
//
// Mutation: a starting VM skips admission outright (as round 2 did) — the
// grow is made with no admission, no permission and no audit row: red.
func TestUpdateVM_GrowingAStartingVMIsAdmitted(t *testing.T) {
	s := serverWithEngine(t)
	startingVM(t, s)
	grow := func(ctx context.Context, overcommit bool) error {
		_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hb", MemoryMib: 4096, AllowRestart: proto.Bool(true), AllowOvercommit: overcommit})
		return err
	}
	if err := grow(adminCtx(), false); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("growing a starting VM past the host = %v, want ResourceExhausted", err)
	}

	// A principal who may update and start VMs but not overcommit.
	if err := corrosion.InsertRole(context.Background(), s.db, corrosion.RoleRecord{
		Name: "Resizer", Verbs: []string{"vm.read", "vm.update", "vm.start", "vm.restart"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{Path: "/", Role: "Resizer", Principal: "user:bob@local", Propagate: true}); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if err := grow(userCtx("bob", "viewer"), true); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("--allow-overcommit without vm.overcommit = %v, want PermissionDenied", err)
	}

	if err := grow(adminCtx(), true); err != nil {
		t.Fatalf("--allow-overcommit by an admin: %v", err)
	}
	rows, err := s.db.Query(context.Background(), `SELECT detail FROM audit_log WHERE target = 'hb' AND detail LIKE '%admission bypassed%'`)
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "mem=3072MiB") {
		t.Fatalf("audit rows %v (%v), want one bypass row for the 3072 MiB grow", rows, err)
	}
}

// Re-review 2 m-1: a VM in starting is counted against its host, so a
// restart of a stuck start adds nothing and is admitted on a host with no
// room for a second copy of it (countedAgainstHost).
//
// Mutation: RestartVM admits everything not running — ResourceExhausted: red.
func TestRestartVM_AStuckStartIsAdmittedOnANearFullHost(t *testing.T) {
	s := reconfigServer(t)
	startingVM(t, s)
	if _, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "hb"}); status.Code(err) == codes.ResourceExhausted {
		t.Fatalf("restart of a VM in starting, already counted on its host = %v", err)
	}
}

// Re-review 3 I-1: a start, restart or zero-growth repair of a VM in starting
// adds no capacity, but it still makes the VM resident, so it passes the
// host-safety gate: an active ownership condition on the VM, or an incomplete
// local inventory, refuses it before anything is started.
//
// Mutation: the zero-delta `return nil, nil` in startGatesLocked, or the
// RestartVM skip of admission for a counted VM — the start goes ahead: red.
func TestStartingVM_OperatorStartsRunTheHostSafetyGate(t *testing.T) {
	ops := []struct {
		name string
		call func(s *Server) error
	}{
		{"StartVM", func(s *Server) error {
			_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "hb"})
			return err
		}},
		{"RestartVM", func(s *Server) error {
			_, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "hb"})
			return err
		}},
		{"UpdateVM repair", func(s *Server) error {
			_, err := s.UpdateVM(adminCtx(), &pb.UpdateVMRequest{Name: "hb", MemoryMib: 1024, AllowRestart: proto.Bool(true)})
			return err
		}},
	}
	type condition struct {
		name, want string
		seed       func(t *testing.T, s *Server, fake *libvirtfake.Fake)
	}
	var conditions []condition
	for _, code := range []string{"vm_dual_run", "runtime_owner_mismatch", "owner_epoch_mismatch"} {
		conditions = append(conditions, condition{code, "ownership condition", func(t *testing.T, s *Server, _ *libvirtfake.Fake) {
			seedOwnershipCondition(t, s, code, "vm", "hb", "h-a", "h-b")
		}})
	}
	conditions = append(conditions, condition{"incomplete inventory", "inventory is incomplete", func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
		fake.FailListDomains = func() error { return errors.New("libvirtd unreachable") }
		s.invalidateInventoryCache()
	}})
	for _, c := range conditions {
		for _, op := range ops {
			t.Run(c.name+"/"+op.name, func(t *testing.T) {
				s := serverWithEngine(t)
				fake := startingVM(t, s)
				c.seed(t, s, fake)
				err := op.call(s)
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("%s of a VM in starting with %s = %v, want FailedPrecondition naming %q", op.name, c.name, err, c.want)
				}
				if st, _ := fake.RawState("hb"); st == libvirtfake.StateRunning {
					t.Fatalf("refused %s still started the domain", op.name)
				}
			})
		}
	}
}

// Re-review 3 nit: a same-host promote takeover of a VM in starting admits a
// zero delta (countedAgainstHost) but still runs the residency safety gate.
//
// Mutation: skip the takeover's admission when its delta is zero — the
// promotion goes ahead under an active ownership condition: red.
func TestPromoteReplica_SameHostTakeoverOfAStartingVMRunsTheSafetyGate(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	poolDir := seedPromotableVM(t, s, s.hostName, "", "", 1, 1024)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'starting' WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	seedOwnershipCondition(t, s, "vm_dual_run", "vm", "vm1", "h-a", "h-b")
	err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "ownership condition") {
		t.Fatalf("same-host promote of a VM in starting under an active vm_dual_run = %v, want FailedPrecondition", err)
	}
	assertNoPromotedArtifacts(t, s, poolDir, "vm1")
}
