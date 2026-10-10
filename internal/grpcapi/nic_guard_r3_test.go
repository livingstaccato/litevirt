package grpcapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

func networkDef(t *testing.T, s *Server, name string) compose.NetworkDef {
	t.Helper()
	def, err := lookupNetworkDef(context.Background(), s.db, name)
	if err != nil || def == nil {
		t.Fatalf("network %s: %v", name, err)
	}
	return *def
}

// TestRecordExistingTrunkVLANs (re-review R2-I1): the trunks a cluster had
// when it upgraded keep their VLANs: each one's VLANs are recorded into its
// network's allowed list. A trunk this release created (it has a guard
// record) is not added: its VLANs need an operator. Recording again until the
// release latches is TestRecordExistingTrunkVLANs_UntilTheRelease.
func TestRecordExistingTrunkVLANs(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore","AllowedVLANs":[50]}`}); err != nil {
		t.Fatal(err)
	}
	trunkVM := func(name, mac string, vids string, guarded bool) {
		t.Helper()
		spec := `{"name":"` + name + `","uuid":"u-` + name + `","network":[{"name":"core","trunk":[` + vids + `]}]}`
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, HostName: s.hostName, State: "running", Spec: spec},
			[]corrosion.InterfaceRecord{{VMName: name, NetworkName: "core", MAC: mac}}, nil); err != nil {
			t.Fatal(err)
		}
		if guarded {
			if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: name, MAC: mac, Mode: corrosion.NICGuardOn,
				VMUUID: "u-" + name, Network: "core"}, "t"); err != nil {
				t.Fatal(err)
			}
		}
	}
	trunkVM("old-router", "52:54:00:00:00:01", "100,101", false)
	trunkVM("new-tenant", "52:54:00:00:00:02", "300", true)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatalf("recordExistingTrunkVLANs: %v", err)
	}
	if got := networkDef(t, s, "core").AllowedVLANs; !reflect.DeepEqual(got, []int{50, 100, 101}) {
		t.Errorf("allowed VLANs = %v, want the existing trunk's added: [50 100 101]", got)
	}
	trunkVM("later", "52:54:00:00:00:03", "200,201", true)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	if got := networkDef(t, s, "core").AllowedVLANs; !reflect.DeepEqual(got, []int{50, 100, 101}) {
		t.Errorf("allowed VLANs = %v after a second pass; a trunk created on this release is not recorded", got)
	}
}

// TestSetNetworkGuardConfig (re-review R2-I1, m4): a network's gateway,
// reserved addresses and allowed trunk VLANs are set after create with
// network.update on the network, audited; a project's network admin may set
// its own network's and not a shared one's.
func TestSetNetworkGuardConfig(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	for _, n := range []corrosion.NetworkRecord{
		{Name: "lan", Type: "bridge", Config: `{"Type":"bridge","Interface":"brlan","Subnet":"10.7.0.0/24"}`},
		{Name: "teamnet", Type: "bridge", Config: `{"Type":"bridge","Interface":"brteam","Subnet":"10.8.0.0/24"}`, Project: "team"},
	} {
		if err := corrosion.UpsertNetwork(ctx, s.db, n); err != nil {
			t.Fatal(err)
		}
	}
	bob := sgBindUser(t, s, "bob", "team")
	req := func(name string) *pb.SetNetworkGuardConfigRequest {
		return &pb.SetNetworkGuardConfigRequest{Name: name, SetGateway: true, Gateway: "10.8.0.254",
			SetReservedAddresses: true, ReservedAddresses: []string{"10.8.0.253"},
			SetAllowedVlans: true, AllowedVlans: []int32{101, 100}}
	}
	if _, err := s.SetNetworkGuardConfig(bob, req("lan")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a project's network admin on a shared network: %v, want PermissionDenied", err)
	}
	if _, err := s.SetNetworkGuardConfig(bob, req("teamnet")); err != nil {
		t.Fatalf("on its own network: %v", err)
	}
	def := networkDef(t, s, "teamnet")
	if def.Gateway != "10.8.0.254" || !reflect.DeepEqual(def.ReservedAddresses, []string{"10.8.0.253"}) ||
		!reflect.DeepEqual(def.AllowedVLANs, []int{100, 101}) || def.Subnet != "10.8.0.0/24" {
		t.Errorf("config = %+v", def)
	}
	bad := req("teamnet")
	bad.AllowedVlans = []int32{4095}
	if _, err := s.SetNetworkGuardConfig(bob, bad); status.Code(err) != codes.InvalidArgument {
		t.Errorf("VLAN 4095: %v, want InvalidArgument", err)
	}
	rows, err := s.db.Query(ctx, `SELECT COUNT(*) AS n FROM audit_log WHERE action = 'network.update' AND target = 'teamnet'`)
	if err != nil || rows[0].Int("n") == 0 {
		t.Errorf("the change was not audited: %v %v", rows, err)
	}
}

// TestRecordFirewallState_BlockedTrunkVLANs (re-review R2-I1): a trunk whose
// VLANs its network does not allow raises a condition naming the command that
// allows them.
func TestRecordFirewallState_BlockedTrunkVLANs(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore","AllowedVLANs":[100]}`}); err != nil {
		t.Fatal(err)
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce,
		BlockedTrunks: []firewall.BlockedTrunk{{Workload: "tenant", Network: "core", VIDs: []int{102}}}})
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallTrunkVLANs, "host", s.hostName)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("no condition raised: %+v %v %v", row, ok, err)
	}
	if !strings.Contains(row.Evidence, "lv network set core --allowed-vlans 100,102") {
		t.Errorf("the condition does not name the command: %q", row.Evidence)
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce})
	if row, _, _ := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallTrunkVLANs, "host", s.hostName); row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("the condition outlived the blocked trunk: %+v", row)
	}
}

// TestVMGuarded_OnlyThisIncarnationsLiveRecords (re-review m1): a record an
// earlier VM under the same name left — another incarnation's, or one
// tombstoned at its delete — guards nothing.
func TestVMGuarded_OnlyThisIncarnationsLiveRecords(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "stopped",
		Spec: `{"name":"web","uuid":"u-2"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:00:00:01",
		Mode: corrosion.NICGuardOn, VMUUID: "u-1"}, "t"); err != nil {
		t.Fatal(err)
	}
	if g, err := s.vmGuarded(ctx, "web"); err != nil || g {
		t.Errorf("an earlier incarnation's record guards the VM: %v, %v", g, err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:00:00:02",
		Mode: corrosion.NICGuardOn, VMUUID: "u-2"}, "t"); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.vmGuarded(ctx, "web"); !g {
		t.Error("this incarnation's record does not guard it")
	}
	if err := corrosion.DeleteNICGuardsOf(ctx, s.db, "web", "test"); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.vmGuarded(ctx, "web"); g {
		t.Error("a record deleted with its VM still guards a VM of that name")
	}
	all, _ := corrosion.ListNICGuards(ctx, s.db)
	if len(all) != 0 {
		t.Errorf("deleted records are listed: %v", all)
	}
}

// inForceArmer is a fakeArmer that also says whether a VM's guards are in
// force.
type inForceArmer struct {
	fakeArmer
	inForce bool
}

func (a *inForceArmer) GuardsInForce(string, []string) bool { return a.inForce }

// TestArmNICsFor_RefusesOnlyWhatIsNotInForce (re-review m3): a failed pass
// refuses a guarded start only when the VM's guards are not in force; an
// unrelated failure (an inet apply, a loader hiccup) with the guards in force
// does not refuse every start on the host.
func TestArmNICsFor_RefusesOnlyWhatIsNotInForce(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "guarded", MAC: "52:54:00:00:00:01", Mode: corrosion.NICGuardOn}, "t"); err != nil {
		t.Fatal(err)
	}
	a := &inForceArmer{fakeArmer: fakeArmer{err: errors.New("inet apply failed")}, inForce: true}
	s.SetFirewallReconciler(a)
	if err := s.ArmNICsFor(ctx, "guarded"); err != nil {
		t.Errorf("guards in force, an unrelated failure: %v", err)
	}
	a.err, a.inForce = nil, false
	if err := s.ArmNICsFor(ctx, "guarded"); err == nil {
		t.Error("a pass that reported success but left the guards out of force cleared the start")
	}
}

// TestGuardHostLabel (re-review m8): until every host
// runs a build that knows NIC guards, a guarded VM is not placed on a host
// that does not advertise them: there it would run unguarded while `nic-guard
// ls` says on.
func TestGuardHostLabel(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "running",
		Spec: `{"name":"web","uuid":"u-1"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:00:00:01",
		Mode: corrosion.NICGuardOn, VMUUID: "u-1"}, "t"); err != nil {
		t.Fatal(err)
	}
	need, err := s.guardHostNeeded(ctx, "web")
	if err != nil || !need {
		t.Errorf("a guarded VM before the release latch: need %v, %v", need, err)
	}
	if err := s.refuseUnguardedTarget(ctx, "web", corrosion.HostRecord{Name: "old", Labels: map[string]string{}}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a guarded VM to a host that does not advertise guards: %v, want FailedPrecondition", err)
	}
	if err := s.refuseUnguardedTarget(ctx, "web", corrosion.HostRecord{Name: "new", Version: "v2",
		Labels: map[string]string{corrosion.LabelNICGuards: "v2"}}); err != nil {
		t.Errorf("to a host that does: %v", err)
	}
	if need, _ := s.guardHostNeeded(ctx, "plain"); need {
		t.Error("an unguarded VM needs no such host")
	}
}

// TestStartContainer_ArmsItsNICsFirst (re-review m10): a container's NIC
// firewall is put in force before it starts, and a guarded container whose
// guards are not in force is not started.
func TestStartContainer_ArmsItsNICsFirst(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "ct1", Template: "download", Distro: "alpine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: corrosion.ContainerGuardOwner("host-a", "ct1"),
		MAC: "52:00:00:00:00:10", Mode: corrosion.NICGuardOn}, "t"); err != nil {
		t.Fatal(err)
	}
	a := &inForceArmer{inForce: false}
	s.SetFirewallReconciler(a)
	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "ct1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a guarded container whose guards are not in force: %v, want FailedPrecondition", err)
	}
	if len(rt.startCalls) != 0 {
		t.Fatalf("the runtime started it anyway: %v", rt.startCalls)
	}
	a.inForce = true
	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "ct1"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(a.armed) == 0 || len(rt.startCalls) != 1 {
		t.Errorf("armed %v, started %v", a.armed, rt.startCalls)
	}
}

// TestSetFirewallReconciler_NoRace (re-review R2-I2): the daemon wires the
// reconciler while the runtime loops may already run starts through it; run
// under -race.
func TestSetFirewallReconciler_NoRace(t *testing.T) {
	s := guardServer(t, true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			s.SetFirewallReconciler(&fakeReconciler{})
		}
	}()
	for i := 0; i < 200; i++ {
		_ = s.ArmNICsFor(context.Background(), "vm")
		s.reconcileLocal(context.Background())
	}
	<-done
}
