package grpcapi

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// r5Trunk is what the loader renders for one NIC: its trunk VLANs, whether
// every tagged frame is dropped, and the VLANs reported blocked.
type r5Trunk struct {
	VIDs    []int
	Denied  bool
	Blocked []int
}

// r5Load runs the real plan loader for this host, with taps as the running
// domains' NICs (vm → mac → tap), and returns each tap's trunk.
func r5Load(t *testing.T, s *Server, taps map[string]map[string]string) (map[string]r5Trunk, firewall.Plan) {
	t.Helper()
	plan, err := firewall.CorrosionPlanLoader(s.db, s.hostName, firewall.Plan{}, firewall.LoaderOptions{
		RunningTaps: func() (map[string]map[string]string, error) { return taps, nil },
	})(context.Background())
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	blocked := map[string][]int{}
	for _, b := range plan.BlockedTrunks {
		blocked[b.Workload] = append(blocked[b.Workload], b.VIDs...)
	}
	out := map[string]r5Trunk{}
	for _, n := range plan.NICs {
		vids := append([]int(nil), n.TrunkVIDs...)
		sort.Ints(vids)
		b := blocked[n.VMName]
		sort.Ints(b)
		out[n.NICDev] = r5Trunk{VIDs: vids, Denied: n.TrunkDenied, Blocked: b}
	}
	return out, plan
}

// r5TrunkVM writes a running VM on this host with one trunk NIC on network,
// guarded (a NIC this release created) or not (one that predates guards).
func r5TrunkVM(t *testing.T, s *Server, name, stack, network, mac, vids string, guarded bool) {
	t.Helper()
	ctx := context.Background()
	spec := `{"name":"` + name + `","uuid":"u-` + name + `","stack_name":"` + stack + `","network":[{"name":"` + network + `","trunk":[` + vids + `]}]}`
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, HostName: s.hostName, State: "running", Spec: spec, StackName: stack},
		[]corrosion.InterfaceRecord{{VMName: name, NetworkName: network, MAC: mac}}, nil); err != nil {
		t.Fatal(err)
	}
	if guarded {
		if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: name, MAC: mac, Mode: corrosion.NICGuardOn,
			VMUUID: "u-" + name, Network: network}, "t"); err != nil {
			t.Fatal(err)
		}
	}
}

func r5Latch(s *Server) {
	s.SetGate(fakeServerGate{durablyLatchedTok: map[string]bool{capabilities.FirewallIPv6V1: true}})
}

func r5AuditCount(t *testing.T, s *Server, target, user string) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM audit_log WHERE action = 'network.update' AND target = ? AND username = ? AND result = 'ok'`, target, user)
	if err != nil {
		t.Fatal(err)
	}
	return rows[0].Int("n")
}

// TestFlatBridge_AllowedVLANsLever (re-review R4-I1): a new trunk on a flat
// bridge (a network name with no network row) carries no VLAN of its own;
// `lv network set <bridge> --allowed-vlans` allows them, with network.update
// at the cluster root (a flat bridge has no project), audited. The loader
// carries the VLANs recorded at upgrade plus that list, and the condition
// names a command that works.
func TestFlatBridge_AllowedVLANsLever(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	const mac = "52:54:00:00:05:01"
	r5TrunkVM(t, s, "router2", "", "wan", mac, "100,200", true)
	if err := corrosion.SetClusterPolicy(ctx, s.db, corrosion.TrunkVLANsRecordedKey, `{}`, "t"); err != nil {
		t.Fatal(err) // the upgrade recording has run
	}
	taps := map[string]map[string]string{"router2": {mac: "vnet1"}}

	got, plan := r5Load(t, s, taps)
	if want := (r5Trunk{Denied: true, Blocked: []int{100, 200}}); !reflect.DeepEqual(got["vnet1"], want) {
		t.Fatalf("a new flat-bridge trunk before any allowance: %+v, want %+v", got["vnet1"], want)
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce, BlockedTrunks: plan.BlockedTrunks})
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallTrunkVLANs, "host", s.hostName)
	if err != nil || !ok || !strings.Contains(row.Evidence, "lv network set wan --allowed-vlans 100,200") {
		t.Fatalf("the condition does not name the flat bridge's command: %q (%v %v)", row.Evidence, ok, err)
	}
	if !strings.Contains(row.Evidence, "cluster root") {
		t.Errorf("the condition does not say a flat bridge needs network.update at the cluster root: %q", row.Evidence)
	}

	bob := sgBindUser(t, s, "bob", "team")
	set := func(c context.Context, vids ...int32) error {
		_, err := s.SetNetworkGuardConfig(c, &pb.SetNetworkGuardConfigRequest{Name: "wan", SetAllowedVlans: true, AllowedVlans: vids})
		return err
	}
	if err := set(bob, 100); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a project's network admin on a flat bridge: %v, want PermissionDenied", err)
	}
	admin := adminCtxWithEngine(t, s)
	if _, err := s.SetNetworkGuardConfig(admin, &pb.SetNetworkGuardConfigRequest{Name: "wan", SetGateway: true, Gateway: "10.0.0.1"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a gateway on a flat bridge: %v, want InvalidArgument", err)
	}
	if err := set(admin, 100); err != nil {
		t.Fatalf("the cluster root on a flat bridge: %v", err)
	}
	if n := r5AuditCount(t, s, "wan", "alice"); n == 0 {
		t.Error("the flat bridge's allowed VLANs were set without an audit row")
	}
	got, plan = r5Load(t, s, taps)
	if want := (r5Trunk{VIDs: []int{100}, Blocked: []int{200}}); !reflect.DeepEqual(got["vnet1"], want) {
		t.Errorf("after `lv network set wan --allowed-vlans 100`: %+v, want %+v", got["vnet1"], want)
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce, BlockedTrunks: plan.BlockedTrunks})
	row, _, _ = corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallTrunkVLANs, "host", s.hostName)
	if !strings.Contains(row.Evidence, "lv network set wan --allowed-vlans 100,200") {
		t.Errorf("the condition's command drops the VLAN already allowed: %q", row.Evidence)
	}
	if err := set(admin); err != nil {
		t.Fatalf("clearing the list: %v", err)
	}
	if got, _ := r5Load(t, s, taps); !got["vnet1"].Denied {
		t.Errorf("after clearing the list: %+v, want every VLAN dropped", got["vnet1"])
	}
}

// TestRecordExistingTrunkVLANs_FlatBridgeIntoTheLoader (re-review R4-I1, the
// concern-6 gap): a trunk that predates guards on a flat bridge is recorded
// through the no-row path and keeps exactly its VLANs in the loader once the
// release has latched; a new trunk on it gets only those.
func TestRecordExistingTrunkVLANs_FlatBridgeIntoTheLoader(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	r5TrunkVM(t, s, "old", "", "rawbr", "52:54:00:00:05:02", "7,8,9", false)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	r5Latch(s)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	r5TrunkVM(t, s, "new", "", "rawbr", "52:54:00:00:05:03", "9,10", true)
	got, _ := r5Load(t, s, map[string]map[string]string{
		"old": {"52:54:00:00:05:02": "vnet2"}, "new": {"52:54:00:00:05:03": "vnet3"}})
	if want := (r5Trunk{VIDs: []int{7, 8, 9}}); !reflect.DeepEqual(got["vnet2"], want) {
		t.Errorf("the flat-bridge trunk that predates guards: %+v, want %+v", got["vnet2"], want)
	}
	if want := (r5Trunk{VIDs: []int{9}, Blocked: []int{10}}); !reflect.DeepEqual(got["vnet3"], want) {
		t.Errorf("a new trunk on that bridge: %+v, want %+v", got["vnet3"], want)
	}
}

// r5Prov provisions every network as one bridge.
type r5Prov struct{ bridgeRemovalProv }

func (p *r5Prov) Provision(context.Context, *corrosion.Client, string, compose.NetworkDef, string, string) (string, error) {
	return "brup", nil
}

// TestRetarget_CarriesTheFlatBridgesRecordedVLANs (re-review R4-I2, scenario
// A): a stack deployed before undeclared networks resolved has a trunk on the
// flat "<stack>_<name>". Its VLANs were recorded under that flat name. A
// re-deploy after the release latched moves the NIC onto the cluster network
// "<name>"; the VLANs go with it, audited, and nothing is blocked.
func TestRetarget_CarriesTheFlatBridgesRecordedVLANs(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.SetNetworkProvisioner(&r5Prov{})
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "uplink", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brup"}`}); err != nil {
		t.Fatal(err)
	}
	const mac = "52:54:00:00:05:04"
	r5TrunkVM(t, s, "edge", "prod", "prod_uplink", mac, "10,20", false)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	r5Latch(s)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.retargetVMNICs(ctx, "edge", []compose.NICRetarget{{Ordinal: 0, From: "prod_uplink", To: "uplink"}}); err != nil {
		t.Fatalf("retarget: %v", err)
	}
	got, _ := r5Load(t, s, map[string]map[string]string{"edge": {mac: "vnet4"}})
	if want := (r5Trunk{VIDs: []int{10, 20}}); !reflect.DeepEqual(got["vnet4"], want) {
		t.Errorf("the moved trunk: %+v, want %+v (it carried these on main)", got["vnet4"], want)
	}
	if r5AuditCount(t, s, "uplink", "litevirt") == 0 {
		t.Error("the carried VLANs were added to uplink without an audit row")
	}
}

// TestNetworkCreatedOverAFlatBridge_KeepsItsVLANs (re-review R4-I2, scenario
// B): a network row created under a flat bridge's name takes the VLANs
// recorded for the bridge and the ones allowed on it, audited; a re-deploy of
// the row, which writes its definition verbatim, keeps them.
func TestNetworkCreatedOverAFlatBridge_KeepsItsVLANs(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.SetNetworkProvisioner(&r5Prov{})
	const mac = "52:54:00:00:05:05"
	r5TrunkVM(t, s, "old", "", "wan", mac, "10,20", false)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	r5Latch(s)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	admin := adminCtxWithEngine(t, s)
	if _, err := s.SetNetworkGuardConfig(admin, &pb.SetNetworkGuardConfigRequest{Name: "wan", SetAllowedVlans: true, AllowedVlans: []int32{30}}); err != nil {
		t.Fatalf("allow VLAN 30 on the flat bridge: %v", err)
	}
	for i := 0; i < 2; i++ { // create, then re-deploy the same definition
		if _, err := s.provisionAndPersistNetwork(ctx, "wan", "", "", compose.NetworkDef{Type: "bridge", Interface: "wan"}); err != nil {
			t.Fatalf("persist %d: %v", i, err)
		}
		if got := networkDef(t, s, "wan").AllowedVLANs; !reflect.DeepEqual(got, []int{10, 20, 30}) {
			t.Errorf("pass %d: wan's allowed VLANs = %v, want [10 20 30]", i, got)
		}
		got, _ := r5Load(t, s, map[string]map[string]string{"old": {mac: "vnet5"}})
		if want := (r5Trunk{VIDs: []int{10, 20}}); !reflect.DeepEqual(got["vnet5"], want) {
			t.Errorf("pass %d: the trunk that predates guards: %+v, want %+v", i, got["vnet5"], want)
		}
	}
	if r5AuditCount(t, s, "wan", "litevirt") == 0 {
		t.Error("the carried VLANs were added to wan without an audit row")
	}
}

// TestRecordExistingTrunkVLANs_ReAddsAVLANLostToAConcurrentWrite (re-review
// m6): a write to the network row that did not see the recording and won
// under LWW loses the recorded VLAN; the next pass puts it back. An
// operator's removal with `lv network set` stays removed.
func TestRecordExistingTrunkVLANs_ReAddsAVLANLostToAConcurrentWrite(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore"}`}); err != nil {
		t.Fatal(err)
	}
	r5TrunkVM(t, s, "router", "", "core", "52:54:00:00:05:06", "100,101", false)
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	// Another host's write, made from a copy without the recording, wins.
	nr, _ := corrosion.GetNetwork(ctx, s.db, "core")
	nr.Config = `{"Type":"bridge","Interface":"brcore","Gateway":"10.0.0.1"}`
	if err := corrosion.UpsertNetwork(ctx, s.db, *nr); err != nil {
		t.Fatal(err)
	}
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	if def := networkDef(t, s, "core"); !reflect.DeepEqual(def.AllowedVLANs, []int{100, 101}) || def.Gateway != "10.0.0.1" {
		t.Fatalf("after a lost write: allowed %v gateway %q, want [100 101] and the other write's gateway", def.AllowedVLANs, def.Gateway)
	}
	admin := adminCtxWithEngine(t, s)
	if _, err := s.SetNetworkGuardConfig(admin, &pb.SetNetworkGuardConfigRequest{Name: "core", SetAllowedVlans: true, AllowedVlans: []int32{100}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	if got := networkDef(t, s, "core").AllowedVLANs; !reflect.DeepEqual(got, []int{100}) {
		t.Errorf("an operator's removal was undone: %v, want [100]", got)
	}
	// A pass that wrote is not the last one: the next confirms it.
	r5Latch(s)
	nr, _ = corrosion.GetNetwork(ctx, s.db, "core")
	nr.Config = `{"Type":"bridge","Interface":"brcore"}`
	if err := corrosion.UpsertNetwork(ctx, s.db, *nr); err != nil {
		t.Fatal(err)
	}
	if done, err := s.recordExistingTrunkVLANs(ctx); err != nil || done {
		t.Errorf("a pass that wrote reported done=%v (%v); the next must confirm what it wrote", done, err)
	}
	if done, err := s.recordExistingTrunkVLANs(ctx); err != nil || !done {
		t.Errorf("a pass with the release latched that wrote nothing: done=%v (%v)", done, err)
	}
}

// TestRecordExistingTrunkVLANs_ReadModifyWriteUnderCAS (re-review m6): a
// write to the network row between the recording's read and its write is
// not overwritten: the recording's write is refused and redone over it.
func TestRecordExistingTrunkVLANs_ReadModifyWriteUnderCAS(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore"}`}); err != nil {
		t.Fatal(err)
	}
	r5TrunkVM(t, s, "router", "", "core", "52:54:00:00:05:07", "100,101", false)
	once := false
	defer SetTrunkVLANWriteHookForTests(func() {
		if once {
			return
		}
		once = true
		nr, _ := corrosion.GetNetwork(ctx, s.db, "core")
		nr.Config = `{"Type":"bridge","Interface":"brcore","Gateway":"10.9.9.9"}`
		if err := corrosion.UpsertNetwork(ctx, s.db, *nr); err != nil {
			t.Error(err)
		}
	})()
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	if def := networkDef(t, s, "core"); def.Gateway != "10.9.9.9" || !reflect.DeepEqual(def.AllowedVLANs, []int{100, 101}) {
		t.Errorf("gateway %q allowed %v: the write between read and write was lost, or the VLANs were", def.Gateway, def.AllowedVLANs)
	}
}

// r5BreakGuardReads makes every read of owner's guard records fail, as an
// unreadable row would, and nothing else; the returned func restores the
// table.
func r5BreakGuardReads(t *testing.T, s *Server, owner string) func() {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`ALTER TABLE cluster_policies RENAME TO cluster_policies_r5`,
		`CREATE VIEW cluster_policies AS SELECT key,
		   CASE WHEN key LIKE 'nic_guard/` + owner + `/%' THEN json_extract('not json', '$') ELSE value END AS value,
		   set_by, updated_at, deleted_at FROM cluster_policies_r5`,
	} {
		if _, err := s.db.DB().ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return func() {
		for _, q := range []string{`DROP VIEW cluster_policies`, `ALTER TABLE cluster_policies_r5 RENAME TO cluster_policies`} {
			if _, err := s.db.DB().ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}
}

// TestGuardReadError_RefusesOnlyWhatMayBeGuarded (re-review m1): a VM whose
// own guard records cannot be read is not started or moved; a VM with none
// starts as on main, its own rows readable.
func TestGuardReadError_RefusesOnlyWhatMayBeGuarded(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.SetFirewallReconciler(&fakeArmer{})
	s.virt = libvirtfake.New()
	for _, vm := range []string{"plain", "broken"} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: vm, HostName: s.hostName, State: "stopped",
			Spec: `{"name":"` + vm + `","uuid":"u-` + vm + `"}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "broken", MAC: "52:54:00:00:05:08",
		Mode: corrosion.NICGuardOn, VMUUID: "u-broken"}, "t"); err != nil {
		t.Fatal(err)
	}
	defer r5BreakGuardReads(t, s, "broken")()

	if err := s.ArmNICsFor(ctx, "plain"); err != nil {
		t.Errorf("an unguarded VM's start was refused for another VM's unreadable guard: %v", err)
	}
	if s.needsPausedStart(ctx, "plain", false) {
		t.Error("an unguarded VM was started paused for another VM's unreadable guard")
	}
	if err := s.refuseUnguardedTarget(ctx, "plain", corrosion.HostRecord{Name: "old"}); err != nil {
		t.Errorf("an unguarded VM's move was refused: %v", err)
	}
	if err := s.ArmNICsFor(ctx, "broken"); err == nil {
		t.Error("a VM whose own guard cannot be read was cleared to run")
	}
}

// TestArmNICFirewall_ResumeFallbackLeavesAPartitionPausedGuest (re-review
// m2): the source's resume of a guest this host does not hold never resumes
// one partition pause holds.
func TestArmNICFirewall_ResumeFallbackLeavesAPartitionPausedGuest(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.dataDir = t.TempDir()
	virt := libvirtfake.New()
	s.virt = virt
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "running",
		Spec: `{"name":"vm1","uuid":"u-vm1"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	virt.SetState("vm1", libvirtfake.StatePaused)
	if err := health.WritePauseRecordForTests(s.dataDir, health.PauseRecord{Kind: health.PauseKindVM, Name: "vm1",
		Host: s.hostName, Reason: "partition"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.ArmNICFirewall(peerCtxFor(t, s, "src"), &pb.ArmNICFirewallRequest{VmName: "vm1", Resume: true})
	if st, _ := virt.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Errorf("a partition-paused guest was resumed by the fallback: %s (err %v)", st, err)
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition naming the partition pause", err)
	}
}

const (
	r5UUID  = "5113ced7-9006-4086-b7dd-9d1840181e03"
	r5Other = "6224dfe8-9006-4086-b7dd-9d1840181e04"
)

// r5HeldVM writes a VM owned by host whose domain is paused here, and a held
// record for it.
func r5HeldVM(t *testing.T, s *Server, virt *libvirtfake.Fake, name, host, domainUUID string) {
	t.Helper()
	r5HeldVMIn(t, s, virt, name, host, "running", domainUUID)
}

func r5HeldVMIn(t *testing.T, s *Server, virt *libvirtfake.Fake, name, host, state, domainUUID string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: name, HostName: host, State: state,
		Spec: `{"name":"` + name + `","uuid":"` + r5UUID + `"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	virt.SetInactiveXML(name, `<domain type='kvm'><name>`+name+`</name><uuid>`+domainUUID+`</uuid></domain>`)
	virt.SetState(name, libvirtfake.StatePaused)
	if err := s.holdForHandOver(context.Background(), name, "src"); err != nil {
		t.Fatal(err)
	}
}

func r5Held(s *Server, vm string) bool {
	for _, g := range s.HeldGuestsForTests() {
		if g == vm {
			return true
		}
	}
	return false
}

// TestHeldRecord_BoundToTheMove (re-review m3): a held record is the move's,
// not the name's: a start of the VM here, or a move here that is not handed
// over paused, ends it, and it resumes only a domain of the incarnation it
// was written for. A guest later paused for another reason stays paused.
func TestHeldRecord_BoundToTheMove(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.dataDir = t.TempDir()
	virt := libvirtfake.New()
	s.virt = virt

	r5HeldVM(t, s, virt, "started", s.hostName, r5UUID)
	if _, err := s.NICStartGuard(ctx).Before("started"); err != nil {
		t.Fatal(err)
	}
	if r5Held(s, "started") {
		t.Error("a start of the VM here left the move's held record")
	}
	virt.SetState("started", libvirtfake.StatePaused) // an I/O error, later
	s.ResumeHeldGuestsOnce(ctx)
	if st, _ := virt.RawState("started"); st != libvirtfake.StatePaused {
		t.Errorf("a guest paused for another reason was resumed through a stale record: %s", st)
	}

	r5HeldVM(t, s, virt, "moved", s.hostName, r5UUID)
	if _, err := s.ArmNICFirewall(peerCtxFor(t, s, "src2"), &pb.ArmNICFirewallRequest{VmName: "moved"}); err != nil {
		t.Fatal(err)
	}
	if r5Held(s, "moved") {
		t.Error("a later move here, not handed over paused, left the earlier move's record")
	}

	r5HeldVM(t, s, virt, "other", s.hostName, r5Other)
	s.ResumeHeldGuestsOnce(ctx)
	if st, _ := virt.RawState("other"); st != libvirtfake.StatePaused {
		t.Errorf("a domain of another incarnation was resumed: %s", st)
	}
	if row, ok, _ := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallHeld, "host", s.hostName); !ok ||
		row.Lifecycle == corrosion.ConditionResolved || !strings.Contains(row.Evidence, "other") {
		t.Errorf("a paused guest its record will not resume is not reported: %+v", row)
	}
}

// TestHeldAfterAFailedCommit_IsReportedAndKept (re-review m4): a guest that
// arrived here paused while its move's ownership commit failed (the row still
// names the source, `migrating`) is held: once the source says so, the
// condition names it and the command, and its record is kept. A move still
// under way is not reported. Nor does an unreadable VM row clear the
// condition.
func TestHeldAfterAFailedCommit_IsReportedAndKept(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.dataDir = t.TempDir()
	virt := libvirtfake.New()
	s.virt = virt
	r5HeldVMIn(t, s, virt, "web", "src", "migrating", r5UUID)
	s.ResumeHeldGuestsOnce(ctx)
	if row, ok, _ := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallHeld, "host", s.hostName); ok && row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("a move still under way was reported held: %q", row.Evidence)
	}
	if _, err := s.ArmNICFirewall(peerCtxFor(t, s, "src"), &pb.ArmNICFirewallRequest{VmName: "web", HandoverUncommitted: true}); err != nil {
		t.Fatal(err)
	}
	cond := func() corrosion.HealthCondition {
		t.Helper()
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallHeld, "host", s.hostName)
		if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
			t.Fatalf("no %s condition while web is held: %+v %v %v", CondFirewallHeld, row, ok, err)
		}
		return row
	}
	s.ResumeHeldGuestsOnce(ctx)
	if ev := cond().Evidence; !strings.Contains(ev, "web") || !strings.Contains(ev, "lv doctor repair-owner web "+s.hostName) {
		t.Errorf("the condition does not name the guest and the repair: %q", ev)
	}
	if !r5Held(s, "web") {
		t.Error("the record of a guest still held was dropped")
	}
	if st, _ := virt.RawState("web"); st != libvirtfake.StatePaused {
		t.Errorf("a guest whose ownership is not recorded here was resumed: %s", st)
	}
	if _, err := s.db.DB().ExecContext(ctx, `ALTER TABLE vms RENAME TO vms_r5`); err != nil {
		t.Fatal(err)
	}
	s.ResumeHeldGuestsOnce(ctx)
	if _, err := s.db.DB().ExecContext(ctx, `ALTER TABLE vms_r5 RENAME TO vms`); err != nil {
		t.Fatal(err)
	}
	cond()
	if !r5Held(s, "web") {
		t.Error("an unreadable VM row dropped the record of a held guest")
	}
}
