package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/placement"
)

// unfilteredNets seeds a shared network "lan" and a project network
// "teamnet", and returns a project network admin of team (network.update on
// teamnet, not admin).
func unfilteredNets(t *testing.T) (*Server, context.Context) {
	t.Helper()
	s := guardServer(t, true)
	for _, n := range []corrosion.NetworkRecord{
		{Name: "lan", Type: "bridge", Config: `{"Type":"bridge","Interface":"brlan","Subnet":"10.7.0.0/24"}`},
		{Name: "teamnet", Type: "bridge", Config: `{"Type":"bridge","Interface":"brteam","Subnet":"10.8.0.0/24"}`, Project: "team"},
	} {
		if err := corrosion.UpsertNetwork(context.Background(), s.db, n); err != nil {
			t.Fatal(err)
		}
	}
	return s, sgBindUser(t, s, "bob", "team")
}

// The opt-in is the admin's alone, even on a network whose owner may set its
// other guard config; it is stored on the network row, read back in the
// reply, audited on and off; a flat bridge cannot hold it; and a re-deploy of
// the network (keepTrunkVLANs, which every verbatim write of the row goes
// through) keeps it.
//
// Mutations: drop the admin check — red; drop the keep in keepTrunkVLANs —
// red; drop the read-back in networkRecordToInfo — red; drop the flat-bridge
// refusal — red.
func TestSetNetworkGuardConfig_UnfilteredAccessVLANMoves(t *testing.T) {
	s, bob := unfilteredNets(t)
	on := &pb.SetNetworkGuardConfigRequest{Name: "teamnet", SetAllowUnfilteredAccessVlanMoves: true, AllowUnfilteredAccessVlanMoves: true}
	if _, err := s.SetNetworkGuardConfig(bob, on); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the network's own admin (not a cluster admin): %v, want PermissionDenied", err)
	}
	if networkDef(t, s, "teamnet").AllowUnfilteredAccessVLANMoves {
		t.Fatal("a denied request set it")
	}
	if n := auditRows(t, s, auditUnfilteredAccessVLANMoves, "denied"); n != 1 {
		t.Errorf("denied audit rows = %d, want 1", n)
	}
	ni, err := s.SetNetworkGuardConfig(adminCtx(), on)
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	if !ni.GetAllowUnfilteredAccessVlanMoves() || !networkDef(t, s, "teamnet").AllowUnfilteredAccessVLANMoves {
		t.Fatalf("after the admin's set: reply %v, stored %v; want both on", ni.GetAllowUnfilteredAccessVlanMoves(),
			networkDef(t, s, "teamnet").AllowUnfilteredAccessVLANMoves)
	}
	if def := networkDef(t, s, "teamnet"); def.Subnet != "10.8.0.0/24" || def.Interface != "brteam" {
		t.Errorf("the set changed the rest of the config: %+v", def)
	}
	if n := auditRows(t, s, auditUnfilteredAccessVLANMoves, "ok"); n != 1 {
		t.Errorf("ok audit rows = %d, want 1", n)
	}

	// A re-deploy writes the definition verbatim: the opt-in survives.
	def := compose.NetworkDef{Type: "bridge", Interface: "brteam", Subnet: "10.8.0.0/24"}
	if _, err := s.keepTrunkVLANs(context.Background(), "teamnet", &def); err != nil {
		t.Fatal(err)
	}
	if !def.AllowUnfilteredAccessVLANMoves {
		t.Fatal("a re-deploy of the network drops the opt-in")
	}

	// A flat bridge has no row to hold it.
	// Asked beside --allowed-vlans, which a flat bridge can hold, it is not
	// dropped silently.
	if _, err := s.SetNetworkGuardConfig(adminCtx(), &pb.SetNetworkGuardConfigRequest{Name: "nosuchbr",
		SetAllowedVlans: true, AllowedVlans: []int32{100},
		SetAllowUnfilteredAccessVlanMoves: true, AllowUnfilteredAccessVlanMoves: true}); status.Code(err) != codes.InvalidArgument ||
		!strings.Contains(err.Error(), "flat bridge") {
		t.Fatalf("on a flat bridge: %v, want InvalidArgument naming the flat bridge", err)
	}

	ni, err = s.SetNetworkGuardConfig(adminCtx(), &pb.SetNetworkGuardConfigRequest{Name: "teamnet",
		SetAllowUnfilteredAccessVlanMoves: true, AllowUnfilteredAccessVlanMoves: false})
	if err != nil || ni.GetAllowUnfilteredAccessVlanMoves() || networkDef(t, s, "teamnet").AllowUnfilteredAccessVLANMoves {
		t.Fatalf("turning it off: %v / %v", ni, err)
	}
	if n := auditRows(t, s, auditUnfilteredAccessVLANMoves, "ok"); n != 2 {
		t.Errorf("ok audit rows after off = %d, want 2", n)
	}
	// A set of anything else leaves it as it is, and needs no admin.
	if _, err := s.SetNetworkGuardConfig(adminCtx(), on); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNetworkGuardConfig(bob, &pb.SetNetworkGuardConfigRequest{Name: "teamnet", SetGateway: true, Gateway: "10.8.0.254"}); err != nil {
		t.Fatalf("the owner's gateway set: %v", err)
	}
	if !networkDef(t, s, "teamnet").AllowUnfilteredAccessVLANMoves {
		t.Fatal("another setting's write dropped the opt-in")
	}
}

// While a network allows unfiltered moves, access_vlan_unfiltered_moves_allowed
// (subject network/<name>, warning) is open for it; it resolves once the
// network no longer does.
//
// Mutation: judgeUnfilteredMoveOptIns a no-op — red.
func TestReconcileAccessVLANBridges_FlagsTheUnfilteredMovesOptIn(t *testing.T) {
	s, _ := unfilteredNets(t)
	ctx := context.Background()
	cond := func() (corrosion.HealthCondition, bool) {
		c, ok, err := corrosion.GetHealthCondition(ctx, s.db, health.AccessVLANEvaluator, health.CondUnfilteredAccessVLANMovesAllowed, "network", "lan")
		if err != nil {
			t.Fatal(err)
		}
		return c, ok
	}
	s.ReconcileAccessVLANBridges(ctx)
	if _, ok := cond(); ok {
		t.Fatal("raised for a network without the opt-in")
	}
	set := func(v bool) {
		if _, err := s.SetNetworkGuardConfig(adminCtx(), &pb.SetNetworkGuardConfigRequest{Name: "lan",
			SetAllowUnfilteredAccessVlanMoves: true, AllowUnfilteredAccessVlanMoves: v}); err != nil {
			t.Fatal(err)
		}
	}
	set(true)
	s.ReconcileAccessVLANBridges(ctx)
	c, ok := cond()
	if !ok || c.Lifecycle == corrosion.ConditionResolved || c.Severity != corrosion.SeverityWarning ||
		!strings.Contains(c.Evidence, "--allow-unfiltered-access-vlan-moves=false") {
		t.Fatalf("with the opt-in on: %+v (found %v); want an open warning saying how to turn it off", c, ok)
	}
	set(false)
	s.ReconcileAccessVLANBridges(ctx)
	if c, _ := cond(); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("with the opt-in off: %s, want resolved", c.Lifecycle)
	}
}

// With its network's opt-in on, a move of an access-VLAN VM onto a bridge
// that does not filter VLANs is let through by the target, and the drain does
// not exclude such a host for it; without, both refuse.
//
// Mutations: drop the opt-in from accessVLANMoveRefusal — red; drop
// WithoutUnfilteredMoveNICs from the drain's exclude — red.
func TestUnfilteredMovesOptIn_LetsTheMoveThrough(t *testing.T) {
	s, _ := unfilteredNets(t)
	ctx := context.Background()
	s.SetBridgeVLANFiltering(func(string) (bool, bool, error) { return true, false, nil })
	s.SetBridgeExists(func(string) bool { return true })
	spec, _ := json.Marshal(&pb.VMSpec{Name: "acc", Network: []*pb.NetworkAttachment{{Name: "lan", Trunk: []int32{30}}}})
	vm := corrosion.VMRecord{Name: "acc", Spec: string(spec)}
	if err := s.accessVLANMoveRefusal(ctx, &vm); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("without the opt-in: %v, want FailedPrecondition", err)
	}
	nets := map[string]corrosion.NetworkRecord{}
	view := func() *accessVLANMoveView {
		rows, _ := corrosion.ListNetworks(ctx, s.db)
		nets = health.AccessVLANNetworks(rows)
		return &accessVLANMoveView{nets: nets, unfit: map[string]map[string]bool{"h2": {network.BridgeName("lan", networkDef(t, s, "lan")): true}}}
	}
	var req placement.Request
	view().exclude(&req, vm)
	if _, ok := req.ExcludeHosts["h2"]; !ok {
		t.Fatalf("without the opt-in the drain does not exclude h2: %v", req.ExcludeHosts)
	}

	if _, err := s.SetNetworkGuardConfig(adminCtx(), &pb.SetNetworkGuardConfigRequest{Name: "lan",
		SetAllowUnfilteredAccessVlanMoves: true, AllowUnfilteredAccessVlanMoves: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.accessVLANMoveRefusal(ctx, &vm); err != nil {
		t.Fatalf("with the opt-in: %v, want the move let through", err)
	}
	req = placement.Request{}
	view().exclude(&req, vm)
	if len(req.ExcludeHosts) != 0 {
		t.Fatalf("with the opt-in the drain still excludes %v", req.ExcludeHosts)
	}
}

// Rolling upgrade: a peer on an earlier build (rc7) knows neither field 8 nor
// 9 of SetNetworkGuardConfigRequest, nor field 11 of NetworkInfo. Bytes this
// build sends parse there — the known fields intact, the new ones kept as
// unknown fields and ignored — so an older server applies the rest of the
// request and answers without the read-back field, which the CLI reports
// (unfilteredMovesTookEffect). A message is decoded here against this build's
// descriptor with those fields removed: the shape the older build compiled.
//
// Mutation: drop omitempty from NetworkDef's field — red.
func TestUnfilteredMovesOptIn_AnOlderPeerIgnoresTheFields(t *testing.T) {
	older := func(msg proto.Message, drop ...protoreflect.FieldNumber) protoreflect.MessageDescriptor {
		t.Helper()
		md := msg.ProtoReflect().Descriptor()
		fdp := protodesc.ToFileDescriptorProto(md.ParentFile())
		for _, m := range fdp.MessageType {
			if m.GetName() != string(md.Name()) {
				continue
			}
			var kept []*descriptorpb.FieldDescriptorProto
			for _, f := range m.Field {
				keep := true
				for _, d := range drop {
					if protoreflect.FieldNumber(f.GetNumber()) == d {
						keep = false
					}
				}
				if keep {
					kept = append(kept, f)
				}
			}
			m.Field = kept
		}
		fd, err := protodesc.NewFile(fdp, protoregistryFiles(t, md.ParentFile()))
		if err != nil {
			t.Fatal(err)
		}
		return fd.Messages().ByName(md.Name())
	}

	req := &pb.SetNetworkGuardConfigRequest{Name: "lan", SetGateway: true, Gateway: "10.7.0.254",
		SetAllowUnfilteredAccessVlanMoves: true, AllowUnfilteredAccessVlanMoves: true}
	b, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	old := dynamicpb.NewMessage(older(req, 8, 9))
	if err := proto.Unmarshal(b, old); err != nil {
		t.Fatalf("an older peer cannot parse the request: %v", err)
	}
	if got := old.Get(old.Descriptor().Fields().ByName("gateway")).String(); got != "10.7.0.254" {
		t.Errorf("an older peer reads gateway %q", got)
	}
	if len(old.GetUnknown()) == 0 {
		t.Error("the new fields did not reach the older peer as unknown fields")
	}
	if old.Descriptor().Fields().ByNumber(8) != nil {
		t.Fatal("the older shape still has field 8: the test is not testing an older peer")
	}

	// Its reply has no field 11: decoded here, the opt-in reads off.
	oldInfo := dynamicpb.NewMessage(older(&pb.NetworkInfo{}, 11))
	oldInfo.Set(oldInfo.Descriptor().Fields().ByName("name"), protoreflect.ValueOfString("lan"))
	ob, err := proto.Marshal(oldInfo)
	if err != nil {
		t.Fatal(err)
	}
	var ni pb.NetworkInfo
	if err := proto.Unmarshal(ob, &ni); err != nil || ni.GetName() != "lan" || ni.GetAllowUnfilteredAccessVlanMoves() {
		t.Fatalf("an older peer's reply: %v, %v", &ni, err)
	}

	// The stored config: written by this build, read by an older one's
	// NetworkDef, which lacks the field (encoding/json ignores the key), and
	// a network without the opt-in is stored exactly as before (omitempty).
	type olderNetworkDef struct {
		Type, Interface, Subnet string
		AllowedVLANs            []int
	}
	cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "brlan", Subnet: "10.7.0.0/24", AllowUnfilteredAccessVLANMoves: true})
	var od olderNetworkDef
	if err := json.Unmarshal(cfg, &od); err != nil || od.Interface != "brlan" || od.Subnet != "10.7.0.0/24" {
		t.Fatalf("an older node reads %s as %+v, %v", cfg, od, err)
	}
	plain, _ := json.Marshal(compose.NetworkDef{Type: "bridge"})
	if strings.Contains(string(plain), "AllowUnfilteredAccessVLANMoves") {
		t.Fatalf("a network without the opt-in stores the key: %s", plain)
	}
}

// protoregistryFiles is a resolver holding fd's imports, for protodesc.
func protoregistryFiles(t *testing.T, fd protoreflect.FileDescriptor) *protoregistry.Files {
	t.Helper()
	files := new(protoregistry.Files)
	var add func(protoreflect.FileDescriptor)
	add = func(f protoreflect.FileDescriptor) {
		imps := f.Imports()
		for i := 0; i < imps.Len(); i++ {
			imp := imps.Get(i).FileDescriptor
			if _, err := files.FindFileByPath(imp.Path()); err == nil {
				continue
			}
			add(imp)
			if err := files.RegisterFile(imp); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(fd)
	return files
}

// NB-R3: the target's access-VLAN judgement of a move reads the same row its
// authorization does, so a move is never let through for want of one: an
// unreadable row refuses, and a readable one with an access NIC on a bridge
// here that does not filter VLANs is refused naming the VLAN.
//
// Mutation: skip accessVLANMoveRefusal in EnsureDisks — red.
func TestEnsureDisks_JudgesTheAccessVLANOfTheRowItAuthorized(t *testing.T) {
	s, _ := unfilteredNets(t)
	ctx := adminCtx()
	s.SetBridgeVLANFiltering(func(string) (bool, bool, error) { return true, false, nil })
	s.SetBridgeExists(func(string) bool { return true })
	insertTestVMWithSpec(t, ctx, s.db, "acc", "other-host", "running", seedSpecJSON(t, &pb.VMSpec{
		Name: "acc", Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:aa:07:01", Trunk: []int32{30}}}}))
	if _, err := s.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: "acc"}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "VLAN 30") {
		t.Fatalf("EnsureDisks onto a non-filtering bridge: %v, want FailedPrecondition naming VLAN 30", err)
	}
	if _, err := s.db.DB().ExecContext(context.Background(), `ALTER TABLE vms RENAME TO vms_nbr3`); err != nil {
		t.Fatal(err)
	}
	defer s.db.DB().ExecContext(context.Background(), `ALTER TABLE vms_nbr3 RENAME TO vms`) //nolint:errcheck
	if _, err := s.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: "acc"}); err == nil {
		t.Fatal("EnsureDisks with the VM's row unreadable let the move through")
	}
}
