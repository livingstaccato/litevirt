package grpcapi

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestGuardDecisions_RecreateKeepsAtMostItsVLANs (re-review R3-I1): a
// re-created NIC that had no guard record stays unguarded only while it
// carries at most the VLANs the incarnation it replaces carried on that
// network. A request that adds a trunk, or widens one, is a new NIC: it gets
// the default guard, and its VLANs are its network's to allow.
func TestGuardDecisions_RecreateKeepsAtMostItsVLANs(t *testing.T) {
	s := guardServer(t, true)
	bob := sgBindUser(t, s, "bob", "team") // a tenant
	cases := []struct {
		name     string
		prior    string
		trunk    []int32
		wantNone bool
	}{
		{"adds a trunk", `[{"name":"core"}]`, []int32{30, 31}, false},
		{"widens a trunk", `[{"name":"core","trunk":[10,11]}]`, []int32{10, 11, 12}, false},
		{"swaps a VLAN", `[{"name":"core","trunk":[10,11]}]`, []int32{10, 12}, false},
		{"keeps its trunk", `[{"name":"core","trunk":[10,11]}]`, []int32{11, 10}, true},
		{"narrows its trunk", `[{"name":"core","trunk":[10,11,12]}]`, []int32{10, 12}, true},
		{"no trunk before or after", `[{"name":"core"}]`, nil, true},
	}
	for i, c := range cases {
		vm := fmt.Sprintf("web%d", i)
		rctx := seedReplacedVM(t, s, bob, vm, `{"name":"`+vm+`","uuid":"u-`+vm+`","network":`+c.prior+`}`)
		att := &pb.NetworkAttachment{Name: "core", Trunk: c.trunk}
		dec, err := s.admitNICGuards(rctx, vm, []*pb.NetworkAttachment{att}, admitRecreate)
		if err != nil {
			t.Fatalf("%s: admit: %v", c.name, err)
		}
		if dec[0].none != c.wantNone {
			t.Errorf("%s: none = %v, want %v", c.name, dec[0].none, c.wantNone)
		}
		rec := dec[0].record(vm, "u-new", 0, "52:54:00:00:01:01", att)
		switch {
		case c.wantNone && rec != nil:
			t.Errorf("%s: a NIC that predates guards got a record: %+v", c.name, rec)
		case !c.wantNone && (rec == nil || !rec.Guarded()):
			t.Errorf("%s: the re-created NIC took VLANs its incarnation never had and got no guard: %+v", c.name, rec)
		}
	}
}

// TestRecordExistingTrunkVLANs_UntilTheRelease (re-review R3-I1, m4): the
// trunks that predate guards are recorded into their networks' lists on
// every pass until the release has latched, so a trunk an older build creates
// during the rollout keeps its VLANs too. A VLAN recorded once is not
// recorded again, so an operator who removes it from the list keeps it
// removed. A replica that has not caught up records nothing: it would
// upsert a stale network row over a newer one.
func TestRecordExistingTrunkVLANs_UntilTheRelease(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore"}`}); err != nil {
		t.Fatal(err)
	}
	trunkVM := func(name, mac, vids string) {
		t.Helper()
		spec := `{"name":"` + name + `","uuid":"u-` + name + `","network":[{"name":"core","trunk":[` + vids + `]}]}`
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, HostName: s.hostName, State: "running", Spec: spec},
			[]corrosion.InterfaceRecord{{VMName: name, NetworkName: "core", MAC: mac}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Another host in the cluster: this replica is trusted only once caught up.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer", Address: "192.0.2.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	trunkVM("old-router", "52:54:00:00:00:01", "100,101")
	if done, err := s.recordExistingTrunkVLANs(ctx); err != nil || done {
		t.Fatalf("a replica that has not caught up: done=%v err=%v, want neither", done, err)
	}
	if got := networkDef(t, s, "core").AllowedVLANs; len(got) != 0 {
		t.Fatalf("recorded from a stale replica: %v", got)
	}
	s.db.MarkReplicaCaughtUpForTests("peer")
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	if got := networkDef(t, s, "core").AllowedVLANs; !reflect.DeepEqual(got, []int{100, 101}) {
		t.Fatalf("allowed VLANs = %v, want [100 101]", got)
	}

	// The operator removes 101 (`lv network set`); an older build creates
	// another trunk.
	if _, err := s.SetNetworkGuardConfig(adminCtxWithEngine(t, s), &pb.SetNetworkGuardConfigRequest{Name: "core",
		SetAllowedVlans: true, AllowedVlans: []int32{100}}); err != nil {
		t.Fatal(err)
	}
	trunkVM("rollout", "52:54:00:00:00:02", "101,200")
	if _, err := s.recordExistingTrunkVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	if got := networkDef(t, s, "core").AllowedVLANs; !reflect.DeepEqual(got, []int{100, 200}) {
		t.Errorf("allowed VLANs = %v, want [100 200]: the rollout's trunk added, the operator's removal kept", got)
	}
}

// TestStartContainer_MigratedGuardFailsClosed (re-review m1): a container
// that migrated here keeps the guard record its first host wrote (owner
// ct:<that host>:<name>); the loader renders it through that record, and the
// check that its guard is in force before it starts must find it too —
// otherwise a guarded container whose guard was refused starts unguarded.
// Its delete retires that record as well, and no other container's.
func TestStartContainer_MigratedGuardFailsClosed(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.hostName = "host-b"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "ct1", Template: "download", Distro: "alpine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	const mac = "52:00:00:00:00:20"
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{HostName: "host-b", CtName: "ct1",
		NetworkName: "lan", MAC: mac, VethDevice: "vethct1"}); err != nil {
		t.Fatal(err)
	}
	// Its record from before the migration, and another host's container of
	// the same name with a NIC of its own.
	for _, r := range []corrosion.NICGuardRecord{
		{VMName: corrosion.ContainerGuardOwner("host-a", "ct1"), MAC: mac, Mode: corrosion.NICGuardOn},
		{VMName: corrosion.ContainerGuardOwner("host-c", "ct1"), MAC: "52:00:00:00:00:30", Mode: corrosion.NICGuardOn},
	} {
		if err := corrosion.PutNICGuard(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), r, "t"); err != nil {
			t.Fatal(err)
		}
	}
	a := &inForceArmer{inForce: false}
	s.SetFirewallReconciler(a)
	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "ct1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a migrated guarded container whose guard is not in force: %v, want FailedPrecondition", err)
	}
	if len(rt.startCalls) != 0 {
		t.Fatalf("the runtime started it anyway: %v", rt.startCalls)
	}
	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "ct1", Force: true}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	all, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := all[corrosion.NICGuardKey(corrosion.ContainerGuardOwner("host-a", "ct1"), mac)]; ok {
		t.Error("the migrated container's record outlived its delete")
	}
	if _, ok := all[corrosion.NICGuardKey(corrosion.ContainerGuardOwner("host-c", "ct1"), "52:00:00:00:00:30")]; !ok {
		t.Error("deleting one host's container retired another host's container's record")
	}
}

// TestGuardHost_LabelCountsOnlyForTheBuildThatSetIt (re-review m2): a host
// advertises NIC guards only while it runs the build that set the label. A
// host rolled back to an older build reports that build's version at start,
// and its stale label no longer counts, so a guarded VM is not placed there.
func TestGuardHost_LabelCountsOnlyForTheBuildThatSetIt(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "running",
		Spec: `{"name":"web","uuid":"u-1"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:00:00:01",
		Mode: corrosion.NICGuardOn, VMUUID: "u-1"}, "t"); err != nil {
		t.Fatal(err)
	}
	guardRelease(s).open = false // this node's own release latch lags
	upgraded := corrosion.HostRecord{Name: "new", Version: "v2", Labels: map[string]string{corrosion.LabelNICGuards: "v2"}}
	if err := s.refuseUnguardedTarget(ctx, "web", upgraded); err != nil {
		t.Errorf("a host running the build that set its label: %v", err)
	}
	rolledBack := corrosion.HostRecord{Name: "back", Version: "v1", Labels: map[string]string{corrosion.LabelNICGuards: "v2"}}
	if err := s.refuseUnguardedTarget(ctx, "web", rolledBack); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a host rolled back below guards, its label left behind: %v, want FailedPrecondition", err)
	}
}

// TestArmNICsFor_UnguardedVMWaitsForNoPass (re-review m3): a VM with no NIC
// guard starts as it did before guards: no forced pass is run, or waited
// for, ahead of it; the next tick renders its NICs.
func TestArmNICsFor_UnguardedVMWaitsForNoPass(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	a := &fakeArmer{}
	s.SetFirewallReconciler(a)
	if err := s.ArmNICsFor(ctx, "plain"); err != nil {
		t.Fatal(err)
	}
	if len(a.armed) != 0 {
		t.Errorf("an unguarded VM's start ran a forced pass: %v", a.armed)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: "guarded", MAC: "52:54:00:00:00:01", Mode: corrosion.NICGuardOn}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.ArmNICsFor(ctx, "guarded"); err != nil || len(a.armed) != 1 {
		t.Errorf("a guarded VM's start: %v (armed %v)", err, a.armed)
	}
}

// TestRecordExistingTrunkVLANsLoop_KeepsGoingUntilTheRelease (re-review
// R3-I1): the loop does not stop after one pass while the release has not
// latched: a trunk an older host creates during the rollout is recorded by a
// later pass.
func TestRecordExistingTrunkVLANsLoop_KeepsGoingUntilTheRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore"}`}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.RecordExistingTrunkVLANsLoop(ctx, 20*time.Millisecond)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, have, _ := corrosion.TrunkVLANsRecorded(ctx, s.db); have {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the loop never made a first pass")
		}
		time.Sleep(10 * time.Millisecond)
	}
	spec := `{"name":"later","uuid":"u-later","network":[{"name":"core","trunk":[300,301]}]}`
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "later", HostName: s.hostName, State: "running", Spec: spec},
		[]corrosion.InterfaceRecord{{VMName: "later", NetworkName: "core", MAC: "52:54:00:00:00:09"}}, nil); err != nil {
		t.Fatal(err)
	}
	for !reflect.DeepEqual(networkDef(t, s, "core").AllowedVLANs, []int{300, 301}) {
		if time.Now().After(deadline) {
			t.Fatalf("a trunk created during the rollout was not recorded: %v", networkDef(t, s, "core").AllowedVLANs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
