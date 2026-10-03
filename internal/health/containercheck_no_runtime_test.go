package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A container relocated onto a host that has no container runtime can never
// be recreated there. Its relocation fails for good: the proof is failed
// (terminal) — not left in_progress forever — and the row leaves the
// relocate-recreate marker, so the sweep stops retrying "lxc-create not found"
// (drill D3: blct on node-3).
//
// The host is taken to have no runtime unless its daemon labelled it
// litevirt.lxc=true (corrosion.HostRunsContainers): "false", written at every
// start where lxc-create is missing, and no label at all both count. Placement
// already refuses such a host, so this is a relocation decided before the
// label said so.
//
// Mutations: drop the no-runtime check — the fake runtime "recreates" the
// container and the proof completes, and both subtests go red; restore the
// lenient rule (only "false" lacks a runtime) — the unlabelled subtest goes red.
func TestContainerCheck_RelocateRecreate_NoRuntimeFailsTheProof(t *testing.T) {
	for _, label := range []string{"false", ""} {
		t.Run("litevirt.lxc="+label, func(t *testing.T) {
			testRelocateRecreateNoRuntime(t, label)
		})
	}
}

func testRelocateRecreateNoRuntime(t *testing.T, label string) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if label != "" {
		if err := corrosion.SetHostLabel(ctx, db, "node1", corrosion.LabelLXCCapable, label); err != nil {
			t.Fatal(err)
		}
	}
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "blct", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail,
		Image:       "alpine:3.19", RelocateToken: "tok-1",
	})
	if err := corrosion.WriteActionProof(ctx, db, corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionRelocate, TargetKind: "container",
		TargetName: "blct", DestHost: "node1", Coordinator: "coord", RelocationToken: "tok-1",
	}); err != nil {
		t.Fatal(err)
	}

	c := NewContainerChecker("node1", db, rt)
	c.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	c.checkContainer(ctx, mustGetCt(t, db, "blct"), time.Now())

	if rt.startCount("blct") != 0 {
		t.Fatal("blct was recreated on a host with no container runtime")
	}
	pr, ok, _ := corrosion.GetActionProof(ctx, db, "p1")
	if !ok || pr.Status != corrosion.ProofFailed {
		t.Fatalf("relocation proof = %q (ok %v), want failed", pr.Status, ok)
	}
	got := mustGetCt(t, db, "blct")
	if got.State != "error" || got.StateDetail == corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("blct = %q / %q, want error, off the relocate-recreate marker", got.State, got.StateDetail)
	}

	// The next sweep leaves it alone.
	c.checkContainer(ctx, mustGetCt(t, db, "blct"), time.Now())
	if again := mustGetCt(t, db, "blct"); again.State != "error" {
		t.Fatalf("a later sweep moved blct to %q", again.State)
	}
}

// A host its daemon labelled litevirt.lxc=true recreates the relocated
// container as before: the control for the refusal above.
//
// Mutation: read every host as lacking a runtime — ct1 is not recreated and
// this goes red.
func TestContainerCheck_RelocateRecreate_LabelledHostRecreates(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetHostLabel(ctx, db, "node1", corrosion.LabelLXCCapable, "true"); err != nil {
		t.Fatal(err)
	}
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail, Image: "alpine:3.19",
	})
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())
	if rt.startCount("ct1") != 1 {
		t.Fatalf("ct1 started %d times on a host labelled litevirt.lxc=true, want 1", rt.startCount("ct1"))
	}
}
