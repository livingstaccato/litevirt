package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A relocation recreate reads the template the container was created from on
// a host that never judged it. The protected places are refused there too
// (storage.CheckReadDir), whoever created the container: the row stays pending
// and nothing is copied.
func TestContainerCheck_RelocateRecreate_ProtectedTemplatePathRefused(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail,
		Image:       "x",
		CreateSpec:  corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "rootfs:/etc"}),
	})
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())
	if rt.lastCreate.Name != "" {
		t.Fatalf("recreated from a protected host path: %+v", rt.lastCreate)
	}
	fresh := mustGetCt(t, db, "ct1")
	if fresh.State != "pending" || fresh.StateDetail != corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("row = %q/%q, want it left pending for the operator", fresh.State, fresh.StateDetail)
	}
}
