package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A healthcheck without a type, whose target settles it, is deployed with the
// inferred type in the VM's stored spec — which is what the owner's checker
// reads, so a node that does not infer still probes it correctly.
func TestFleet_ComposeInferredHealthcheckTypeIsStored(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	const src = `name: inf

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    healthcheck:
      target: "5432"
      action: alert
`
	deployCollect(t, ctx, client, src)
	db, err := corrosion.GetVM(ctx, node.DB, "db")
	if err != nil || db == nil {
		t.Fatalf("db not created: %v", err)
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(db.Spec), spec); err != nil {
		t.Fatalf("decode db spec: %v", err)
	}
	if spec.Healthcheck == nil || spec.Healthcheck.Type != "tcp" || spec.Healthcheck.Target != "5432" {
		t.Errorf("stored healthcheck = %+v, want type tcp, target 5432", spec.Healthcheck)
	}
}
