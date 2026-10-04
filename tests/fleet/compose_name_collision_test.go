package fleet

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const collisionStackA = `name: app

images:
  test:
    source: file:///dev/null

vms:
  v1:
    image: test
    cpu: 1
    memory: 512
  web-1:
    image: test
    cpu: 1
    memory: 512
`

// Stack app_v2 names v1 as app does, and its web replicas expand to web-1,
// which app also has. VM names are cluster-wide.
const collisionStackB = `name: app_v2

images:
  test:
    source: file:///dev/null

vms:
  v1:
    image: test
    cpu: 1
    memory: 512
  web:
    image: test
    cpu: 1
    memory: 512
    replicas: 2
`

// A planned create whose name is already a VM of another stack is refused by
// the plan, before anything runs. It used to plan "+ create v1" and then fail
// at create time with AlreadyExists, after the actions before it had run.
func TestFleet_ComposeCreateCollidingWithAnotherStackIsRefused(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	for _, p := range deployCollect(t, ctx, client, collisionStackA) {
		if p.Phase == "error" {
			t.Fatalf("stack app deploy: %s %s", p.VmName, p.Detail)
		}
	}
	eventsBefore := len(node.Virt.EventLog())

	wantMsgs := []string{
		`vm "v1" already exists in stack "app" — rename it in this file or delete it there`,
		`vm "web-1" already exists in stack "app" — rename it in this file or delete it there`,
	}
	check := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: want the name-collision refusal, got none", what)
		}
		if !strings.Contains(err.Error(), "pre-deploy validation failed") {
			t.Errorf("%s: err=%v, want a pre-deploy validation failure", what, err)
		}
		for _, m := range wantMsgs {
			if !strings.Contains(err.Error(), m) {
				t.Errorf("%s: err=%v\nwant it to contain %q", what, err, m)
			}
		}
		if strings.Contains(err.Error(), `"web-2"`) {
			t.Errorf("%s: web-2 collides with nothing but was reported: %v", what, err)
		}
	}

	// The plan (lv compose up's dry-run) refuses it.
	check("dry-run", recvErr(ctx, client, &pb.DeployStackRequest{ComposeYaml: collisionStackB, DryRun: true}))
	// So does the server's diff of the same file.
	_, err := client.DiffStack(ctx, &pb.DiffStackRequest{ComposeYaml: collisionStackB})
	check("DiffStack", err)
	// And the deploy itself, before any action.
	check("deploy", recvErr(ctx, client, &pb.DeployStackRequest{ComposeYaml: collisionStackB}))

	for _, e := range node.Virt.EventLog()[eventsBefore:] {
		t.Errorf("refused deploy touched the hypervisor: %s %s", e.Op, e.Domain)
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "web-2"); vm != nil {
		t.Errorf("web-2 was created by a refused deploy")
	}
	if v1, _ := corrosion.GetVM(ctx, node.DB, "v1"); v1 == nil || v1.StackName != "app" {
		t.Errorf("v1 after the refused deploy: %+v, want it still in stack app", v1)
	}
	if st, _ := corrosion.GetStack(ctx, node.DB, "app_v2"); st != nil {
		t.Errorf("refused deploy recorded stack app_v2 (state %s)", st.State)
	}

	// A VM of the SAME stack is an update, not a collision.
	edited := strings.Replace(collisionStackA, "  v1:\n    image: test\n    cpu: 1\n", "  v1:\n    image: test\n    cpu: 2\n", 1)
	if edited == collisionStackA {
		t.Fatal("fixture edit did not apply")
	}
	updated := false
	for _, op := range dryRunPlan(t, ctx, client, edited) {
		if op.VmName == "v1" && op.Phase == string(compose.OpUpdate) {
			updated = true
		}
	}
	if !updated {
		t.Error("same-stack redeploy with a cpu change did not plan an update for v1")
	}
	for _, p := range deployCollect(t, ctx, client, edited) {
		if p.Phase == "error" {
			t.Errorf("same-stack redeploy: %s %s", p.VmName, p.Detail)
		}
	}
}

// recvErr runs a deploy and returns the stream's terminal error, nil on EOF.
func recvErr(ctx context.Context, client pb.LiteVirtClient, req *pb.DeployStackRequest) error {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, req)
	if err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
