package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A disk whose storage: names neither a volume of the file nor any pool in
// the cluster is refused at deploy time, before any VM exists. It used to be
// created on the local driver, silently.
func TestFleet_ComposeUndeclaredStorageIsRefused(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	const src = `name: st

images:
  test:
    source: file:///dev/null

volumes:
  warm: { driver: nfs, source: "nas:/x" }

vms:
  db:
    image: test
    cpu: 1
    memory: 512
    disks:
      data: { size: 1G, storage: wram }
`
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: src})
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil || !strings.Contains(err.Error(), `vms.db.disks.data.storage: storage "wram"`) ||
		!strings.Contains(err.Error(), `did you mean "warm"?`) {
		t.Fatalf("deploy with storage wram: err=%v, want the undeclared-storage refusal", err)
	}
	if db, _ := corrosion.GetVM(ctx, node.DB, "db"); db != nil {
		t.Errorf("db was created (state %s) with storage that resolves nowhere", db.State)
	}
}
