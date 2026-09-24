package fleet

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// An update of a VM already on its host is placed as a REPLACEMENT of the VM's
// current allocation on that host, not an addition to it. The regression, found
// on a 4 vCPU / 2971 MiB lab host: db (1 vCPU / 1 GiB) filled most of the
// host's 1947 MiB allocatable, the planner charged db's running 1024 MiB AND
// its updated request, and every update of db — a shrink, even a label-only
// change — failed with "no eligible host for VM db".

const composeFillHost = `name: hc

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 1
    memory: 1024
    placement:
      host: node-0
    network:
      - name: hc
`

// setupFilledHost sizes node-0 like the lab host and deploys db on it.
func setupFilledHost(t *testing.T) (context.Context, *Node, pb.LiteVirtClient) {
	t.Helper()
	node, client := newUpdateNode(t)
	ctx := context.Background()
	// 4 vCPU / 2971 MiB → 15 vCPU / 1947 MiB allocatable under the default
	// policy. db's 1024+128 fits once; twice it does not.
	if err := node.DB.Execute(ctx, `UPDATE hosts SET cpu_total = 4, mem_total = 2971 WHERE name = ?`, node.Name); err != nil {
		t.Fatalf("size host: %v", err)
	}
	deployClean(t, ctx, client, composeFillHost)
	waitRunning(t, ctx, node, "db")
	return ctx, node, client
}

func TestFleet_ComposeUpdateOfAVMFillingItsHostStaysOnIt(t *testing.T) {
	ctx, node, client := setupFilledHost(t)
	before := identityOf(t, ctx, node, "db", true)

	// A label-only change, memory unchanged at 1 GiB.
	labelled := edit(t, composeFillHost, "    network:\n", "    labels:\n      tier: data\n    network:\n")
	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, labelled)
	assertSameVM(t, ctx, node, "db", before, from, false)
	if got := storedSpec(t, ctx, node, "db").Labels["tier"]; got != "data" {
		t.Errorf("label tier = %q after the update, want data", got)
	}

	// A shrink to 768 MiB alongside the label.
	smaller := edit(t, labelled, "    memory: 1024\n", "    memory: 768\n")
	from = len(node.Virt.EventLog())
	deployClean(t, ctx, client, smaller)
	assertSameVM(t, ctx, node, "db", before, from, false)
	rec, err := corrosion.GetVM(ctx, node.DB, "db")
	if err != nil || rec == nil {
		t.Fatalf("GetVM(db): %v %v", rec, err)
	}
	if rec.HostName != node.Name || rec.MemActual != 768 {
		t.Errorf("db after the shrink = host %s / %d MiB, want %s / 768", rec.HostName, rec.MemActual, node.Name)
	}
}

func TestFleet_ComposeUpdateBeyondItsHostIsRefusedWithTheShortfall(t *testing.T) {
	ctx, node, client := setupFilledHost(t)
	before := identityOf(t, ctx, node, "db", true)

	bigger := edit(t, composeFillHost, "    memory: 1024\n", "    memory: 4096\n")
	from := len(node.Virt.EventLog())
	err := deployErr(t, ctx, client, bigger)
	want := "db needs 4224 MiB of memory on node-0 (4096 MiB + 128 MiB qemu overhead), " +
		"which has 1947 MiB free after db's current 1024 MiB is released"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("deploy of a 4096 MiB db = %v\nwant a refusal containing %q", err, want)
	}
	// Refused before anything was touched.
	assertSameVM(t, ctx, node, "db", before, from, false)
	if got := storedSpec(t, ctx, node, "db").MemoryMib; got != 1024 {
		t.Errorf("memory = %d after a refused update, want 1024", got)
	}
}

// deployErr runs a deploy and returns the error the stream ends with, or the
// first in-band error phase; nil when the deploy succeeds.
func deployErr(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml string) error {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: yaml})
	if err != nil {
		return err
	}
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if p.Phase == "error" {
			return errString(p.VmName + ": " + p.Error)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
