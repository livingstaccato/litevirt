package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A container deployed by compose on another host is `running` in the list the
// entry node serves the moment compose reports it done — which is the node
// `lv compose up` and the `lv ct ls` after it both talk to.
//
// The owning host records `running` before its StartContainer returns. The
// entry node forwards the create and the start there and used to report done
// on the owner's answer alone, while `lv ct ls` reads the entry node's own
// replica — which had the create (state stopped) and not yet the start. So a
// just-deployed container listed as stopped until replication caught up.
const composeRemoteContainer = `name: remotect

workloads:
  web-ct:
    kind: lxc
    image: alpine:3.21
    cpu: 8
    memory: 512
    placement:
      host: node-1
`

// laggingPump carries every mutation from one node to another over the real
// PushMutations RPC, each entry only once it is lag old: replication that
// works, and takes a moment — as it does on a real network.
func laggingPump(t *testing.T, c *Cluster, from, to *Node, lag time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		firstSeen := map[int64]time.Time{}
		var delivered int64
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			rows, err := from.DB.Query(ctx,
				`SELECT seq, hlc, origin, stmts FROM mutation_log WHERE seq > ? ORDER BY seq`, delivered)
			if err != nil {
				continue
			}
			now := time.Now()
			for _, r := range rows {
				if _, ok := firstSeen[r.Int64("seq")]; !ok {
					firstSeen[r.Int64("seq")] = now
				}
			}
			var ready []*pb.MutationEntry
			for _, r := range rows {
				seq := r.Int64("seq")
				if now.Sub(firstSeen[seq]) < lag {
					break // in order: nothing after a young entry goes first
				}
				ready = append(ready, &pb.MutationEntry{
					Seq: seq, Hlc: r.String("hlc"), Origin: r.String("origin"), Stmts: r.String("stmts"),
				})
			}
			if len(ready) == 0 {
				continue
			}
			if _, err := c.PeerClient(from, to).PushMutations(ctx, &pb.ReplicateRequest{
				Sender:              from.Name,
				SenderVersion:       "fleet-test",
				SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion),
				AfterSeq:            delivered,
				Entries:             ready,
			}); err != nil {
				if ctx.Err() == nil {
					t.Errorf("push %s→%s: %v", from.Name, to.Name, err)
				}
				return
			}
			delivered = ready[len(ready)-1].Seq
		}
	}()
}

func TestFleet_ComposeContainerIsRunningOnTheEntryNodeWhenDone(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	entry, owner := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	if err := corrosion.SetHostLabel(ctx, entry.DB, owner.Name, corrosion.LabelLXCCapable, "true"); err != nil {
		t.Fatalf("label %s lxc-capable: %v", owner.Name, err)
	}
	laggingPump(t, c, owner, entry, 300*time.Millisecond)

	deployClean(t, ctx, c.SelfClient(entry), composeRemoteContainer)

	// Read at once: no settling, no retry. This is `lv ct ls` on the node
	// `lv compose up` just printed "Stack deployed." from.
	resp, err := c.SelfClient(entry).ListContainers(ctx, &pb.ListContainersRequest{})
	if err != nil {
		t.Fatalf("ListContainers on %s: %v", entry.Name, err)
	}
	var got *pb.Container
	for _, ct := range resp.GetContainers() {
		if ct.GetName() == "web-ct" {
			got = ct
		}
	}
	if got == nil {
		t.Fatalf("web-ct is not listed on %s right after the deploy reported done", entry.Name)
	}
	if got.GetHostName() != owner.Name || got.GetState() != "running" {
		t.Fatalf("web-ct on %s right after the deploy = host %q state %q, want host %q state running",
			entry.Name, got.GetHostName(), got.GetState(), owner.Name)
	}
	if st := owner.CT.State("web-ct"); st != "running" {
		t.Fatalf("web-ct runtime on %s = %q, want running", owner.Name, st)
	}
}

// `lv ct create` then `lv ct start`, both through a node that does not own the
// container: each reports success only once the node it was asked on lists the
// result — the row after the create, `running` after the start.
func TestFleet_ContainerCreateAndStartThroughAPeerAreVisibleOnReturn(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	entry, owner := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	laggingPump(t, c, owner, entry, 300*time.Millisecond)
	client := c.SelfClient(entry)

	if _, err := client.CreateContainer(ctx, &pb.CreateContainerRequest{
		HostName: owner.Name, Name: "ct1", Template: "download", Distro: "alpine", Release: "3.21",
		Arch: "amd64", MemoryMib: 256,
	}); err != nil {
		t.Fatalf("CreateContainer via %s: %v", entry.Name, err)
	}
	rec, err := corrosion.GetContainer(ctx, entry.DB, owner.Name, "ct1")
	if err != nil || rec == nil {
		t.Fatalf("ct1 on %s right after create returned = %+v err=%v, want the row", entry.Name, rec, err)
	}

	if _, err := client.StartContainer(ctx, &pb.StartContainerRequest{HostName: owner.Name, Name: "ct1"}); err != nil {
		t.Fatalf("StartContainer via %s: %v", entry.Name, err)
	}
	rec, err = corrosion.GetContainer(ctx, entry.DB, owner.Name, "ct1")
	if err != nil || rec == nil || rec.State != "running" {
		t.Fatalf("ct1 on %s right after start returned = %+v err=%v, want running", entry.Name, rec, err)
	}
}
