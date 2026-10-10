// Fleet scenarios for re-review 3 of fix/iscsi-one-disk-per-lun: the window
// AFTER a rebuild or recreate that moved a LUN's claim has returned, when the
// host that decided the moved allocation (the rollout host) does not yet see
// the re-created VM's rows. Each one injects the fault the reviewer named —
// replication lag that delivers the old incarnation's tombstone before the
// new rows, a restart of the rollout host, a create that errs after its
// guest started, a partition from the VM's host — and races a create on the
// LUN from a node whose replica has neither the old rows nor the new ones.
//
// They run on independent replicas. Every wait is on another node's replica,
// so a test whose replication stalled times out rather than passing.

package fleet

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const allAtOnce = "    update:\n      strategy: all-at-once\n"

// blockOutOf refuses every replication push from n: nothing n writes reaches
// another node, directly or through a relay.
func blockOutOf(c *Cluster, n *Node) {
	for _, o := range c.Nodes {
		if o != n {
			c.SetLinkFault(n, o, LinkFault{Block: true})
		}
	}
}

// lunHoldersAt is what n answers asker about the LUN.
func lunHoldersAt(t *testing.T, c *Cluster, asker, n *Node, lun string) []*pb.LUNHolder {
	t.Helper()
	resp, err := c.PeerClient(asker, n).LUNHolders(context.Background(), &pb.LUNHoldersRequest{Luns: []string{lun}})
	if err != nil {
		t.Fatalf("ask %s about the LUN: %v", n.Name, err)
	}
	return resp.GetHolders()
}

// heldInFlight reports whether hs has vm in flight; heldByRow whether hs has
// a committed holder vm on host.
func heldInFlight(hs []*pb.LUNHolder, vm string) bool {
	for _, h := range hs {
		if h.InFlight && h.VmName == vm {
			return true
		}
	}
	return false
}

func heldByRow(hs []*pb.LUNHolder, vm, host string) bool {
	for _, h := range hs {
		if !h.InFlight && h.VmName == vm && h.HostName == host {
			return true
		}
	}
	return false
}

// deployResult is deployCollect for a deploy that may fail or be cut off.
func deployResult(ctx context.Context, client pb.LiteVirtClient, yaml string) ([]*pb.DeployProgress, error) {
	dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: yaml})
	if err != nil {
		return nil, err
	}
	var out []*pb.DeployProgress
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
}

// restartNode stands in for a daemon restart on n: its gRPC server stops —
// every RPC it was serving is cancelled, as a process exit cancels them — and
// a new server comes up on the same port, over the same state database and
// data directory. Nothing held only in the old server's memory survives.
func restartNode(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	if n.replStarted {
		n.repl.Stop()
		n.replStarted = false
	}
	if n.stopServerLoops != nil {
		n.stopServerLoops()
	}
	n.Stop()
	l, err := net.Listen("tcp", net.JoinHostPort(n.Address, strconv.Itoa(n.Port)))
	if err != nil {
		t.Fatalf("rebind %s on port %d: %v", n.Name, n.Port, err)
	}
	n.Listener = l
	c.buildServer(n)
	n.repl.SetProofReplicaGate(func(context.Context, string) bool { return true })
	n.repl.Start(c.ctx)
	n.replStarted = true
	n.Server.SetReleaseFeatureGate(func(context.Context, string) error { return nil })
}

// webOn reports whether n's replica has web live on host.
func webOn(t *testing.T, n *Node, web, host string) bool {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, web)
	return err == nil && rec != nil && rec.HostName == host
}

// Re-review 3, I-1. web runs on node-1; an update from node-0 re-creates it
// on node-3, and returns. web's old incarnation is gone from node-0 and node-2
// (its tombstone arrived, or node-0's create retired its copy), and web's new
// rows reach neither: node-3's writes reach no one. A create on node-2 meets
// the moved allocation and asks node-0, which must still hold it — the window
// after the recreate has returned, which no racer inside the create reaches.
// Once web's new rows reach node-0, its hold gives way to them.
//
// Mutation: release the moved hold as soon as the recreate returns — node-0
// answers nothing, and this goes red.
func TestFleet_ISCSI_AMovedHoldWaitsForTheNewIncarnationsRows(t *testing.T) {
	c, web, stack := lunWebStack(t, allAtOnce)
	n0, n2, n3 := c.Nodes[0], c.Nodes[2], c.Nodes[3]
	ctx := context.Background()
	key := fleetLUNKey(0)

	blockOutOf(c, n3)
	msgs := deployCollect(t, ctx, c.SelfClient(n0), stack(n3.Name, "      scratch: 1G\n"))
	if p := errorPhaseFor(msgs, web); p != nil {
		t.Fatalf("the update failed: %s", p.Detail)
	}
	if !n3.Virt.DomainExists(web) {
		t.Fatal("web was not re-created on node-3")
	}
	eventually(t, convergeTimeout, "the old incarnation to be gone from node-0 and node-2", func() bool {
		return !lunVMOn(t, n0, web) && !lunVMOn(t, n2, web)
	})
	err := createOnLUN(c, n2, "db", "san")
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), web) {
		t.Fatalf("a create on web's LUN once web's old rows are gone and its new ones have not arrived: got %v, "+
			"want Aborted naming %s", err, web)
	}
	if lunVMOn(t, n2, "db") {
		t.Fatal("the racer's VM was persisted: two guests on one LUN")
	}
	if hs := lunHoldersAt(t, c, n2, n0, key); !heldInFlight(hs, web) {
		t.Fatalf("node-0 answers %v, want the moved claim of %s held in flight", hs, web)
	}

	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "web's new rows to reach node-0", func() bool { return webOn(t, n0, web, n3.Name) })
	eventually(t, 2*convergeTimeout, "node-0's hold to give way to web's new rows", func() bool {
		hs := lunHoldersAt(t, c, n2, n0, key)
		return !heldInFlight(hs, web) && heldByRow(hs, web, n3.Name)
	})
}

// Re-review 3, I-2 (restart). The rollout host, node-0, restarts after the
// teardown, while web's create is on its way to node-3 but has not reached
// it. A create on node-2 meets the moved allocation: node-0, restarted, still
// holds it.
//
// Mutation: keep the moved hold in memory only — the restarted node-0
// answers nothing, node-3 has nothing yet, the racer takes the LUN, and this
// goes red.
func TestFleet_ISCSI_AMovedHoldSurvivesARestartOfTheRolloutHost(t *testing.T) {
	c, web, stack := lunWebStack(t, allAtOnce)
	n0, n2, n3 := c.Nodes[0], c.Nodes[2], c.Nodes[3]
	ctx := context.Background()
	key := fleetLUNKey(0)

	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	hold := func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		once.Do(func() { close(entered) })
		<-proceed
		return handler(ctx, req)
	}
	n3.HookUnary("CreateVM", hold)
	n3.HookUnary("ExecuteCreateVM", hold)
	var proceedOnce sync.Once
	letGo := func() { proceedOnce.Do(func() { close(proceed) }) }
	t.Cleanup(letGo)

	done := make(chan error, 1)
	client := c.SelfClient(n0)
	go func() {
		_, err := deployResult(ctx, client, stack(n3.Name, "      scratch: 1G\n"))
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("web's create never reached node-3")
	}
	eventually(t, convergeTimeout, "web's teardown to reach node-2", func() bool { return !lunVMOn(t, n2, web) })

	restartNode(t, c, n0)
	err := createOnLUN(c, n2, "db", "san")
	letGo()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the cut-off update never returned")
	}
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), web) {
		t.Fatalf("a create on web's LUN after the rollout host restarted: got %v, want Aborted naming %s", err, web)
	}
	if lunVMOn(t, n2, "db") {
		t.Fatal("the racer's VM was persisted while web's create was on its way")
	}

	// The restarted node-0 lets go only on positive evidence: node-3 shows
	// nothing of web (its create was cut off), or web's new rows arrived.
	eventually(t, 2*convergeTimeout, "the restarted node-0 to resolve its hold", func() bool {
		return !heldInFlight(lunHoldersAt(t, c, n2, n0, key), web)
	})
	// Never two writers: db takes the LUN only if web did not come back.
	if err := createOnLUN(c, n2, "db", "san"); err == nil && n3.Virt.DomainExists(web) {
		t.Fatal("two guests on one LUN: db, and web on node-3")
	} else if err != nil && !n3.Virt.DomainExists(web) {
		t.Fatalf("with web's create cut off and node-0's hold resolved, db is still refused: %v", err)
	}
}

// Re-review 3, I-2 (an error after the guest started). web's create on
// node-3 commits — the guest runs, its rows are written — but its answer is
// lost, so the update on node-0 sees an error. node-3's rows reach no one
// yet. node-0 must not let go of the moved claim on that error: a create on
// node-2 is refused. Once web's rows reach node-0, its hold gives way to them.
//
// Mutation: release the moved hold when the create returns an error (round
// 3) — the racer asks node-0, hears nothing, and this goes red.
func TestFleet_ISCSI_AMovedHoldSurvivesACreateThatErrsAfterItsGuestStarted(t *testing.T) {
	c, web, stack := lunWebStack(t, allAtOnce)
	n0, n2, n3 := c.Nodes[0], c.Nodes[2], c.Nodes[3]
	ctx := context.Background()
	key := fleetLUNKey(0)

	lost := func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		out, err := handler(ctx, req)
		if err != nil {
			return out, err
		}
		return nil, status.Error(codes.Unavailable, "fleet: the create's answer was lost")
	}
	n3.HookUnary("CreateVM", lost)
	n3.HookUnary("ExecuteCreateVM", lost)
	blockOutOf(c, n3)
	msgs, _ := deployResult(ctx, c.SelfClient(n0), stack(n3.Name, "      scratch: 1G\n"))
	if errorPhaseFor(msgs, web) == nil {
		t.Fatalf("the update did not see the lost answer: %v", msgs)
	}
	if !n3.Virt.DomainExists(web) {
		t.Fatal("the scenario needs web's guest running on node-3")
	}
	eventually(t, convergeTimeout, "the old incarnation's tombstone to reach node-0 and node-2", func() bool {
		return !lunVMOn(t, n0, web) && !lunVMOn(t, n2, web)
	})
	err := createOnLUN(c, n2, "db", "san")
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), web) {
		t.Fatalf("a create on web's LUN after web's create erred with its guest running: got %v, want Aborted naming %s", err, web)
	}
	if lunVMOn(t, n2, "db") {
		t.Fatal("the racer's VM was persisted: two guests on one LUN")
	}

	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "web's new rows to reach node-0", func() bool { return webOn(t, n0, web, n3.Name) })
	eventually(t, 2*convergeTimeout, "node-0's hold to give way to web's new rows", func() bool {
		hs := lunHoldersAt(t, c, n2, n0, key)
		return !heldInFlight(hs, web) && heldByRow(hs, web, n3.Name)
	})
}

// Re-review 3, I-2 (a partition). web is re-created on node-3, and node-3 is
// then cut off: nothing it writes arrives, and it cannot be asked. However
// long that lasts — round 3 let the hold lapse after ten minutes — node-0
// keeps the moved claim: no time passes into the decision, and an unreachable
// run host is not evidence. A create on node-2, on the majority side and with
// neither of web's incarnations in its replica, is refused by node-0's hold.
// Once node-3 is back and web's rows reach node-0, the hold gives way.
//
// Mutation: release the hold when its run host cannot be asked (a lapse) —
// node-0 answers nothing, the racer meets node-3's silence instead, and this
// goes red.
func TestFleet_ISCSI_AMovedHoldOutlastsAPartitionFromTheVMsHost(t *testing.T) {
	c, web, stack := lunWebStack(t, allAtOnce)
	n0, n2, n3 := c.Nodes[0], c.Nodes[2], c.Nodes[3]
	ctx := context.Background()
	key := fleetLUNKey(0)

	blockOutOf(c, n3)
	msgs := deployCollect(t, ctx, c.SelfClient(n0), stack(n3.Name, "      scratch: 1G\n"))
	if p := errorPhaseFor(msgs, web); p != nil {
		t.Fatalf("the update failed: %s", p.Detail)
	}
	if !n3.Virt.DomainExists(web) {
		t.Fatal("web was not re-created on node-3")
	}
	restore := n3.DoNotImplement("LUNHolders")
	eventually(t, convergeTimeout, "the old incarnation to be gone from node-0 and node-2", func() bool {
		return !lunVMOn(t, n0, web) && !lunVMOn(t, n2, web)
	})
	for i := 0; i < 5; i++ {
		if err := n0.Server.ResolveLUNHolds(ctx); err == nil {
			t.Fatal("node-0 judged its hold with node-3 unreachable and reported nothing wrong")
		}
	}
	if hs := lunHoldersAt(t, c, n2, n0, key); !heldInFlight(hs, web) {
		t.Fatalf("node-0 answers %v during the partition, want the moved claim of %s held in flight", hs, web)
	}
	err := createOnLUN(c, n2, "db", "san")
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), web) {
		t.Fatalf("a create on web's LUN during the partition: got %v, want Aborted naming %s (node-0's hold)", err, web)
	}
	if lunVMOn(t, n2, "db") {
		t.Fatal("the racer's VM was persisted: two guests on one LUN")
	}

	restore()
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "web's new rows to reach node-0", func() bool { return webOn(t, n0, web, n3.Name) })
	eventually(t, 2*convergeTimeout, "node-0's hold to give way to web's new rows", func() bool {
		_ = n0.Server.ResolveLUNHolds(ctx)
		hs := lunHoldersAt(t, c, n2, n0, key)
		return !heldInFlight(hs, web) && heldByRow(hs, web, n3.Name)
	})
}
