package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// P-3 of lab 2 run c2. The admission gate reads this host's runtime inventory
// through a 10 s cache (grpcapi.localInventoryTTL). A workload this host just
// removed — deleted, or migrated away — stayed in that cache with no DB row
// left here to account for it:
//
//   - an UNCAPPED container read as a runtime-only rogue, so the next create
//     on the host was refused, naming the container just deleted;
//   - a running VM read as runtime-only load, charged against the host's
//     headroom, so a create that fits was refused for memory nothing used.
//
// Each removal now drops the cache, so the next admission reads afresh. It
// never admits blind: a real runtime-only rogue is still refused (the last
// scenario), because a fresh read is still a read.

// createCT drives CreateContainer on n with the given memory cap (0: none).
func createCT(c *Cluster, n *Node, name string, memMiB int32) error {
	_, err := c.SelfClient(n).CreateContainer(context.Background(), &pb.CreateContainerRequest{
		HostName: n.Name, Name: name, Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64",
		Cpu: 1, MemoryMib: memMiB,
	})
	return err
}

// inventoryContainers makes every node's runtime inventory list its
// containers, as an LXC-capable host's does.
func inventoryContainers(c *Cluster) {
	for _, n := range c.Nodes {
		n.Server.SetLXCCapableForTest(true)
	}
}

// primeInventory makes an admission on n read (and cache) its inventory now,
// with every workload created so far there: the cache a create filled
// before them has expired (as it does after 10 s), and a create of a small,
// capped container reads it afresh.
func primeInventory(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	n.Server.InvalidateInventoryCache()
	if err := createCT(c, n, name, 64); err != nil {
		t.Fatalf("priming create %s on %s: %v", name, n.Name, err)
	}
}

// Mutation "no invalidation in DeleteContainer" — red.
func TestFleet_DeleteContainer_TheNextCreateIsNotRefusedForIt(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	inventoryContainers(c)
	n := c.Nodes[0]
	if err := createCT(c, n, "ct-uncapped", 0); err != nil {
		t.Fatalf("create the uncapped container: %v", err)
	}
	primeInventory(t, c, n, "ct-prime")
	if _, err := c.SelfClient(n).DeleteContainer(context.Background(), &pb.DeleteContainerRequest{
		HostName: n.Name, Name: "ct-uncapped",
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := createCT(c, n, "ct-next", 64); err != nil {
		t.Fatalf("create right after deleting an uncapped container on the same host: %v", err)
	}
}

// Mutation "no invalidation in the VM delete" — red.
func TestFleet_DeleteVM_TheNextCreateIsNotChargedForIt(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	n := c.Nodes[0]
	// About 5 GiB allocatable: big and small fit, and small and big-again
	// fit, but not with big charged too.
	setHostCapacity(t, c, n.Name, 8, 6144)
	if _, err := runVM(t, c, n, "big", n.Name, 1, 3072); err != nil {
		t.Fatalf("create big: %v", err)
	}
	// The admission of this create reads the inventory with big running
	// (the cache big's own create filled has expired).
	n.Server.InvalidateInventoryCache()
	if _, err := runVM(t, c, n, "small", n.Name, 1, 256); err != nil {
		t.Fatalf("create small: %v", err)
	}
	if _, err := c.SelfClient(n).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "big"}); err != nil {
		t.Fatalf("delete big: %v", err)
	}
	if _, err := runVM(t, c, n, "big-again", n.Name, 1, 3072); err != nil {
		t.Fatalf("a create that fits once big is deleted: %v", err)
	}
}

// Mutation "no invalidation on the container migrate's source" — red.
func TestFleet_MigrateContainerAway_TheNextCreateIsNotRefusedForIt(t *testing.T) {
	c := ctMigrateCluster(t)
	inventoryContainers(c)
	src, dst := c.Nodes[0], c.Nodes[1]
	if err := createCT(c, src, "ct-mover", 0); err != nil {
		t.Fatalf("create the uncapped container: %v", err)
	}
	primeInventory(t, c, src, "ct-prime")
	if err := runMigrate(t, c, src, dst, "ct-mover", stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := createCT(c, src, "ct-next", 64); err != nil {
		t.Fatalf("create on the source right after an uncapped container migrated away: %v", err)
	}
}

// Mutation "no invalidation on the VM migrate's source" — red.
func TestFleet_MigrateVMAway_TheNextCreateIsNotChargedForIt(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	setHostCapacity(t, c, src.Name, 8, 6144)
	setHostCapacity(t, c, dst.Name, 64, 65536)
	if _, err := runVM(t, c, src, "big", src.Name, 1, 3072); err != nil {
		t.Fatalf("create big: %v", err)
	}
	src.Server.InvalidateInventoryCache()
	if _, err := runVM(t, c, src, "small", src.Name, 1, 256); err != nil {
		t.Fatalf("create small: %v", err)
	}
	// As libvirt's live migration does: the guest lands on the target, and
	// the source domain is gone (VIR_MIGRATE_UNDEFINE_SOURCE).
	src.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error {
		x, err := src.Virt.DumpXML(name)
		if err != nil {
			return err
		}
		if err := dst.Virt.DefineDomain(x); err != nil {
			return err
		}
		dst.Virt.SetState(name, libvirtfake.StateRunning)
		return src.Virt.UndefineDomain(name, false)
	}
	if err := migrateAt(t, c, src, "big", dst.Name); err != nil {
		t.Fatalf("migrate big away: %v", err)
	}
	if _, err := runVM(t, c, src, "big-again", src.Name, 1, 3072); err != nil {
		t.Fatalf("a create on the source that fits once big has left: %v", err)
	}
}

// The invalidation only forces a fresh read: a real uncapped runtime-only
// container on the host is still refused after a delete — named, where the
// stale cache named the deleted one.
//
// Mutation "a removal marks the inventory clean instead of re-reading" — red.
func TestFleet_DeleteContainer_ARealRogueIsStillRefused(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	inventoryContainers(c)
	n := c.Nodes[0]
	if err := createCT(c, n, "ct-uncapped", 0); err != nil {
		t.Fatalf("create the uncapped container: %v", err)
	}
	primeInventory(t, c, n, "ct-prime")
	n.CT.Seed("rogue", "") // runtime only, no limits, no row
	if _, err := c.SelfClient(n).DeleteContainer(context.Background(), &pb.DeleteContainerRequest{
		HostName: n.Name, Name: "ct-uncapped",
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	err := createCT(c, n, "ct-next", 64)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `"rogue"`) {
		t.Fatalf("create beside an uncapped runtime-only container = %v; want refused, naming it", err)
	}
}
