package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Catalog birth incarnations across a real fleet (corrosion
// catalog_incarnation.go): an image's and a pool's birth replicates to every
// node, a re-create is a new lifetime everywhere, and an ordinary write keeps
// the lifetime everywhere.

// latchCatalogRelease latches the release token catalog_incarnation is under
// on every node, the HA monitor's job in production.
func latchCatalogRelease(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	for _, n := range c.Nodes {
		n := n
		eventually(t, 10*time.Second, n.Name+" to latch "+capabilities.Release202702V1, func() bool {
			return gates[n.Name].Enforced(context.Background(), capabilities.Release202702V1) &&
				gates[n.Name].DurablyLatched(capabilities.Release202702V1)
		})
	}
}

// sameBirthEverywhere waits until every node holds one born incarnation for
// what, and returns it.
func sameBirthEverywhere(t *testing.T, c *Cluster, what string, birth func(*Node) (string, error)) string {
	t.Helper()
	var got map[string]string
	ok := catalogWaitFor(30*time.Second, func() bool {
		got = map[string]string{}
		var first string
		for i, n := range c.Nodes {
			inc, err := birth(n)
			if err != nil || !corrosion.ValidCatalogIncarnation(inc) {
				return false
			}
			got[n.Name] = inc
			if i == 0 {
				first = inc
			} else if inc != first {
				return false
			}
		}
		return true
	})
	if !ok {
		t.Fatalf("%s: the nodes never agreed on one born incarnation: %v", what, got)
	}
	return got[c.Nodes[0].Name]
}

func catalogWaitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

func imageBirthOn(name string) func(*Node) (string, error) {
	return func(n *Node) (string, error) {
		b, err := corrosion.ImageBirthOf(context.Background(), n.DB, name)
		return b.Incarnation, err
	}
}

func poolBirthOn(host, name string) func(*Node) (string, error) {
	return func(n *Node) (string, error) {
		b, err := corrosion.StoragePoolBirthOf(context.Background(), n.DB, host, name)
		return b.Incarnation, err
	}
}

// Mutation: write the previous release's pair for an operator's record
// (recordImageRow always taking corrosion.RecordImage) — red: no node ever
// holds a born incarnation.
func TestFleet_CatalogBirth_ImageLifetimesReplicate(t *testing.T) {
	c, gates := latchedFleet(t, 3, 1025)
	latchCatalogRelease(t, c, gates)
	imageRmFleet(c)
	n0, n1 := c.Nodes[0], c.Nodes[1]

	importImageOn(t, c, n0, "ubuntu")
	first := sameBirthEverywhere(t, c, "first import", imageBirthOn("ubuntu"))
	if !featureUsedOn(t, n0, capabilities.Release202702V1, string(capabilities.FeatureCatalogIncarnation)) {
		t.Error("the birth recorded no use of catalog_incarnation")
	}

	// A re-import over the live image is the same lifetime.
	importImageOn(t, c, n1, "ubuntu")
	if again := sameBirthEverywhere(t, c, "re-import", imageBirthOn("ubuntu")); again != first {
		t.Fatalf("a re-import over the live image changed its lifetime: %s -> %s", first, again)
	}

	if _, err := c.SelfClient(n0).RemoveImage(context.Background(), &pb.RemoveImageRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		n := n
		eventually(t, 30*time.Second, n.Name+" to hold the image deleted", func() bool {
			_, err := corrosion.ImageBirthOf(context.Background(), n.DB, "ubuntu")
			return errors.Is(err, corrosion.ErrCatalogNoBirth)
		})
	}
	importImageOn(t, c, n1, "ubuntu")
	second := sameBirthEverywhere(t, c, "re-create", imageBirthOn("ubuntu"))
	if corrosion.CompareCatalogIncarnations(second, first) <= 0 {
		t.Fatalf("a deleted and re-created image kept or regressed its lifetime: %s -> %s", first, second)
	}
}

// Before the release latches, an import records no birth: ” is refused by
// the consume API on every node.
func TestFleet_CatalogBirth_NoBirthBeforeTheLatch(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	importImageOn(t, c, c.Nodes[0], "ubuntu")
	for _, n := range c.Nodes {
		n := n
		eventually(t, 30*time.Second, n.Name+" to hold the image", func() bool {
			r, err := corrosion.GetImage(context.Background(), n.DB, "ubuntu")
			return err == nil && r != nil
		})
		if _, err := corrosion.ImageBirthOf(context.Background(), n.DB, "ubuntu"); !errors.Is(err, corrosion.ErrCatalogNoBirth) {
			t.Fatalf("%s: an unlatched import: %v, want ErrCatalogNoBirth", n.Name, err)
		}
	}
}

// A pool's birth on its host replicates with the host's incarnation; a
// capacity refresh keeps it; a delete and re-create is a new lifetime.
//
// Mutation: UpdateStoragePool giving birth over a tombstone (catalogMutate
// treated as catalogBirth) — red at "to hold the pool deleted".
func TestFleet_CatalogBirth_PoolLifetimesReplicate(t *testing.T) {
	c, gates := latchedFleet(t, 3, 1026)
	latchCatalogRelease(t, c, gates)
	ctx := context.Background()
	n0 := c.Nodes[0]
	target := t.TempDir()
	create := func() {
		t.Helper()
		if _, err := c.SelfClient(n0).CreateStoragePool(ctx, &pb.CreateStoragePoolRequest{
			Name: "fast", Driver: "dir", Target: target, Host: n0.Name,
		}); err != nil {
			t.Fatalf("CreateStoragePool: %v", err)
		}
	}
	create()
	first := sameBirthEverywhere(t, c, "pool create", poolBirthOn(n0.Name, "fast"))
	for _, n := range c.Nodes {
		b, err := corrosion.StoragePoolBirthOf(ctx, n.DB, n0.Name, "fast")
		if err != nil || b.HostName != n0.Name || b.Target != target {
			t.Fatalf("%s: pool birth %+v %v", n.Name, b, err)
		}
	}

	// The daemon's capacity refresh, through the same writer.
	rec, ok, err := corrosion.GetStoragePool(ctx, n0.DB, n0.Name, "fast")
	if err != nil || !ok {
		t.Fatalf("pool row: %v %v", ok, err)
	}
	rec.TotalBytes, rec.UsedBytes = 1<<30, 1<<20
	if err := corrosion.WriteStoragePool(ctx, n0.DB, gates[n0.Name], rec); err != nil {
		t.Fatal(err)
	}
	if again := sameBirthEverywhere(t, c, "capacity refresh", poolBirthOn(n0.Name, "fast")); again != first {
		t.Fatalf("a capacity refresh changed the pool's lifetime: %s -> %s", first, again)
	}

	if _, err := c.SelfClient(n0).DeleteStoragePool(ctx, &pb.DeleteStoragePoolRequest{Name: "fast", Host: n0.Name}); err != nil {
		t.Fatalf("DeleteStoragePool: %v", err)
	}
	// A refresh that raced the delete never brings the pool back.
	if err := corrosion.UpdateStoragePool(ctx, n0.DB, rec); err != nil {
		t.Fatalf("refresh after the delete: %v", err)
	}
	for _, n := range c.Nodes {
		n := n
		eventually(t, 30*time.Second, n.Name+" to hold the pool deleted", func() bool {
			_, ok, _ := corrosion.GetStoragePool(ctx, n.DB, n0.Name, "fast")
			return !ok
		})
	}
	create()
	second := sameBirthEverywhere(t, c, "pool re-create", poolBirthOn(n0.Name, "fast"))
	if corrosion.CompareCatalogIncarnations(second, first) <= 0 {
		t.Fatalf("a deleted and re-created pool kept or regressed its lifetime: %s -> %s", first, second)
	}
}
