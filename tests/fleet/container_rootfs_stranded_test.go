// Fleet scenario: a container relocated off a failed host leaves its own
// rootfs there. Nothing deletes it (and a relocation back adopts it), but
// before this nothing said so: the relocated container is a fresh instance of
// its image on the new host, and its data was on the failed host, unrecorded.
// Surface only: the adopt and delete behaviour is unchanged.

package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Mutations: record nothing in the coordinator — no record, no inspect line,
// and the test is red; skip the path fill-in on the returning host — the
// record never names the rootfs path and the test is red; drop the adopt
// note — no ct.relocate.adopted audit row and the record stays open, red;
// record a relocation the source never carried out (a pending row) — the
// host web was relocated to first, which never ran it, is named and the test
// is red.
func TestFleet_ContainerRelocationSurfacesTheRootfsItLeftBehind(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()
	ctx := context.Background()
	other, home, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	home.CT.Seed("web", "web's real data")
	if err := corrosion.UpsertContainer(ctx, coord.DB, corrosion.ContainerRecord{
		HostName: home.Name, Name: "web", Image: "docker.io/library/nginx:1.27", State: "running",
		OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatal(err)
	}

	// home fails: web is re-homed and recreated from its image elsewhere.
	if got := fenceVictim(t, c, coord, home, other, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	host, rec := findContainer(t, c, "web")
	if rec == nil || host == home.Name {
		t.Fatalf("web was not relocated off %s (host %q)", home.Name, host)
	}
	got, err := health.StrandedRootfsOf(ctx, coord.DB, "web")
	if err != nil || len(got) != 1 || got[0].Host != home.Name || got[0].MovedTo != host {
		t.Fatalf("stranded rootfs records = %+v (err %v), want one naming %s", got, err, home.Name)
	}
	d, err := c.SelfClient(coord).InspectContainer(ctx, &pb.InspectContainerRequest{Name: "web", HostName: host})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if len(d.StrandedRootfs) != 1 || d.StrandedRootfs[0].Host != home.Name {
		t.Fatalf("inspect shows %+v, want the rootfs left on %s", d.StrandedRootfs, home.Name)
	}

	// home is back: its sweep records where the rootfs is, and touches
	// nothing.
	if err := coord.DB.Execute(ctx, `UPDATE hosts SET state = 'active', updated_at = ? WHERE name = ?`, coord.DB.NowTS(), home.Name); err != nil {
		t.Fatal(err)
	}
	homeCC := health.NewContainerChecker(home.Name, home.DB, home.CT.LXC())
	homeCC.SweepOnce(ctx)
	got, _ = health.StrandedRootfsOf(ctx, coord.DB, "web")
	if len(got) != 1 || got[0].Path == "" {
		t.Fatalf("records after %s came back = %+v, want the rootfs path named", home.Name, got)
	}
	if home.CT.Payload("web") != "web's real data" {
		t.Fatal("the rootfs left on home was changed")
	}

	// Relocated back onto home, the old rootfs is adopted (as before) and
	// that is now said: an audit row, and the record clears.
	if err := coord.DB.Execute(ctx, `DELETE FROM host_health WHERE target = ?`, home.Name); err != nil {
		t.Fatal(err)
	}
	if got := fenceVictim(t, c, coord, c.Node(host), home, coord); got != 1 {
		t.Fatalf("second fencer fired %d times, want 1", got)
	}
	homeCC.SweepOnce(ctx)
	if home.CT.Payload("web") != "web's real data" {
		t.Fatal("the adopted rootfs lost its data")
	}
	rows, err := coord.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'ct.relocate.adopted' AND target = 'web'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("ct.relocate.adopted audit rows = %d (err %v), want 1", len(rows), err)
	}
	if got, _ := health.StrandedRootfsOf(ctx, coord.DB, "web"); len(got) != 0 {
		t.Fatalf("records after the adopt = %+v, want none open", got)
	}
}
