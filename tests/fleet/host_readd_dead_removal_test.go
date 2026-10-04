package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_DeadRemovalOfAReaddedHostNeedsItsOwnFence: `lv host rm --dead`
// removes only a host proven off, and the proof must be of the host as it is
// now. d is confirmed off and removed for good, then `lv host add` gives its
// name to a new machine. The old machine's confirmation is still in
// fencing_log under the name, and HostProofGradeFence used to accept a row of
// any age, so a removal of the NEW machine — joining, or booted and since
// gone offline unfenced — went through on the old machine's proof.
//
// It must be refused at both boundaries: the plan the CLI checks first, and
// RemoveHost itself. Once the new machine is fence-confirmed, it is removed.
//
// Mutations: dropping the life cutoff from HostProofGradeFence lets the
// joining and the offline removal through; cutting a 'fenced' host's rows
// too (no exemption) refuses the old machine's own removal, whose
// confirmation is a minute older than its 'fenced' write.
func TestFleet_DeadRemovalOfAReaddedHostNeedsItsOwnFence(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 3407})
	a, d := c.Nodes[0], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	c.WaitConverged(t, convergeTimeout)
	d.Stop()
	c.Kill(d)
	withOperatorPKI(t, a)

	// The old machine: confirmed off a minute ago, and removed for good.
	if err := a.DB.Execute(ctx,
		`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		"confirm-old-"+d.Name, d.Name, "manual", "manual-confirmed",
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "operator confirmation"); err != nil {
		t.Fatalf("fence-confirm %s: %v", d.Name, err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatalf("record %s fenced: %v", d.Name, err)
	}
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s (the old machine, confirmed off): %v", d.Name, err)
	}

	// `lv host add`: a new machine under the name, with its own certificate.
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: "0a0b0c0d0e0f",
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}

	refused := func(stage string) {
		t.Helper()
		plan, err := c.SelfClient(a).PlanDeadHostRemoval(ctx, &pb.PlanDeadHostRemovalRequest{Name: d.Name})
		if err != nil {
			t.Fatalf("%s: plan: %v", stage, err)
		}
		if plan.GetFenced() {
			t.Errorf("%s: the plan counts the removed machine's fence as the new one's: %s", stage, plan.GetFenceDetail())
		}
		if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err == nil {
			t.Fatalf("%s: lv host rm --dead removed the new machine on the old machine's fence", stage)
		}
		_, err = c.SelfClient(a).RemoveHost(ctx, &pb.RemoveHostRequest{Name: d.Name, Dead: true})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%s: RemoveHost --dead: got %v, want FailedPrecondition", stage, err)
		}
		if msg := status.Convert(err).Message(); !strings.Contains(msg, "fence-confirm "+d.Name) {
			t.Errorf("%s: the refusal %q does not name the fix", stage, msg)
		}
		if h, err := corrosion.GetHost(ctx, a.DB, d.Name); err != nil || h == nil {
			t.Fatalf("%s: the new machine's row is gone: %v", stage, err)
		}
	}

	// Joining: nothing of the new machine has been proven.
	refused("joining")

	// Booted, then lost without a proof-grade fence: its boot write records it
	// active, and the coordinator's unproven fence leaves it offline.
	if err := corrosion.UpdateHostStartup(ctx, a.DB, d.Name, "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "offline"); err != nil {
		t.Fatalf("record %s offline: %v", d.Name, err)
	}
	refused("offline")

	// The new machine's own confirmation is what removes it.
	if _, err := c.SelfClient(a).FenceHost(ctx, &pb.FenceHostRequest{
		Name: d.Name, Confirmed: true, ConfirmManualOnly: true,
	}); err != nil {
		t.Fatalf("fence-confirm the new %s: %v", d.Name, err)
	}
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s after its own confirmation: %v", d.Name, err)
	}
}
