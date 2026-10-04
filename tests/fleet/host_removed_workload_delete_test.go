// Fleet scenario: a workload still recorded on a host removed for good can be
// deleted.
//
// On the kvm003 lab (drill 6, main-e004c250) `lv rm --force app` failed with
// "cannot reach host node-3" and `lv ct rm blct --host node-4` with "forward:
// look up host node-4: not found in cluster state or gossip". Both delete
// paths forward to the workload's recorded host, and a removed host has no
// address left to dial. So the exit the re-admission refusal named, removing
// the workloads, did not exist, and the name could not be added back.
//
// A removed host is revoked and never returns, so there is nothing to stop or
// free on it: the delete is a cluster-side delete of the rows, audited, with
// no forward.
package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// removeForGood kills d, records an operator's confirmation that it is off,
// removes it with `lv host rm --dead` through by, and waits for the survivors
// to adopt the voter generation without it and install the CRL.
func removeForGood(t *testing.T, c *Cluster, by, d *Node, survivors ...*Node) {
	t.Helper()
	ctx := context.Background()
	c.Kill(d)
	if err := corrosion.InsertFenceLog(ctx, by.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, by.DB, d.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	withOperatorPKI(t, by)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(by), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	adoptAll(t, c, 2, survivors...)
	c.WaitConverged(t, convergeTimeout, survivors...)
	syncCRL(t, survivors...)
}

// auditedOn reports whether n's audit log holds an ok row for action on
// target whose detail mentions want.
func auditedOn(t *testing.T, n *Node, action, target, want string) bool {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT detail FROM audit_log WHERE action = ? AND target = ? AND result = 'ok'`, action, target)
	if err != nil {
		t.Fatalf("%s: read audit log: %v", n.Name, err)
	}
	for _, r := range rows {
		if strings.Contains(r.String("detail"), want) {
			return true
		}
	}
	return false
}

// TestFleet_DeleteAWorkloadOnARemovedHost: d is removed for good with vm-old
// and ct old-ct recorded on it. `lv rm vm-old` and `lv ct rm old-ct` (by name,
// and the container again by --host) delete the rows on every replica with no
// forward to d, each audited as a delete on a removed host, and d's name can
// then be added back.
//
// Mutation: drop the removed-host branch in DeleteVM — the delete forwards to
// d and fails Unavailable; drop it in DeleteContainer — the same for the
// container.
func TestFleet_DeleteAWorkloadOnARemovedHost(t *testing.T) {
	for _, byHost := range []bool{false, true} {
		name := "by-name"
		if byHost {
			name = "by-host"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2608})
			a, b, e, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
			insertVM(t, a, "vm-old", d.Name)
			putContainer(t, d, "old-ct", "docker.io/library/alpine:3.19", "none")
			c.WaitConverged(t, convergeTimeout)
			genesisByTick(t, c, a)
			enableRecoveryClaims(t, c)
			survivors := []*Node{a, b, e}
			removeForGood(t, c, a, d, survivors...)

			if _, err := c.SelfClient(a).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-old"}); err != nil {
				t.Fatalf("lv rm vm-old, recorded on removed %s: %v", d.Name, err)
			}
			req := &pb.DeleteContainerRequest{Name: "old-ct"}
			if byHost {
				req.HostName = d.Name
			}
			if _, err := c.SelfClient(a).DeleteContainer(ctx, req); err != nil {
				t.Fatalf("lv ct rm old-ct (host %q), recorded on removed %s: %v", req.HostName, d.Name, err)
			}
			c.WaitConverged(t, convergeTimeout, survivors...)
			for _, n := range survivors {
				if vm, _ := corrosion.GetVM(ctx, n.DB, "vm-old"); vm != nil {
					t.Errorf("%s still has vm-old live: %+v", n.Name, vm)
				}
				if hosts := liveContainerHosts(t, n, "old-ct"); len(hosts) != 0 {
					t.Errorf("%s still has old-ct live on %v", n.Name, hosts)
				}
			}
			if !auditedOn(t, a, "vm.delete", "vm-old", "removed host "+d.Name) {
				t.Error("no vm.delete audit row naming the removed host")
			}
			if !auditedOn(t, a, "ct.delete", "old-ct", "removed host "+d.Name) {
				t.Error("no ct.delete audit row naming the removed host")
			}

			if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
				Name: d.Name, Address: d.Address, CertSerial: "0a0b0c0d0e0f",
			}); err != nil {
				t.Fatalf("admit %s once its workloads are deleted: %v", d.Name, err)
			}
		})
	}
}
