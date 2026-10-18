// Fleet scenario: a start retries the rebuild of a seed an attach could not
// rewrite (lab 2 seed hot-plug proof, F4).
//
// Multi-node by construction: the attach, the restart and the stop and start
// are sent to the node that does not own the VM and reach the owner over real
// gRPC, which rebuilds its seed in its start path.
package fleet

import (
	"context"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A NIC attach whose seed rebuild on the owner fails (the seed cannot be
// read: a directory stands at its path while the attach runs) leaves the seed
// without the NIC and marked stale. Lab 2 found that a restart, or a stop and
// a start, of the defined domain then never tried again: the mark stayed and
// no warning was recorded; only the next attach or detach cleared it. Now the
// start tries the rebuild again before the domain boots: with the seed back,
// it lists B as eth1 and the mark is gone; with the seed still unreadable, the
// VM still starts and the warning is recorded again.
//
// Mutation: do not retry the rebuild on a start — "restart" and "stop, start"
// go red (B missing, mark kept), "fails again" goes red (one warning).
func TestFleet_AStartRetriesAStaleSeed(t *testing.T) {
	for _, how := range []string{"restart", "stop, start", "fails again"} {
		t.Run(how, func(t *testing.T) {
			ctx := context.Background()
			const macA = "52:54:00:5f:03:0a"
			c, isos, gates := seededVMCluster(t, true, "sr", map[string]compose.NetworkDef{
				"na": {Type: "bridge", Subnet: "10.78.0.0/24", DHCP: true},
				"nb": {Type: "bridge", Subnet: "10.79.0.0/24", DHCP: true},
			}, &pb.VMSpec{Cpu: 1, MemoryMib: 256,
				CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: sr\n"},
				Network:   []*pb.NetworkAttachment{{Name: "na", Mac: macA}}})
			home, other := c.Nodes[0], c.Nodes[1]
			iso := isos[home.Name]
			before := mustReadSeedAt(t, "home", iso)

			// The seed is unreadable while the attach runs.
			aside := iso + ".aside"
			if err := os.Rename(iso, aside); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(iso, 0o700); err != nil {
				t.Fatal(err)
			}
			b := mustAttachNIC(t, c, other, "sr", "nb")
			rebuildFailed := func() int {
				t.Helper()
				evs, err := corrosion.ListVMEvents(ctx, other.DB, "sr", 100, "")
				if err != nil {
					t.Fatal(err)
				}
				n := 0
				for _, e := range evs {
					if e.Type == "seed.rebuild_failed" && strings.Contains(e.Detail, iso) && strings.Contains(e.Detail, home.Name) {
						n++
					}
				}
				return n
			}
			if rebuildFailed() != 1 || !cloudinit.SeedMarkedStale(iso) {
				t.Fatalf("setup: the failed rebuild was not reported (%d), or left no stale mark", rebuildFailed())
			}
			if how != "fails again" {
				if err := os.Remove(iso); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(aside, iso); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(strings.ToLower(mustReadSeedAt(t, "home", iso).NetworkConfig), strings.ToLower(b.MAC)) {
					t.Fatal("setup: the seed lists B")
				}
			}

			// The fleet runs no peer-probe loop, so the real checker counts
			// one live voter of two and refuses the start with no_quorum;
			// quorum is not what this scenario is about.
			for _, n := range c.Nodes {
				n.Server.SetGate(quorumGranted{&fleetGate{Checker: gates[n.Name], reach: c.reach}})
			}
			cl := c.SelfClient(other)
			switch how {
			case "stop, start":
				if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "sr", Force: true}); err != nil {
					t.Fatalf("stop through %s: %v", other.Name, err)
				}
				if !cloudinit.SeedMarkedStale(iso) {
					t.Fatal("the stop cleared the mark; it is the start that must")
				}
				if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "sr"}); err != nil {
					t.Fatalf("start through %s: %v", other.Name, err)
				}
			default:
				if _, err := cl.RestartVM(ctx, &pb.RestartVMRequest{Name: "sr"}); err != nil {
					t.Fatalf("restart through %s: %v", other.Name, err)
				}
			}
			if st, err := home.Virt.DomainState("sr"); err != nil || st != "running" {
				t.Fatalf("sr on %s = %q (%v), want running", home.Name, st, err)
			}

			if how == "fails again" {
				if n := rebuildFailed(); n != 2 {
					t.Errorf("seed.rebuild_failed warnings = %d, want the attach's and the start's", n)
				}
				if !cloudinit.SeedMarkedStale(iso) {
					t.Error("a failed retry removed the stale mark")
				}
				return
			}
			got := mustReadSeedAt(t, "home after the start", iso)
			if !strings.Contains(strings.ToLower(got.NetworkConfig), strings.ToLower(b.MAC)+"\"\n    set-name: eth1\n") {
				t.Errorf("the start did not bring the seed up to date: want B (%s) eth1:\n%s", b.MAC, got.NetworkConfig)
			}
			if got.MetaData != before.MetaData || got.UserData != before.UserData {
				t.Errorf("the rebuild changed the seed's identity or user-data: %q %q", got.MetaData, got.UserData)
			}
			if cloudinit.SeedMarkedStale(iso) {
				t.Error("the rebuild before the start succeeded and left the stale mark")
			}
			if n := rebuildFailed(); n != 1 {
				t.Errorf("seed.rebuild_failed warnings = %d, want only the attach's", n)
			}
		})
	}
}
