package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// errNoLXCTooling is what the LXC runtime returns on a host without the lxc-*
// tooling: every list fails at the binary lookup.
var errNoLXCTooling = fmt.Errorf("lxc-ls: %w", &exec.Error{Name: "lxc-ls", Err: exec.ErrNotFound})

// withoutLXC makes n a host without the lxc-* tooling: not LXC-capable, and
// its runtime fails every list at the binary lookup.
func withoutLXC(n *Node) {
	n.Server.SetLXCCapableForTest(false)
	n.CT.FailList(errNoLXCTooling)
}

// Lab 1 netprov proof, finding 1: on a host without LXC the container list
// fails at the lookup of lxc-ls, and the holder check read that as an unknown
// running holder. A host with nothing on the network never completed a move,
// and a host with a running VM refused without naming it.
//
//   - node-1 (no LXC, nothing on the network) moves at once.
//   - node-0 (no LXC, ia running) refuses, naming VM ia and nothing unknown.
//   - Once ia stops, node-0 moves too.
//
// Mutation: read every list failure as an unknown holder again — node-1 keeps
// serving lanaa, and node-0's refusal names "(unknown: ...)".
func TestFleet_NetworkMoveOnHostsWithoutLXC(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	busy, idle := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		n.Net.SetDHCPConflicts(true)
		withoutLXC(n)
	}
	cl := c.SelfClient(busy)
	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "lanaa")); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	reconcileNetworks(t, idle)
	if got := idle.Net.Serving(); strings.Join(got, ",") != "lanaa" {
		t.Fatalf("fixture: %s serves %v, want [lanaa]", idle.Name, got)
	}

	_, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "lanbb"))
	if err == nil || !strings.Contains(err.Error(), "VM ia") {
		t.Fatalf("redeploy onto lanbb while ia runs on lanaa: err=%v, want a refusal naming VM ia", err)
	}
	if strings.Contains(err.Error(), "unknown") {
		t.Errorf("the refusal reads a host without LXC as an unknown holder: %v", err)
	}
	reconcileNetworks(t, idle)
	if got := idle.Net.Serving(); strings.Join(got, ",") != "lanbb" {
		t.Errorf("%s (no LXC, nothing on the network) serves %v, want the move done: [lanbb]", idle.Name, got)
	}
	if b, _ := idle.Net.CreatedBridges(); strings.Join(b, ",") != "lanbb" {
		t.Errorf("%s keeps bridges %v, want [lanbb]", idle.Name, b)
	}

	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "ia", Force: true}); err != nil {
		t.Fatalf("stop ia: %v", err)
	}
	reconcileNetworks(t, busy)
	if got := busy.Net.Serving(); strings.Join(got, ",") != "lanbb" {
		t.Errorf("%s serves %v once ia stopped, want [lanbb]", busy.Name, got)
	}
	if b, _ := busy.Net.CreatedBridges(); strings.Join(b, ",") != "lanbb" {
		t.Errorf("%s keeps bridges %v once ia stopped, want [lanbb]", busy.Name, b)
	}
}

// A host whose LXC probe says it runs containers but whose lxc-ls is missing
// may have running containers on the old device, so its not-found list
// failure holds the move: it keeps serving lanaa, and names what it could not
// read.
//
// Mutation: drop the runsContainers check — node-1 moves to lanbb.
func TestFleet_NetworkMoveHeldOnAnLXCHostWithoutLxcLs(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	busy, capable := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		n.Net.SetDHCPConflicts(true)
	}
	withoutLXC(busy)
	cl := c.SelfClient(busy)
	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "lanaa")); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	reconcileNetworks(t, capable)
	if got := capable.Net.Serving(); strings.Join(got, ",") != "lanaa" {
		t.Fatalf("fixture: %s serves %v, want [lanaa]", capable.Name, got)
	}
	capable.Server.SetLXCCapableForTest(true)
	capable.CT.FailList(errNoLXCTooling)

	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "lanbb")); err == nil {
		t.Fatal("redeploy onto lanbb while ia runs on lanaa was not refused")
	}
	reconcileNetworks(t, capable)
	if got := capable.Net.Serving(); strings.Join(got, ",") != "lanaa" {
		t.Errorf("%s (LXC-capable, lxc-ls missing) serves %v, want the move held: [lanaa]", capable.Name, got)
	}
	if b, _ := capable.Net.CreatedBridges(); !strings.Contains(strings.Join(b, ","), "lanaa") {
		t.Errorf("%s keeps bridges %v, want lanaa kept", capable.Name, b)
	}
}

// Lab 1 netprov proof, finding 1: `compose down` after a move that hosts
// refused (a VM ran on the old device) left the old bridge, its dnsmasq and
// the pending retirement behind on every refusing host without LXC. Down
// retires them on each refusing host, with LXC or without.
//
// Mutation: read every list failure as an unknown holder again — the no-LXC
// case keeps lanaa serving after the down.
func TestFleet_ComposeDownAfterARefusedMoveRetiresTheOldDevice(t *testing.T) {
	for _, tc := range []struct {
		name  string
		noLXC bool
	}{
		{"lxc", false},
		{"no lxc", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			ctx := context.Background()
			seedTestImageEverywhere(t, c)
			statePath := map[string]string{}
			for _, n := range c.Nodes {
				statePath[n.Name] = filepath.Join(t.TempDir(), "network-devices.json")
				n.Server.SetNetworkDeviceStatePath(statePath[n.Name])
				n.Net.SetDHCPConflicts(true)
				if tc.noLXC {
					withoutLXC(n)
				}
			}
			cl := c.SelfClient(c.Nodes[0])
			if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChange, "IFACE", "lanaa")); err != nil {
				t.Fatalf("first deploy: %v", err)
			}
			if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChange, "IFACE", "lanbb")); err == nil {
				t.Fatal("redeploy onto lanbb with a VM running on lanaa on each node was not refused")
			}
			for _, n := range c.Nodes {
				reconcileNetworks(t, n)
				if got := n.Net.Serving(); strings.Join(got, ",") != "lanaa" {
					t.Fatalf("fixture: %s serves %v after the refused move, want [lanaa]", n.Name, got)
				}
				if p := pendingRetires(t, statePath[n.Name]); strings.Join(p, ",") != "lanaa" {
					t.Fatalf("fixture: %s pending retirements %v after the refused move, want [lanaa]", n.Name, p)
				}
			}

			stream, err := cl.DeleteStack(ctx, &pb.DeleteStackRequest{Name: "ic"})
			if err != nil {
				t.Fatalf("DeleteStack: %v", err)
			}
			for {
				_, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("DeleteStack stream: %v", err)
				}
			}
			for _, n := range c.Nodes {
				reconcileNetworks(t, n)
				if got := n.Net.Serving(); len(got) != 0 {
					t.Errorf("%s still serves %v after compose down", n.Name, got)
				}
				if b, _ := n.Net.CreatedBridges(); len(b) != 0 {
					t.Errorf("%s keeps bridges %v after compose down", n.Name, b)
				}
				if p := pendingRetires(t, statePath[n.Name]); len(p) != 0 {
					t.Errorf("%s keeps pending retirements %v after compose down", n.Name, p)
				}
			}
		})
	}
}

// pendingRetires reads the devices waiting to be retired from a host's
// network device record at path.
func pendingRetires(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var st struct {
		Pending map[string]json.RawMessage `json:"pending"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for d := range st.Pending {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// A container list that fails for any other reason than a missing runtime
// still holds the move (fail closed), and the refusal names the VM on the old
// device beside what could not be read.
//
// Mutations: read every list failure as no runtime — nothing unknown is
// named; drop the VMs read when the list fails — the refusal names no VM.
func TestFleet_NetworkMoveRefusalNamesTheVMWhenTheContainerListFails(t *testing.T) {
	c := New(t, Options{Nodes: 1, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	n := c.Nodes[0]
	n.Net.SetDHCPConflicts(true)
	cl := c.SelfClient(n)
	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "lanaa")); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	n.CT.FailList(errors.New("lxc-ls: exit status 1"))
	_, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "lanbb"))
	for _, want := range []string{"VM ia", "unknown: list the containers", "lanaa"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("redeploy onto lanbb while the containers cannot be read: err=%v, want a refusal containing %q", err, want)
		}
	}
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanaa" {
		t.Errorf("serving %v while the containers cannot be read, want [lanaa] kept", got)
	}
}
