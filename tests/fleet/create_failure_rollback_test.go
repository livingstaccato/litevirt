// Fleet scenarios for a VM create that cannot finish (lab 2, 2026-10-16,
// F-A and F-B). A create that fails once its domain is defined must leave
// nothing behind — no domain, no disks, no guard records, no NIC rows — and
// say so to the client; a name whose earlier create failed must be usable
// again; and two NICs on one network, which the VM's NIC record cannot hold,
// is refused before anything is created.

package fleet

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// guardedCreateNode is a one-node fleet whose node records NIC guards and
// arms them before every start, as the daemon does.
func guardedCreateNode(t *testing.T) (*Cluster, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	openNICGuards(t, n)
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	wireNodeFirewall(t, n)
	return c, n
}

// createWithDisk creates VM name pinned to n, with a data disk and one NIC
// per network in nets.
func createWithDisk(c *Cluster, n *Node, name string, nets ...string) (*pb.VM, error) {
	atts := make([]*pb.NetworkAttachment, 0, len(nets))
	for _, net := range nets {
		atts = append(atts, &pb.NetworkAttachment{Name: net})
	}
	return c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256,
		Placement: &pb.PlacementSpec{Host: n.Name},
		Disks:     []*pb.DiskSpec{{Name: "data", Size: "64M"}},
		Network:   atts,
	}})
}

// diskFilesOf is the disk files of VM name under n's data dir.
func diskFilesOf(t *testing.T, n *Node, name string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(n.Server.DataDir(), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), name+"-") && strings.HasSuffix(d.Name(), ".qcow2") {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", n.Server.DataDir(), err)
	}
	return out
}

// liveGuardsOf is the MACs of the live guard records of VM name on n.
func liveGuardsOf(t *testing.T, n *Node, name string) []string {
	t.Helper()
	all, err := corrosion.ListNICGuards(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("ListNICGuards: %v", err)
	}
	var out []string
	for _, r := range all {
		if r.VMName == name {
			out = append(out, r.MAC)
		}
	}
	return out
}

// assertNothingOf fails t if n holds anything of VM name: a domain, a disk
// file, a VM row, a live NIC row or a live guard record.
func assertNothingOf(t *testing.T, n *Node, name string) {
	t.Helper()
	ctx := context.Background()
	if n.Virt.DomainExists(name) {
		t.Errorf("a domain of %s is left on %s", name, n.Name)
	}
	if files := diskFilesOf(t, n, name); len(files) != 0 {
		t.Errorf("disk files of %s are left: %v", name, files)
	}
	if vm, err := corrosion.GetVM(ctx, n.DB, name); err != nil || vm != nil {
		t.Errorf("VM row of %s: %v, %v", name, vm, err)
	}
	if nics, err := corrosion.MergedVMNICs(ctx, n.DB, name); err != nil || len(nics) != 0 {
		t.Errorf("live NIC rows of %s: %v, %v", name, nics, err)
	}
	if macs := liveGuardsOf(t, n, name); len(macs) != 0 {
		t.Errorf("live guard records of %s are left: %v", name, macs)
	}
}

// TestFleet_CreateVM_TwoNICsOnOneNetworkRefusedBeforeAnything (F-A): the
// create is refused as invalid before anything is created, rather than
// starting a domain whose NIC records then collide and leaving it running
// with no VM row.
func TestFleet_CreateVM_TwoNICsOnOneNetworkRefusedBeforeAnything(t *testing.T) {
	c, n := guardedCreateNode(t)

	_, err := createWithDisk(c, n, "dup", "lan", "lan")
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "one NIC per network") {
		t.Fatalf("two NICs on one network: got %v, want InvalidArgument naming the rule", err)
	}
	for _, ev := range n.Virt.EventLog() {
		if ev.Domain == "dup" {
			t.Errorf("libvirt was asked to %s the refused VM", ev.Op)
		}
	}
	assertNothingOf(t, n, "dup")

	// The same VM with its NICs on two networks is created.
	if _, err := createWithDisk(c, n, "dup", "lan", "lan2"); err != nil {
		t.Fatalf("two NICs on two networks: %v", err)
	}
}

// TestFleet_CreateVM_FailureAfterDefineRollsBack (F-A, F-B): a create that
// fails after its domain is defined — at the first start, or when its VM row
// cannot be written once the domain runs — undoes everything it made and
// fails at the client. The name is then created again as if the failed
// create never happened.
func TestFleet_CreateVM_FailureAfterDefineRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func(t *testing.T, n *Node) func()
	}{
		{"start fails", func(t *testing.T, n *Node) func() {
			n.Virt.FailStartDomain = func(string) error { return errors.New("induced start failure") }
			return func() { n.Virt.FailStartDomain = nil }
		}},
		{"record write fails", func(t *testing.T, n *Node) func() {
			return n.FailVMRowWrites(t)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, n := guardedCreateNode(t)
			clear := tc.inject(t, n)

			_, err := createWithDisk(c, n, "web", "lan")
			if err == nil {
				t.Fatal("the create succeeded with the failure injected")
			}
			if status.Code(err) == codes.NotFound {
				t.Fatalf("the client got NotFound, not the create's failure: %v", err)
			}
			defined := false
			for _, ev := range n.Virt.EventLog() {
				defined = defined || (ev.Domain == "web" && ev.Op == "define")
			}
			if !defined {
				t.Fatal("the domain was never defined, so the failure is not after the define")
			}
			assertNothingOf(t, n, "web")

			clear()
			if _, err := createWithDisk(c, n, "web", "lan"); err != nil {
				t.Fatalf("create of the name again: %v", err)
			}
			if st, _ := n.Virt.DomainState("web"); st != "running" {
				t.Fatalf("the re-created VM is %q, want running", st)
			}
		})
	}
}

// TestFleet_CreateVM_StaleGuardRecordsDoNotBlockTheName (F-B): guard records
// a failed create of an earlier build left live, of another incarnation of
// the name, are not demanded in force by a new create of it: they guard
// nothing the firewall renders for the new VM.
func TestFleet_CreateVM_StaleGuardRecordsDoNotBlockTheName(t *testing.T) {
	c, n := guardedCreateNode(t)
	ctx := context.Background()
	const staleMAC = "52:54:00:ee:00:01"
	if err := corrosion.PutNICGuard(ctx, n.DB, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
		corrosion.NICGuardRecord{VMName: "web", MAC: staleMAC, Mode: corrosion.NICGuardOn,
			VMUUID: "0f0f0f0f-0000-4000-8000-000000000001", Network: "lan"}, "admin"); err != nil {
		t.Fatalf("seed the stale record: %v", err)
	}

	if _, err := createWithDisk(c, n, "web", "lan"); err != nil {
		t.Fatalf("create of a name with a stale guard record: %v", err)
	}
	if st, _ := n.Virt.DomainState("web"); st != "running" {
		t.Fatalf("the VM is %q, want running", st)
	}
	// Its own guard was demanded and is in force: the stale record was
	// skipped, not every record.
	macs, err := corrosion.GuardedMACsOf(ctx, n.DB, "web")
	if err != nil || len(macs) != 1 || macs[0] == staleMAC {
		t.Fatalf("guarded MACs of the new VM = %v, %v; want its own one", macs, err)
	}
	// The delete of the name retires every record of it, the stale one too.
	if err := deleteVM(c, n, "web"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if left := liveGuardsOf(t, n, "web"); len(left) != 0 {
		t.Errorf("live guard records of web after its delete: %v", left)
	}
}
