// Fleet scenarios: where a rebuild or a rolling recreate puts a VM with an
// installer ISO, and who judges that ISO before the VM is torn down.
//
// Main placed the re-created VM with the cluster's placement rules after the
// teardown (RebuildVM → CreateVM → placement.Select, vm.go:3145 and :212 at
// 3e4ba50b; recreateAs → CreateVM, stacks_rolling.go:47 at 3e4ba50b). This
// build places it the same way BEFORE the teardown, has the chosen host judge
// the ISO as the create there will, and refuses with the VM intact when that
// host would refuse it. Only a real fleet reaches this: the placement, the
// judgement on another host and the forwarded create are different daemons.
//
// Forwarded identity is not reachable here: every fleet node dials loopback,
// and a loopback peer is local-root, which is never promoted to the relayed
// user. internal/grpcapi/iso_recreate_placement_test.go drives the same
// rebuild and recreate against a second host that judges the relayed
// Operator.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// isoFleet is a three-node shared-state fleet with an optical image at a host
// path every node can read (they share one filesystem).
type isoFleet struct {
	c   *Cluster
	iso string
}

func newISOFleet(t *testing.T) *isoFleet {
	t.Helper()
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	dir := filepath.Join(c.tmpRoot, "media")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	iso := filepath.Join(dir, "win.iso")
	writeOptical(t, iso)
	return &isoFleet{c: c, iso: iso}
}

// writeOptical writes a file with an ISO-9660 volume descriptor, which is
// what a host judges an installer ISO by.
func writeOptical(t *testing.T, path string) {
	t.Helper()
	b := make([]byte, 0x8800)
	copy(b[0x8000:], "\x01CD001\x01")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *isoFleet) label(t *testing.T, host, k, v string) {
	t.Helper()
	if err := corrosion.SetHostLabel(context.Background(), f.c.Nodes[0].DB, host, k, v); err != nil {
		t.Fatalf("label %s %s=%s: %v", host, k, v, err)
	}
}

func (f *isoFleet) setHostState(t *testing.T, host, state string) {
	t.Helper()
	if err := f.c.Nodes[0].DB.Execute(context.Background(), `UPDATE hosts SET state = ? WHERE name = ?`, state, host); err != nil {
		t.Fatal(err)
	}
}

func (f *isoFleet) vm(t *testing.T, name string) *corrosion.VMRecord {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), f.c.Nodes[0].DB, name)
	if err != nil || rec == nil {
		t.Fatalf("VM %q is gone (%v)", name, err)
	}
	return rec
}

func specOf(t *testing.T, rec *corrosion.VMRecord) *pb.VMSpec {
	t.Helper()
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(rec.Spec), spec); err != nil {
		t.Fatalf("parse spec of %s: %v", rec.Name, err)
	}
	return spec
}

// createOn creates an Admin's VM `name` with installer ISO iso on host, then
// takes the pin out of its stored spec: a VM that placement put there, which
// a rebuild places again.
func (f *isoFleet) createOn(t *testing.T, host *Node, name, iso string) *corrosion.VMRecord {
	t.Helper()
	ctx := context.Background()
	if _, err := f.c.SelfClient(host).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256, Iso: iso,
		Placement: &pb.PlacementSpec{Host: host.Name},
	}}); err != nil {
		t.Fatalf("CreateVM %s on %s: %v", name, host.Name, err)
	}
	rec := f.vm(t, name)
	spec := specOf(t, rec)
	spec.Placement = nil
	b, _ := json.Marshal(spec)
	if err := host.DB.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = ?`, string(b), name); err != nil {
		t.Fatal(err)
	}
	return f.vm(t, name)
}

// recreateOn runs a rolling recreate of name to desired on node n, as the
// caller of client (whose bearer, if any, n relays to the peers it reaches).
// The rolling engine's recreate is serverOps.RecreateVM; a compose file never
// carries an installer ISO into a desired spec (compose `iso:` is an image),
// so the test drives that entry point itself, inside one of n's RPCs so it
// runs with the caller's authenticated context.
func recreateOn(t *testing.T, n *Node, client pb.LiteVirtClient, name string, desired *pb.VMSpec) error {
	t.Helper()
	var rerr error
	ran := false
	n.HookUnary("ListVMs", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		ran = true
		rerr = n.Server.RecreateVMForTest(ctx, name, desired)
		return handler(ctx, req)
	})
	if _, err := client.ListVMs(context.Background(), &pb.ListVMsRequest{}); err != nil {
		t.Fatalf("ListVMs on %s: %v", n.Name, err)
	}
	if !ran {
		t.Fatalf("the recreate on %s did not run", n.Name)
	}
	return rerr
}

// A rolling recreate of two ISO VMs, on two different hosts, run from a
// third: each is re-created where the cluster's placement rules put it — here
// the one host its required label allows, the host it is on — and not on the
// node running the rollout, which carries neither label.
//
// Red against e287bc8b: the re-create was pinned to the rollout node, which
// placement does not admit, so the recreate was refused.
func TestFleet_ARollingRecreateOfISOVMsLandsWherePlacementPutsThem(t *testing.T) {
	f := newISOFleet(t)
	ctx := context.Background()
	n0, n1, n2 := f.c.Nodes[0], f.c.Nodes[1], f.c.Nodes[2]
	f.label(t, n0.Name, "rack", "a")
	f.label(t, n1.Name, "rack", "b")
	vms := []struct {
		vm, rack string
		host     *Node
	}{{"isa", "a", n0}, {"isb", "b", n1}}
	before := map[string]string{}
	desired := map[string]*pb.VMSpec{}
	for _, v := range vms {
		rec := f.createOn(t, v.host, v.vm, f.iso)
		spec := specOf(t, rec)
		before[v.vm] = spec.GetUuid()
		spec.Placement = &pb.PlacementSpec{Require: map[string]string{"rack": v.rack}}
		b, _ := json.Marshal(spec)
		if err := n0.DB.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = ?`, string(b), v.vm); err != nil {
			t.Fatal(err)
		}
		d := proto.Clone(spec).(*pb.VMSpec)
		d.Cpu, d.Uuid = 2, ""
		desired[v.vm] = d
	}

	client := f.c.SelfClient(n2)
	for _, v := range vms {
		err := recreateOn(t, n2, client, v.vm, desired[v.vm])
		rec := f.vm(t, v.vm) // never lost, whatever happened
		if err != nil {
			t.Fatalf("rolling recreate of %s from %s: %v", v.vm, n2.Name, err)
		}
		spec := specOf(t, rec)
		if rec.HostName != v.host.Name || spec.GetCpu() != 2 || spec.GetUuid() == before[v.vm] {
			t.Errorf("%s after the recreate: host %s, cpu %d, uuid %s (was %s); want re-created on %s with 2 vCPU",
				v.vm, rec.HostName, spec.GetCpu(), spec.GetUuid(), before[v.vm], v.host.Name)
		}
		if spec.GetIso() != f.iso {
			t.Errorf("%s's ISO after the recreate = %q, want %q", v.vm, spec.GetIso(), f.iso)
		}
		if !v.host.Virt.DomainExists(v.vm) {
			t.Errorf("%s has no domain on %s", v.vm, v.host.Name)
		}
		if n2.Virt.DomainExists(v.vm) {
			t.Errorf("%s was re-created on the rollout node %s", v.vm, n2.Name)
		}
	}
}

// A VM whose host is in maintenance is rebuilt on another host, as main
// re-placed it, once that host has judged its ISO.
//
// Red against e287bc8b: the rebuild was pinned to the VM's own host and
// refused because that host is in maintenance.
func TestFleet_ARebuildOfAnISOVMOnAHostInMaintenanceIsRePlaced(t *testing.T) {
	f := newISOFleet(t)
	n0 := f.c.Nodes[0]
	before := f.createOn(t, n0, "web", f.iso)
	f.setHostState(t, n0.Name, "maintenance")
	client := f.c.SelfClient(n0)
	_, err := client.RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"})
	rec := f.vm(t, "web")
	if err != nil {
		t.Fatalf("rebuild of an ISO VM whose host is in maintenance: %v", err)
	}
	spec := specOf(t, rec)
	if rec.HostName == n0.Name || spec.GetUuid() == specOf(t, before).GetUuid() || spec.GetIso() != f.iso {
		t.Fatalf("after the rebuild: host %s, uuid %s (was %s), iso %q; want re-placed off %s with its ISO",
			rec.HostName, spec.GetUuid(), specOf(t, before).GetUuid(), spec.GetIso(), n0.Name)
	}
	if spec.GetPlacement().GetHost() != "" {
		t.Errorf("the rebuild persisted a placement pin %q", spec.GetPlacement().GetHost())
	}
	if !f.c.Node(rec.HostName).Virt.DomainExists("web") || n0.Virt.DomainExists("web") {
		t.Errorf("the domain is not on %s alone", rec.HostName)
	}
}

// The host placement chooses does not have the VM's ISO (its pool of that
// name is empty there): it says so before the teardown, and the VM is left as
// it was. Only that host can tell — the entry node sees its pool row, not its
// files.
//
// Mutation: skip asking the chosen host — the VM is torn down, its create
// there is refused, and it is gone.
func TestFleet_ARebuildIsRefusedBeforeTheTeardownWhenTheChosenHostLacksTheISO(t *testing.T) {
	f := newISOFleet(t)
	ctx := context.Background()
	n0, n1 := f.c.Nodes[0], f.c.Nodes[1]
	for _, n := range f.c.Nodes {
		dir := filepath.Join(f.c.tmpRoot, n.Name, "media-pool")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertStoragePool(ctx, n0.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: "media", Driver: "dir", Target: dir, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		if n == n0 {
			writeOptical(t, filepath.Join(dir, "win.iso"))
		}
	}
	f.createOn(t, n0, "web", "media/win.iso")
	f.setHostState(t, n0.Name, "maintenance")
	f.setHostState(t, f.c.Nodes[2].Name, "maintenance") // placement's one choice: n1
	xml := n0.Virt.DefinedXML("web")

	_, err := f.c.SelfClient(n0).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"})
	rec := f.vm(t, "web")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), n1.Name) {
		t.Fatalf("rebuild onto a host without the ISO: got %v, want FailedPrecondition naming %s", err, n1.Name)
	}
	if rec.HostName != n0.Name || n0.Virt.DefinedXML("web") != xml || xml == "" || n1.Virt.DomainExists("web") {
		t.Fatalf("the refused rebuild changed the VM: host %s, domain kept %v", rec.HostName, n0.Virt.DefinedXML("web") == xml)
	}
}

// A chosen host on an older build has no PreflightRecreateVM. Its create
// judges no installer ISO (main had no ISO gate), so the rebuild goes ahead
// there, as on main.
//
// Mutation: treat Unimplemented as a refusal — red.
func TestFleet_ARebuildOntoAnOlderHostGoesAheadAsOnMain(t *testing.T) {
	f := newISOFleet(t)
	n0, n1 := f.c.Nodes[0], f.c.Nodes[1]
	f.createOn(t, n0, "web", f.iso)
	f.setHostState(t, n0.Name, "maintenance")
	f.setHostState(t, f.c.Nodes[2].Name, "maintenance")
	defer n1.DoNotImplement("PreflightRecreateVM")()

	if _, err := f.c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"}); err != nil {
		f.vm(t, "web")
		t.Fatalf("rebuild onto a host on an older build: %v", err)
	}
	if rec := f.vm(t, "web"); rec.HostName != n1.Name || !n1.Virt.DomainExists("web") {
		t.Fatalf("after the rebuild: host %s, want %s", rec.HostName, n1.Name)
	}
}
