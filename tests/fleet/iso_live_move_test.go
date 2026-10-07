// Fleet scenarios for a running VM's installer ISO in a live migration. The
// target resolves the VM's ISO on its own filesystem and the source hands
// libvirt a destination definition with that file (MigrateParams.
// CDROMSources): an ISO library whose directory is reached through a link that
// names another directory on each host is followed on each host, as qemu
// followed the link on main.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// isoLiveMoveCluster gives each of two nodes a pool "shared-isos" whose target
// is a link to a directory of that node's own, holding install.iso, and seeds
// a running VM on the first whose domain carries the first node's file.
func isoLiveMoveCluster(t *testing.T) (*Cluster, *Node, *Node, map[string]string) {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
	files := map[string]string{}
	for _, n := range c.Nodes {
		real := filepath.Join(c.tmpRoot, n.Name, "isos-"+n.Name)
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(real, "install.iso"), []byte("CD001 installer"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(c.tmpRoot, n.Name, "isos")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertStoragePool(ctx, n.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: "shared-isos", Driver: "dir", Target: link, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		r, err := filepath.EvalSymlinks(filepath.Join(real, "install.iso"))
		if err != nil {
			t.Fatal(err)
		}
		files[n.Name] = r
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "inst", Cpu: 1, MemoryMib: 256, Iso: "shared-isos/install.iso", IsoScope: "pool"})
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "inst", HostName: src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	dom := `<domain type='kvm'><name>inst</name><memory unit='MiB'>256</memory><vcpu>1</vcpu><devices>` +
		`<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='` + files[src.Name] +
		`'/><target dev='sda' bus='sata'/><readonly/></disk></devices></domain>`
	src.Virt.SetInactiveXML("inst", dom)
	src.Virt.SetActiveXML("inst", dom)
	src.Virt.SetState("inst", "running")
	return c, src, dst, files
}

// The live move lands the domain on the target's own file.
//
// Mutation: drop CDROMSources from the MigrateParams in MigrateVM — the
// migrate call carries no cdroms and the test goes red.
func TestFleet_ALiveMoveLandsOnTheTargetsISO(t *testing.T) {
	c, src, dst, files := isoLiveMoveCluster(t)
	defer c.Stop()
	if err := migrateAt(t, c, src, "inst", dst.Name); err != nil {
		t.Fatalf("live move of a VM whose library is a link to another directory on each host: %v", err)
	}
	want := "cdroms=" + files[src.Name] + "->" + files[dst.Name]
	if note := lastMigrateNote(src); !strings.Contains(note, want) {
		t.Fatalf("libvirt migrate = %q; want the destination definition pointed at the target's file (%s)", note, want)
	}
}

// The target's link names the host key: the move is refused before libvirt is
// asked.
func TestFleet_ALiveMoveToALinkAtTheHostKeyIsRefused(t *testing.T) {
	c, src, dst, files := isoLiveMoveCluster(t)
	defer c.Stop()
	if err := os.Remove(files[dst.Name]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(c.tmpRoot, dst.Name, "pki", "host.key"), files[dst.Name]); err != nil {
		t.Fatal(err)
	}
	if err := migrateAt(t, c, src, "inst", dst.Name); err == nil {
		t.Fatal("a live move onto an ISO that is a link to the host key was not refused")
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("the refused move reached libvirt %d time(s)", n)
	}
}

// C-3 end to end: on the target another project's pool maps the library's
// directory. The source sends the sha256 of the file it judged; the very same
// bytes there are admitted, other bytes are not.
func TestFleet_AFirstArrivalInASharedDirectoryIsTheSameBytes(t *testing.T) {
	c, src, dst, files := isoLiveMoveCluster(t)
	defer c.Stop()
	if err := corrosion.UpsertStoragePool(context.Background(), dst.DB, corrosion.StoragePoolRecord{
		HostName: dst.Name, Name: "o-disks", Driver: "dir", Target: filepath.Dir(files[dst.Name]), Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[dst.Name], []byte("CD001 another project's file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := migrateAt(t, c, src, "inst", dst.Name); err == nil {
		t.Fatal("a first arrival onto other bytes in another project's directory was not refused")
	}
	if err := os.WriteFile(files[dst.Name], []byte("CD001 installer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := migrateAt(t, c, src, "inst", dst.Name); err != nil {
		t.Fatalf("a first arrival onto the very bytes the source judged: %v", err)
	}
}

// A drain moves the running VM live the same way: onto the target's file.
//
// Mutation: drop CDROMSources from the drain's MigrateParams — red.
func TestFleet_ADrainLandsOnTheTargetsISO(t *testing.T) {
	c, src, dst, files := isoLiveMoveCluster(t)
	defer c.Stop()
	st, err := c.SelfClient(src).DrainHost(context.Background(), &pb.DrainHostRequest{Name: src.Name})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	var last *pb.DrainProgress
	for {
		p, rerr := st.Recv()
		if rerr != nil {
			break
		}
		if p.GetVmName() == "inst" {
			last = p
		}
	}
	if last == nil || last.GetStatus() != "done" || last.GetStrategy() != pb.MigrateStrategy_MIGRATE_LIVE {
		t.Fatalf("drain progress for inst = %+v, want a live move, done", last)
	}
	want := "cdroms=" + files[src.Name] + "->" + files[dst.Name]
	if note := lastMigrateNote(src); !strings.Contains(note, want) {
		t.Fatalf("libvirt migrate = %q; want the destination definition pointed at the target's file (%s)", note, want)
	}
}
