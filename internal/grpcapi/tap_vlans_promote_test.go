package grpcapi

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// promoteAccessVLAN promotes vm1, an access-VLAN-30 VM, as vm1-p (a renamed
// promotion, a new row written after the start) through the start guard.
func promoteAccessVLAN(t *testing.T, s *Server) (*libvirtfake.Fake, error) {
	t.Helper()
	fake := libvirtfake.New()
	s.virt = fake
	fake.SetStartGuard(s.NICStartGuard(context.Background()))
	ctx := adminCtx()
	const srcMAC = "52:54:00:00:09:01"
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "lo", Mac: srcMAC, Trunk: []int32{30}}}})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)},
		[]corrosion.InterfaceRecord{{VMName: "vm1", NetworkName: "lo", MAC: srcMAC}},
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
	return fake, s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-p", TargetPool: "replica-pool", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx})
}

// R-B1 (the review's probe, kept): a renamed promotion writes its row after
// the start, so it registers its NICs' VLANs for the guard as a create does;
// the access VLAN is on the tap before the promoted guest runs.
//
// Mutation: drop pendingTapVLANsFor from the renamed promotion — red.
func TestPromoteReplica_RenamedPutsTheAccessVLANOnBeforeItRuns(t *testing.T) {
	s := testServer(t)
	fake, err := promoteAccessVLAN(t, s)
	if err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
	ops := vlanDomainOps(fake, "vm1-p")
	tap, start, resume := opIndex(ops, "vlan-tap"), opIndex(ops, "start"), opIndex(ops, "resume")
	if tap < 0 || !(start < tap && tap < resume) || !strings.Contains(ops[tap], "vlan=30") {
		t.Fatalf("ops = %q: want start (paused), VLAN 30 on the tap, then resume", ops)
	}
	if strings.Contains(ops[tap], "52:54:00:00:09:01") {
		t.Fatalf("the promoted NIC's VLAN went on the source's MAC: %q", ops[tap])
	}
}

// Every function that registers pending NICs (pendingNICs: a start whose rows
// are written after it) registers their tap VLANs too, or the guard finds
// none and the guest runs on VLAN 1 (R-B1 was exactly that). An exception
// says why here.
//
// Mutation: drop pendingTapVLANsFor from the renamed promotion — red.
func TestEveryPendingNICsStartAlsoRegistersItsTapVLANs(t *testing.T) {
	exempt := map[string]string{
		// A hot attach carries no trunk: an attach with one is refused
		// (TestNICHotplug_ATrunkIsRefused).
		"executeNICAttach": "no trunk on a hot attach",
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil || fd.Name.Name == "pendingNICs" {
					continue
				}
				calls := map[string]bool{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
							calls[sel.Sel.Name] = true
						}
					}
					return true
				})
				if !calls["pendingNICs"] {
					continue
				}
				found++
				if _, ok := exempt[fd.Name.Name]; ok {
					continue
				}
				if !calls["pendingTapVLANsFor"] && !calls["notePendingTapVLANs"] {
					t.Errorf("%s registers pending NICs but not their tap VLANs: a guest it starts runs its access NICs on VLAN 1",
						fd.Name.Name)
				}
			}
		}
	}
	if found < 5 {
		t.Fatalf("found %d functions registering pending NICs, want at least createVM, clone, promote, restore and the hot attach", found)
	}
}
