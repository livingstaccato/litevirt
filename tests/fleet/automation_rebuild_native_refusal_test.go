package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// This control deliberately never calls NewAutomationFixture (even its
// initialize=false form writes automation authority). Native startup, PKI,
// project creation and voter/claim bookkeeping remain intact.
func TestAutomationRetainedRebuildNativeCompatibility(t *testing.T) {
	for _, entryIndex := range []int{0, 1} {
		name := "direct"
		if entryIndex == 1 {
			name = "forwarded"
		}
		t.Run(name, func(t *testing.T) {
			stageFakeGenisoimage(t)
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 4102026})
			c.WaitConverged(t, convergeTimeout)
			genesisByTick(t, c, c.Nodes[0])
			enableRecoveryClaims(t, c)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			owner, entry := c.Nodes[0], c.Nodes[entryIndex]
			const vmName, project = "native-rebuild", "/native-rebuild-project"
			if err := corrosion.InsertProject(ctx, owner.DB, corrosion.ProjectRecord{Name: project}); err != nil {
				t.Fatal(err)
			}
			c.WaitConverged(t, convergeTimeout)
			assertRebuildNoAutomationState(t, c)
			spec := &pb.VMSpec{Name: vmName, Project: project, Cpu: 2, MemoryMib: 1024, Placement: &pb.PlacementSpec{Host: owner.Name}, Disks: []*pb.DiskSpec{{Name: "root", Size: "64M"}}, CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: native-rebuild\n"}}
			if out, err := c.SelfClient(owner).CreateVM(ctx, &pb.CreateVMRequest{Spec: spec}); err != nil || out == nil {
				t.Fatal("SETUP native create", out, err)
			}
			c.WaitConverged(t, convergeTimeout)
			before, err := corrosion.GetVM(ctx, owner.DB, vmName)
			if err != nil || before == nil || before.Project != project {
				t.Fatal("SETUP native row", before, err)
			}
			oldUUID := specOf(t, before).Uuid
			if oldUUID == "" || ownershipRebuildXMLUUID(t, owner.Virt.DefinedXML(vmName)) != oldUUID {
				t.Fatal("SETUP real native runtime UUID")
			}
			if active, err := owner.Virt.DomainIsActive(vmName); err != nil || !active {
				t.Fatal("SETUP native runtime must be active", err)
			}
			disks, err := corrosion.GetVMDisks(ctx, owner.DB, vmName)
			if err != nil || len(disks) != 1 || !disks[0].DeleteWithVM {
				t.Fatal("SETUP owned native disk", disks, err)
			}
			dataDir := filepath.Join(c.tmpRoot, owner.Name, "data")
			paths := []string{disks[0].Path, lv.NvramPath(dataDir, vmName), lv.CloudInitISOPath(dataDir, vmName)}
			// The image-less native create skips seed generation; these explicit firmware
			// and seed sentinels are ordinary artifacts, not automation evidence.
			if err := os.MkdirAll(filepath.Dir(paths[1]), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths[1], []byte("native old firmware sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(paths[2]), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths[2], []byte("native old seed sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			disk, err := os.OpenFile(paths[0], os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := disk.WriteString("native old disk sentinel")
			closeErr := disk.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatal(writeErr, closeErr)
			}
			files := make([]os.FileInfo, len(paths))
			contents := make([][]byte, len(paths))
			for i, path := range paths {
				files[i], err = os.Stat(path)
				if err != nil {
					t.Fatal("SETUP artifact", path, err)
				}
				contents[i], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			assertRebuildNoAutomationState(t, c)
			start := len(owner.Virt.EventLog())
			entryStart := len(entry.Virt.EventLog())
			var destroy, undefine, define atomic.Int32
			owner.Virt.FailDestroyDomain = func(string) error { destroy.Add(1); return nil }
			owner.Virt.FailUndefineDomain = func(string, bool) error { undefine.Add(1); return nil }
			owner.Virt.FailDefineDomain = func(string) error { define.Add(1); return nil }
			t.Cleanup(func() {
				owner.Virt.FailDestroyDomain = nil
				owner.Virt.FailUndefineDomain = nil
				owner.Virt.FailDefineDomain = nil
			})
			out, rebuildErr := c.SelfClient(entry).RebuildVM(ctx, &pb.RebuildVMRequest{Name: vmName})
			after, rowErr := corrosion.GetVM(ctx, owner.DB, vmName)
			if rebuildErr != nil || out == nil || rowErr != nil || after == nil {
				t.Fatalf("NATIVE_REBUILD_COMPATIBILITY: real replacement refused: out=%+v row=%+v rebuild=%v read=%v", out, after, rebuildErr, rowErr)
			}
			effects := map[string]int{}
			for _, event := range owner.Virt.EventLog()[start:] {
				if event.Domain == vmName {
					effects[event.Op]++
				}
			}
			newUUID := specOf(t, after).Uuid
			if destroy.Load() != 1 || undefine.Load() != 1 || define.Load() != 1 || effects["destroy"] != 1 || effects["undefine"] != 1 || effects["define"] != 1 || effects["start"] != 1 {
				t.Fatalf("native replacement missed actual owner effects: %v attempts=%d/%d/%d", effects, destroy.Load(), undefine.Load(), define.Load())
			}
			if newUUID == "" || newUUID == oldUUID || after.CreatedAt == before.CreatedAt || after.Project != project || ownershipRebuildXMLUUID(t, owner.Virt.DefinedXML(vmName)) != newUUID {
				t.Fatal("native replacement did not change row/domain incarnation", before, after)
			}
			for i, path := range paths {
				info, e := os.Stat(path)
				if e == nil && os.SameFile(files[i], info) {
					b, e := os.ReadFile(path)
					if e != nil || bytes.Equal(b, contents[i]) {
						t.Errorf("native replacement retained original artifact %s: %v", path, e)
					}
				} else if e != nil && !os.IsNotExist(e) {
					t.Errorf("artifact check %s: %v", path, e)
				}
			}
			if entry != owner {
				for _, event := range entry.Virt.EventLog()[entryStart:] {
					if event.Domain == vmName && (event.Op == "destroy" || event.Op == "undefine" || event.Op == "define" || event.Op == "start") {
						t.Errorf("forwarding entry performed owner effect: %+v", event)
					}
				}
			}
			assertReCreated(t, c, vmName, before, owner)
			assertRebuildNoAutomationState(t, c)
		})
	}
}

func assertRebuildNoAutomationState(t *testing.T, c *Cluster) {
	t.Helper()
	for _, n := range c.Nodes {
		for _, table := range []string{"local_automation_authority", "local_automation_prefix", "local_automation_history", "local_automation_anchors", "local_automation_requests", "local_automation_resources", "local_automation_names", "local_automation_bindings"} {
			rows, err := n.DB.Query(context.Background(), "SELECT count(*) AS n FROM "+table)
			if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
				t.Fatal("native control acquired automation state", n.Name, table, rows, err)
			}
		}
		if cfg, err := corrosion.AdoptedVoterConfig(context.Background(), n.DB); err != nil || cfg == nil || cfg.Generation == 0 {
			t.Fatal("native voter bookkeeping missing", n.Name, cfg, err)
		}
	}
}
