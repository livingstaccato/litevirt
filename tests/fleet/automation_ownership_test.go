package fleet

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
)

const ownershipRebuildDomainUUID = "0b9a3c1e-7d2f-4c55-9a1b-5e6f7a8b9c0d"

// Mutation: omit the managed-resource refusal in the real RebuildVM handler.
// It destroys/undefines the enrolled runtime, deletes its artifacts and replaces
// its ordinary VM incarnation while the certified resource still names the old
// domain. The unowned control must successfully rebuild with the same preflight.
// Retained signed history is consumer setup, not fresh enrollment authority.
func TestAutomationOwnershipLegacyRebuildRefusesBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		managed bool
		through uint64
	}{
		{name: "managed", managed: true, through: 12},
		{name: "unowned_control", through: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageFakeGenisoimage(t)
			f := NewAutomationFixture(t, 3)
			c, ctx := f.cluster, f.Context()
			n := c.Nodes[0]
			const name, project = "legacy-machine", "/project-alias"
			if err := corrosion.InsertProject(ctx, n.DB, corrosion.ProjectRecord{Name: project}); err != nil {
				t.Fatal(err)
			}
			dataDir := filepath.Join(c.tmpRoot, n.Name, "data")
			diskPath := lv.DiskPath(dataDir, name, "root")
			if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := qcow2.Create(diskPath, 64<<20, nil); err != nil {
				t.Fatal(err)
			}
			// A trailing sentinel keeps the old disk distinguishable even if the
			// filesystem immediately reuses its inode for a fresh empty qcow2.
			disk, err := os.OpenFile(diskPath, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := disk.WriteString("original legacy disk bytes")
			closeErr := disk.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("write legacy disk sentinel: %v %v", writeErr, closeErr)
			}
			spec := &pb.VMSpec{
				Name: name, Project: project, Uuid: ownershipRebuildDomainUUID,
				Cpu: 2, MemoryMib: 1024, Placement: &pb.PlacementSpec{Host: n.Name},
				Disks:     []*pb.DiskSpec{{Name: "root", Size: "64M"}},
				CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: legacy-machine\n"},
			}
			encoded, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			// This is the ordinary legacy row, never an unchecked automation row.
			if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
				Name: name, Project: project, HostName: n.Name, State: "running",
				Spec: string(encoded), CPUActual: 2, MemActual: 1024,
			}, nil, []corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: n.Name, Path: diskPath, SizeBytes: 64 << 20, StorageType: "local", TargetDev: "vda", DeleteWithVM: true}}); err != nil {
				t.Fatal(err)
			}
			if err := n.Virt.DefineDomain(`<domain><name>legacy-machine</name><uuid>` + ownershipRebuildDomainUUID + `</uuid><devices><disk device="disk"><source file="` + diskPath + `"/><target dev="vda" bus="virtio"/></disk></devices></domain>`); err != nil {
				t.Fatal(err)
			}
			if err := n.Virt.StartDomain(name); err != nil {
				t.Fatal(err)
			}
			for path, content := range map[string]string{
				lv.NvramPath(dataDir, name):        "original firmware bytes",
				lv.CloudInitISOPath(dataDir, name): "original seed bytes",
			} {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c.WaitConverged(t, convergeTimeout)
			observeRetainedHistoryFixtureForRuntime(t, f, tc.through, project, ownershipRebuildDomainUUID)
			if head := f.Head(t, 0); head.Sequence != tc.through {
				t.Fatalf("fixture frontier = %+v, want sequence %d", head, tc.through)
			}
			if tc.managed {
				assertOwnershipRebuildFacts(t, f)
				view, err := f.Engine(0).Observe(ctx, "legacy-uid", 12)
				if err != nil || view.ResourceUID != "legacy-uid" || view.Name != name || view.DomainUUID != ownershipRebuildDomainUUID || view.ResourceRevision != "new-opaque-legacy-uid" || view.Generation != 1 || view.Retired {
					t.Fatalf("certified enrolled runtime before rebuild: %+v %v", view, err)
				}
			} else {
				if _, err := f.Engine(0).Observe(ctx, "legacy-uid", 10); !automation.IsAbsent(err) {
					t.Fatalf("control requires certified genuine absence: %v", err)
				}
				rows, err := n.DB.Query(ctx, `SELECT uid FROM local_automation_resources WHERE stage='' AND name=?`, name)
				if err != nil || len(rows) != 0 {
					t.Fatalf("control unexpectedly enrolled: %+v %v", rows, err)
				}
			}
			before, err := corrosion.GetVM(ctx, n.DB, name)
			if err != nil || before == nil || before.Project != project || specOf(t, before).Uuid != ownershipRebuildDomainUUID || before.ActiveOperationID != "" || before.State != "running" {
				t.Fatalf("ordinary runtime does not match certified fixture/preflight: %+v %v", before, err)
			}
			beforeDisks, err := corrosion.GetVMDisks(ctx, n.DB, name)
			if err != nil || len(beforeDisks) != 1 || beforeDisks[0].Path != diskPath || !beforeDisks[0].DeleteWithVM {
				t.Fatalf("missing owned disk before rebuild: %+v %v", beforeDisks, err)
			}
			beforeXML := n.Virt.DefinedXML(name)
			if ownershipRebuildXMLUUID(t, beforeXML) != ownershipRebuildDomainUUID {
				t.Fatal("actual runtime UUID differs from enrolled domain UUID")
			}
			paths := []string{diskPath, lv.NvramPath(dataDir, name), lv.CloudInitISOPath(dataDir, name)}
			contents := make([][]byte, len(paths))
			files := make([]os.FileInfo, len(paths))
			for i, path := range paths {
				contents[i], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				files[i], err = os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			eventStart := len(n.Virt.EventLog())
			var destroyAttempts, undefineAttempts, defineAttempts atomic.Int64
			// Observe attempted external calls too, even if a future fake stops
			// recording a failed call. These hooks preserve its normal behavior.
			n.Virt.FailDestroyDomain = func(domain string) error {
				if domain == name {
					destroyAttempts.Add(1)
				}
				return nil
			}
			n.Virt.FailUndefineDomain = func(domain string, _ bool) error {
				if domain == name {
					undefineAttempts.Add(1)
				}
				return nil
			}
			n.Virt.FailDefineDomain = func(string) error {
				defineAttempts.Add(1)
				return nil
			}
			t.Cleanup(func() {
				n.Virt.FailDestroyDomain = nil
				n.Virt.FailUndefineDomain = nil
				n.Virt.FailDefineDomain = nil
			})
			out, rebuildErr := c.SelfClient(n).RebuildVM(ctx, &pb.RebuildVMRequest{Name: name})
			after, rowErr := corrosion.GetVM(ctx, n.DB, name)
			effects := map[string]int{}
			for _, event := range n.Virt.EventLog()[eventStart:] {
				if event.Domain == name {
					effects[event.Op]++
				}
			}
			if !tc.managed {
				if rebuildErr != nil || out == nil || rowErr != nil || after == nil {
					t.Fatalf("unowned compatibility control did not complete actual rebuild: out=%+v row=%+v rebuild=%v read=%v effects=%v", out, after, rebuildErr, rowErr, effects)
				}
				newUUID := specOf(t, after).Uuid
				if destroyAttempts.Load() != 1 || undefineAttempts.Load() != 1 || defineAttempts.Load() != 1 {
					t.Errorf("unowned rebuild did not reach all teardown/create boundaries: destroy=%d undefine=%d define=%d", destroyAttempts.Load(), undefineAttempts.Load(), defineAttempts.Load())
				}
				if newUUID == "" || newUUID == ownershipRebuildDomainUUID || after.CreatedAt == before.CreatedAt || after.Project != project || ownershipRebuildXMLUUID(t, n.Virt.DefinedXML(name)) != newUUID || effects["destroy"] != 1 || effects["undefine"] != 1 || effects["define"] != 1 {
					t.Errorf("unowned rebuild did not replace the runtime and row: before=%+v after=%+v effects=%v", before, after, effects)
				}
				for i, path := range paths {
					info, err := os.Stat(path)
					if err == nil && os.SameFile(files[i], info) {
						b, readErr := os.ReadFile(path)
						if readErr != nil {
							t.Errorf("control artifact read: %s: %v", path, readErr)
						} else if bytes.Equal(b, contents[i]) {
							t.Errorf("unowned rebuild left original artifact intact: %s", path)
						}
					} else if err != nil && !os.IsNotExist(err) {
						t.Errorf("control artifact read: %s: %v", path, err)
					}
				}
				return
			}
			if status.Code(rebuildErr) != codes.FailedPrecondition || out != nil {
				t.Errorf("managed legacy rebuild must refuse before effects: out=%+v err=%v effects=%v", out, rebuildErr, effects)
			}
			if destroyAttempts.Load() != 0 || undefineAttempts.Load() != 0 || defineAttempts.Load() != 0 {
				t.Errorf("managed rebuild reached destructive/replacement boundaries: destroy=%d undefine=%d define=%d", destroyAttempts.Load(), undefineAttempts.Load(), defineAttempts.Load())
			}
			for _, op := range []string{"destroy", "undefine", "define", "start", "shutdown"} {
				if effects[op] != 0 {
					t.Errorf("managed legacy rebuild attempted %s %d times", op, effects[op])
				}
			}
			if rowErr != nil || !reflect.DeepEqual(after, before) {
				t.Errorf("managed rebuild tombstoned/replaced/changed ordinary VM row: before=%+v after=%+v err=%v", before, after, rowErr)
			}
			afterDisks, err := corrosion.GetVMDisks(ctx, n.DB, name)
			if err != nil || !reflect.DeepEqual(afterDisks, beforeDisks) {
				t.Errorf("managed rebuild changed disk ownership rows: %+v %v", afterDisks, err)
			}
			if active, err := n.Virt.DomainIsActive(name); err != nil || !active || n.Virt.DefinedXML(name) != beforeXML {
				t.Errorf("managed rebuild changed original runtime: active=%v err=%v", active, err)
			}
			for i, path := range paths {
				b, readErr := os.ReadFile(path)
				info, statErr := os.Stat(path)
				if readErr != nil || statErr != nil || !bytes.Equal(b, contents[i]) || !os.SameFile(files[i], info) {
					t.Errorf("managed rebuild removed/replaced/rewrote original artifact %s: read=%v stat=%v", path, readErr, statErr)
				}
			}
			assertOwnershipRebuildFacts(t, f)
		})
	}
}

func ownershipRebuildXMLUUID(t *testing.T, text string) string {
	t.Helper()
	var domain struct {
		UUID string `xml:"uuid"`
	}
	if err := xml.Unmarshal([]byte(text), &domain); err != nil {
		t.Fatal(err)
	}
	return domain.UUID
}

func assertOwnershipRebuildFacts(t *testing.T, f *AutomationFixture) {
	t.Helper()
	db, ctx := f.cluster.Nodes[0].DB, f.Context()
	head := f.Head(t, 0)
	rows, err := db.Query(ctx, `SELECT cluster_uid,sequence,digest FROM local_automation_semantic_heads WHERE stage=''`)
	if err != nil || len(rows) != 1 || rows[0].String("cluster_uid") != head.ClusterUID || rows[0].Int64("sequence") != int64(head.Sequence) || rows[0].String("digest") != head.Digest || head.Sequence < 12 {
		t.Fatalf("incomplete semantic/certified frontier: head=%+v rows=%+v err=%v", head, rows, err)
	}
	rows, err = db.Query(ctx, `SELECT r.*,n.resource_uid AS named_uid,n.disposition,b.resource_uid AS bound_uid,b.retired AS binding_retired,b.creation_generation,b.operation_id AS binding_operation,b.revision AS binding_revision FROM local_automation_resources r JOIN local_automation_names n ON n.stage=r.stage AND n.cluster_uid=r.cluster_uid AND n.name=r.name JOIN local_automation_bindings b ON b.stage=r.stage AND b.cluster_uid=r.cluster_uid AND b.project_uid=r.project_uid AND b.owner_id=r.owner_id AND b.management_key=r.management_key WHERE r.stage='' AND r.uid='legacy-uid'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("certified owned runtime facts missing: %+v %v", rows, err)
	}
	r := rows[0]
	for column, want := range map[string]string{
		"cluster_uid": head.ClusterUID, "project_uid": "project-uid", "uid": "legacy-uid", "name": "legacy-machine",
		"domain_uuid": ownershipRebuildDomainUUID, "incarnation": "legacy-incarnation", "owner_id": "target-owner", "management_key": "legacy-key",
		"revision": "new-opaque-legacy-uid", "last_operation_id": "adopt_resource-op", "original_operation_id": "",
		"named_uid": "legacy-uid", "disposition": "live", "bound_uid": "legacy-uid", "binding_operation": "adopt_resource-op", "binding_revision": "new-opaque-legacy-uid",
	} {
		if r.String(column) != want {
			t.Fatalf("certified %s=%q, want literal %q", column, r.String(column), want)
		}
	}
	if r.Int64("retired") != 0 || r.Int64("binding_retired") != 0 || r.Int64("binding_generation") != 1 || r.Int64("creation_generation") != 1 || r.Int64("applied_sequence") != 12 {
		t.Fatalf("certified ownership generation/frontier changed: %+v", r)
	}
	rows, err = db.Query(ctx, `SELECT uid FROM local_automation_aliases WHERE stage='' AND cluster_uid=? AND kind='project' AND alias='/project-alias'`, head.ClusterUID)
	if err != nil || len(rows) != 1 || rows[0].String("uid") != "project-uid" {
		t.Fatalf("ordinary project selector does not resolve to certified project: %+v %v", rows, err)
	}
}
