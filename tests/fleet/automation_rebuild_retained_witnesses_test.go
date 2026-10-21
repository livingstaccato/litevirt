package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The retained fixture always uses legacy-incarnation; ordinary CreateVM mints
// its own CreatedAt. UUID/project leaves therefore also differ in incarnation.
// These are explicit refusal preconditions, not three isolated dimensions.
func TestAutomationRetainedManagedRebuildMismatchesRefuse(t *testing.T) {
	for _, mismatch := range []string{"uuid", "incarnation", "project"} {
		t.Run(mismatch, func(t *testing.T) {
			stageFakeGenisoimage(t)
			f := NewAutomationFixture(t, 3)
			const ordinaryProject = "/project-alias"
			before := retainedRebuildWitnessNativeVM(t, f, ordinaryProject, false)
			certifiedProject, certifiedUUID := ordinaryProject, specOf(t, before).Uuid
			if mismatch == "uuid" {
				certifiedUUID = ownershipRebuildDomainUUID
				if certifiedUUID == specOf(t, before).Uuid {
					t.Fatal("SETUP: UUID mismatch must be real")
				}
			}
			if mismatch == "project" {
				certifiedProject = "/retained-other-project"
				if err := corrosion.InsertProject(f.Context(), f.cluster.Nodes[0].DB, corrosion.ProjectRecord{Name: certifiedProject}); err != nil {
					t.Fatal(err)
				}
				f.cluster.WaitConverged(t, convergeTimeout)
			}
			observeRetainedHistoryFixtureForRuntime(t, f, 12, certifiedProject, certifiedUUID)
			managed := retainedRebuildWitnessManagedName(t, f, certifiedProject, certifiedUUID)
			if before.CreatedAt == "" || before.CreatedAt == managed.Record.Resource.Incarnation {
				t.Fatal("SETUP: ordinary incarnation must differ from certified legacy-incarnation")
			}
			if (specOf(t, before).Uuid != managed.Record.Resource.DomainUUID) != (mismatch == "uuid") ||
				(before.Project != managed.Record.Project.Alias) != (mismatch == "project") {
				t.Fatal("SETUP: UUID/project mismatch preconditions are not exact")
			}
			retainedRebuildWitnessRefusal(t, f, managed)
		})
	}
}

// Mutation: move the owner guard immediately after successful preflightLUNs.
// Native teardown may still be zero, but LUN votes/allocation/hold effects make
// this witness fail. The initial allocation below is real, not a seeded claim.
func TestAutomationRetainedManagedRebuildRefusesBeforeLUNClaim(t *testing.T) {
	stageFakeGenisoimage(t)
	t.Cleanup(storage.OverrideISCSICommandForTest(func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	}))
	f := NewAutomationFixture(t, 3)
	c, ctx := f.cluster, f.Context()
	for _, n := range c.Nodes {
		wireLUNReleaseGate(t, c, n)
	}
	openLUNFeature(t, c)
	addLUNPool(t, c, "retained-san", 0, onePortal)
	const project = "/project-alias"
	before := retainedRebuildWitnessNativeVM(t, f, project, true)
	observeRetainedHistoryFixtureForRuntime(t, f, 12, project, specOf(t, before).Uuid)
	managed := retainedRebuildWitnessManagedName(t, f, project, specOf(t, before).Uuid)
	key := fleetLUNKey(0)
	disks, err := corrosion.GetVMDisks(ctx, c.Nodes[0].DB, before.Name)
	if err != nil || len(disks) != 2 {
		t.Fatalf("SETUP: local root plus iSCSI data disk: %+v %v", disks, err)
	}
	var actualLUN bool
	for _, disk := range disks {
		if disk.DiskName == "data" {
			k, fixed := storage.FixedDeviceKeyOfPath(disk.Path)
			actualLUN = fixed && k == key && disk.StorageType == "iscsi"
		}
	}
	if !actualLUN {
		t.Fatal("SETUP: native disk rows must actually use the LUN under test")
	}
	type lunSnapshot struct {
		claims, policies []corrosion.Row
		current, next    corrosion.ClaimVoterState
		currentFound     bool
		nextFound        bool
		resolved         int64
		plainDelete      string
	}
	readLUN := func(n *Node) lunSnapshot {
		t.Helper()
		var out lunSnapshot
		var err error
		out.claims, err = n.DB.Query(ctx, `SELECT * FROM local_recovery_claims WHERE target_kind=? ORDER BY target_name,owner_epoch,attempt`, corrosion.ClaimKindLUN)
		if err != nil {
			t.Fatal(err)
		}
		out.policies, err = n.DB.Query(ctx, `SELECT * FROM cluster_policies WHERE key IN (?,?) ORDER BY key`, "lun_resolved/"+key, "lun_plain_delete/"+key)
		if err != nil {
			t.Fatal(err)
		}
		out.current, out.currentFound, err = n.DB.ClaimState(ctx, corrosion.LUNClaimKey(key, 0))
		if err != nil {
			t.Fatal(err)
		}
		out.next, out.nextFound, err = n.DB.ClaimState(ctx, corrosion.LUNClaimKey(key, 1))
		if err != nil {
			t.Fatal(err)
		}
		out.resolved, err = corrosion.GetLUNResolved(ctx, n.DB, key)
		if err != nil {
			t.Fatal(err)
		}
		out.plainDelete, err = corrosion.GetLUNPlainDelete(ctx, n.DB, key)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// Include directory existence: a refused late guard can delete the moved
	// hold file while leaving the newly created directory behind.
	type holdSnapshot struct {
		exists bool
		files  map[string][]byte
	}
	readHolds := func() holdSnapshot {
		t.Helper()
		out := holdSnapshot{files: map[string][]byte{}}
		dir := filepath.Join(c.tmpRoot, c.Nodes[0].Name, "data", "iscsi-lun-holds")
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out.exists = true
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				t.Fatalf("unexpected LUN hold entry %s: %v", entry.Name(), err)
			}
			body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			out.files[entry.Name()] = body
		}
		return out
	}
	beforeLUN := make([]lunSnapshot, len(c.Nodes))
	accepted := 0
	for i, n := range c.Nodes {
		snap := readLUN(n)
		beforeLUN[i] = snap
		if snap.nextFound || snap.resolved != 0 || snap.plainDelete != "" {
			t.Fatalf("SETUP: expected first LUN allocation only on %s: %+v", n.Name, snap)
		}
		if snap.currentFound && snap.current.Value != nil && snap.current.Value.LUN != nil {
			allocation := snap.current.Value.LUN
			if allocation.LUN != key || allocation.Generation != 0 || allocation.VMName != before.Name || allocation.VMID != specOf(t, before).Uuid || allocation.Disk != "data" || allocation.Host != c.Nodes[0].Name || allocation.ClaimID == "" || snap.current.Accept == nil {
				t.Fatalf("SETUP: genuine native LUN allocation differs on %s: %+v", n.Name, snap.current)
			}
			accepted++
		}
	}
	if accepted < corrosion.MajorityOf(len(c.Nodes)) {
		t.Fatal("SETUP: native CreateVM did not establish a real accepted LUN majority")
	}
	beforeHolds := readHolds()
	if len(beforeHolds.files) != 0 {
		t.Fatal("SETUP: initial native create left a moved LUN hold")
	}
	var prepares, accepts atomic.Int64
	for _, n := range c.Nodes {
		n.Server.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
			if v.Key.TargetKind != corrosion.ClaimKindLUN {
				return
			}
			switch v.Phase {
			case "prepare":
				prepares.Add(1)
			case "accept":
				accepts.Add(1)
			}
		})
		n := n
		t.Cleanup(func() { n.Server.SetClaimVoteObserverForTest(nil) })
	}
	retainedRebuildWitnessRefusal(t, f, managed)
	if prepares.Load() != 0 || accepts.Load() != 0 {
		t.Errorf("RETAINED_REBUILD_LUN_EFFECT: committed LUN votes before refusal: prepare=%d accept=%d", prepares.Load(), accepts.Load())
	}
	for i, n := range c.Nodes {
		if after := readLUN(n); !reflect.DeepEqual(beforeLUN[i], after) {
			t.Errorf("RETAINED_REBUILD_LUN_EFFECT: LUN claims/checkpoints changed on %s: before=%+v after=%+v", n.Name, beforeLUN[i], after)
		}
	}
	if after := readHolds(); !reflect.DeepEqual(beforeHolds, after) {
		t.Errorf("RETAINED_REBUILD_LUN_EFFECT: LUN hold files/directory changed: before=%+v after=%+v", beforeHolds, after)
	}
}

// Ordinary CreateVM supplies the row, runtime UUID and owned local disk.
// The image-less fixture explicitly stages NVRAM and seed preservation sentinels.
// The optional data disk uses the actual already-open fleet iSCSI claim path.
func retainedRebuildWitnessNativeVM(t *testing.T, f *AutomationFixture, project string, onLUN bool) *corrosion.VMRecord {
	t.Helper()
	c, ctx := f.cluster, f.Context()
	n := c.Nodes[0]
	if err := corrosion.InsertProject(ctx, n.DB, corrosion.ProjectRecord{Name: project}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	spec := &pb.VMSpec{
		Name: "legacy-machine", Project: project, Cpu: 2, MemoryMib: 1024,
		Placement: &pb.PlacementSpec{Host: n.Name},
		Disks:     []*pb.DiskSpec{{Name: "root", Size: "64M"}},
		CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: legacy-machine\n"},
	}
	if onLUN {
		spec.Disks = append(spec.Disks, &pb.DiskSpec{Name: "data", Size: "1G", Storage: "retained-san"})
	}
	if out, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: spec}); err != nil || out == nil {
		t.Fatalf("SETUP: actual native create: %+v %v", out, err)
	}
	c.WaitConverged(t, convergeTimeout)
	vm, err := corrosion.GetVM(ctx, n.DB, spec.Name)
	if err != nil || vm == nil || vm.Project != project || vm.HostName != n.Name || vm.State != "running" || vm.ActiveOperationID != "" || vm.CreatedAt == "" {
		t.Fatalf("SETUP: actual native VM: %+v %v", vm, err)
	}
	uuid := specOf(t, vm).Uuid
	if uuid == "" || ownershipRebuildXMLUUID(t, n.Virt.DefinedXML(spec.Name)) != uuid {
		t.Fatal("SETUP: actual native row and domain UUID must match")
	}
	if active, err := n.Virt.DomainIsActive(spec.Name); err != nil || !active {
		t.Fatalf("SETUP: actual native VM must run: %v", err)
	}
	dataDir := filepath.Join(c.tmpRoot, n.Name, "data")
	disk, err := os.OpenFile(lv.DiskPath(dataDir, spec.Name, "root"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := disk.WriteString("retained rebuild original native disk sentinel")
	closeErr := disk.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	nvram := lv.NvramPath(dataDir, spec.Name)
	if err := os.MkdirAll(filepath.Dir(nvram), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nvram, []byte("retained rebuild original native firmware sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := lv.CloudInitISOPath(dataDir, spec.Name)
	if err := os.MkdirAll(filepath.Dir(seed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seed, []byte("retained rebuild original seed sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	return vm
}

func retainedRebuildWitnessManagedName(t *testing.T, f *AutomationFixture, project, uuid string) corrosion.AutomationNameObservation {
	t.Helper()
	head := f.Head(t, 0)
	if head.Sequence != 12 {
		t.Fatalf("SETUP: signed retained fixture frontier must be12: %+v", head)
	}
	view, err := f.cluster.Nodes[0].DB.AutomationObserveName(f.Context(), head.ClusterUID, "legacy-machine", head.Sequence)
	if err != nil || view.State != corrosion.AutomationNamePresent || view.Record == nil || view.Record.Owner == nil || view.Record.Binding == nil || view.Prefix != head || view.Name != "legacy-machine" {
		t.Fatalf("SETUP: complete retained managed name reader: %+v %v", view, err)
	}
	r := view.Record
	if r.Resource.UID != "legacy-uid" || r.Resource.Name != "legacy-machine" || r.Resource.ClusterUID != head.ClusterUID || r.Resource.ProjectUID != "project-uid" || r.Resource.DomainUUID != uuid || r.Resource.Incarnation != "legacy-incarnation" || r.Resource.OwnerID != "target-owner" || r.Resource.ManagementKey != "legacy-key" || r.Resource.BindingGeneration != 1 || r.Resource.Revision != "new-opaque-legacy-uid" || r.Resource.LastOperationID != "adopt_resource-op" || r.Resource.AppliedSequence != 12 || r.Resource.Retired ||
		r.Project.UID != "project-uid" || r.Project.Alias != project || r.Project.Retired || r.VMIdentity.UID != "legacy-uid" || r.VMIdentity.Alias != "legacy-machine" || r.VMIdentity.Retired ||
		r.Name.ResourceUID != "legacy-uid" || r.Name.Disposition != "live" || r.Name.Generation != 1 || r.Owner.OwnerID != "target-owner" || r.Owner.SessionID != "target-session" ||
		r.Binding.ResourceUID != "legacy-uid" || r.Binding.OwnerID != "target-owner" || r.Binding.ManagementKey != "legacy-key" || r.Binding.Generation != 1 || r.Binding.Revision != r.Resource.Revision || r.Binding.Retired {
		t.Fatalf("SETUP: complete signed managed facts do not match selected fixture: %+v", r)
	}
	return view
}

// Same concrete preservation boundaries as the untouched original regression.
// Returning from the RPC is required; error-only assertions cannot prove that
// teardown, artifact deletion, or ordinary-row replacement never happened.
func retainedRebuildWitnessRefusal(t *testing.T, f *AutomationFixture, certified corrosion.AutomationNameObservation) {
	t.Helper()
	c, ctx := f.cluster, f.Context()
	n := c.Nodes[0]
	const name = "legacy-machine"
	before, err := corrosion.GetVM(ctx, n.DB, name)
	if err != nil || before == nil {
		t.Fatalf("SETUP: native VM before rebuild: %+v %v", before, err)
	}
	disks, err := corrosion.GetVMDisks(ctx, n.DB, name)
	if err != nil || len(disks) == 0 {
		t.Fatalf("SETUP: native disks before rebuild: %+v %v", disks, err)
	}
	dataDir := filepath.Join(c.tmpRoot, n.Name, "data")
	root := lv.DiskPath(dataDir, name, "root")
	rootOwned := false
	for _, disk := range disks {
		if disk.DiskName == "root" && disk.Path == root && disk.DeleteWithVM && disk.StorageType == "local" {
			rootOwned = true
		}
	}
	if !rootOwned {
		t.Fatal("SETUP: missing real owned local root disk")
	}
	paths := []string{root, lv.NvramPath(dataDir, name), lv.CloudInitISOPath(dataDir, name)}
	contents, files := make([][]byte, len(paths)), make([]os.FileInfo, len(paths))
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
	beforeXML := n.Virt.DefinedXML(name)
	start := len(n.Virt.EventLog())
	var destroy, undefine, define atomic.Int64
	n.Virt.FailDestroyDomain = func(domain string) error {
		if domain == name {
			destroy.Add(1)
		}
		return nil
	}
	n.Virt.FailUndefineDomain = func(domain string, _ bool) error {
		if domain == name {
			undefine.Add(1)
		}
		return nil
	}
	n.Virt.FailDefineDomain = func(string) error { define.Add(1); return nil }
	defer func() {
		n.Virt.FailDestroyDomain = nil
		n.Virt.FailUndefineDomain = nil
		n.Virt.FailDefineDomain = nil
	}()
	out, rebuildErr := c.SelfClient(n).RebuildVM(ctx, &pb.RebuildVMRequest{Name: name})
	if status.Code(rebuildErr) != codes.FailedPrecondition || out != nil {
		t.Errorf("RETAINED_REBUILD_REFUSAL: managed name must refuse: out=%+v err=%v", out, rebuildErr)
	}
	if destroy.Load() != 0 || undefine.Load() != 0 || define.Load() != 0 {
		t.Errorf("RETAINED_REBUILD_EFFECT: attempted destroy=%d undefine=%d define=%d", destroy.Load(), undefine.Load(), define.Load())
	}
	for _, event := range n.Virt.EventLog()[start:] {
		if event.Domain == name {
			switch event.Op {
			case "destroy", "undefine", "define", "start", "shutdown", "nvram-deleted":
				t.Errorf("RETAINED_REBUILD_EFFECT: attempted native event %+v", event)
			}
		}
	}
	if after, err := corrosion.GetVM(ctx, n.DB, name); err != nil || !reflect.DeepEqual(before, after) {
		t.Errorf("RETAINED_REBUILD_EFFECT: native VM row changed: before=%+v after=%+v err=%v", before, after, err)
	}
	if after, err := corrosion.GetVMDisks(ctx, n.DB, name); err != nil || !reflect.DeepEqual(disks, after) {
		t.Errorf("RETAINED_REBUILD_EFFECT: native disk rows changed: before=%+v after=%+v err=%v", disks, after, err)
	}
	if active, err := n.Virt.DomainIsActive(name); err != nil || !active || n.Virt.DefinedXML(name) != beforeXML {
		t.Errorf("RETAINED_REBUILD_EFFECT: original domain/UUID changed: active=%v err=%v", active, err)
	}
	for i, path := range paths {
		body, readErr := os.ReadFile(path)
		info, statErr := os.Stat(path)
		if readErr != nil || statErr != nil || !bytes.Equal(contents[i], body) || !os.SameFile(files[i], info) {
			t.Errorf("RETAINED_REBUILD_EFFECT: original artifact changed: %s read=%v stat=%v", path, readErr, statErr)
		}
	}
	if after, err := n.DB.AutomationObserveName(ctx, certified.Prefix.ClusterUID, name, certified.Prefix.Sequence); err != nil || !reflect.DeepEqual(certified, after) {
		t.Errorf("RETAINED_REBUILD_EFFECT: complete retained name graph changed: before=%+v after=%+v err=%v", certified, after, err)
	}
}
