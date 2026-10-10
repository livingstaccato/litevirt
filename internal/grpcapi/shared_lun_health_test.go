package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// insertLUNVM records VM name on host with one disk at path, as an older
// build (or a create that raced) left it.
func insertLUNVM(t *testing.T, s *Server, name, host, disk, path string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: name, HostName: host, State: "running", Spec: "{}", CPUActual: 1, MemActual: 256},
		nil, []corrosion.DiskRecord{{VMName: name, DiskName: disk, HostName: host, Path: path,
			SizeBytes: 1 << 30, StorageType: "iscsi", StorageVolume: "san", TargetDev: "vda"}}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

func sharedLUNCondition(t *testing.T, s *Server) (corrosion.HealthCondition, bool) {
	t.Helper()
	conds, err := corrosion.ListHealthConditions(context.Background(), s.db, true)
	if err != nil {
		t.Fatalf("ListHealthConditions: %v", err)
	}
	var found []corrosion.HealthCondition
	for _, c := range conds {
		if c.Evaluator == sharedLUNEvaluator {
			found = append(found, c)
		}
	}
	if len(found) > 1 {
		t.Fatalf("%d shared_lun conditions, want at most one: %+v", len(found), found)
	}
	if len(found) == 0 {
		return corrosion.HealthCondition{}, false
	}
	return found[0], true
}

// A cluster that already has two VMs on one LUN — an older build let it — is
// told so: a shared_lun condition naming both VMs, observed on the first scan
// and critical once confirmed. Nothing else changes: no disk row is touched,
// and admission for the VMs (their start) is not refused. Once only one VM is
// left on the LUN, the condition resolves.
//
// Mutation: compare recorded paths instead of LUN keys (the two spellings
// below then differ) — no condition is raised and this goes red. Mutation:
// add shared_lun to ownershipConditionCodes — the start admission is refused
// and this goes red.
func TestSharedLUN_TwoVMsOnOneLUNRaiseACondition(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertLUNVM(t, s, "a", "host-a", "root", "/dev/disk/by-path/ip-10.0.0.1-iscsi-iqn.2020-01.com.example:store-lun-0")
	insertLUNVM(t, s, "b", "host-b", "data", "/dev/disk/by-path/ip-10.0.0.1:3260-iscsi-iqn.2020-01.com.example:store-lun-0")
	insertLUNVM(t, s, "c", "host-b", "root", "/dev/disk/by-path/ip-10.0.0.1-iscsi-iqn.2020-01.com.example:store-lun-1")
	before, err := corrosion.LiveVMDisksWithPathPrefix(ctx, s.db, "/")
	if err != nil {
		t.Fatalf("list disks: %v", err)
	}

	s.detectSharedLUNs(ctx)
	c, ok := sharedLUNCondition(t, s)
	if !ok {
		t.Fatal("two VMs on one LUN raised no condition")
	}
	if c.Lifecycle != corrosion.ConditionObserved || c.Severity != corrosion.SeverityWarning {
		t.Errorf("first scan: %s/%s, want observed/warning", c.Lifecycle, c.Severity)
	}
	var ev conditionEvidence
	if err := json.Unmarshal([]byte(c.Evidence), &ev); err != nil {
		t.Fatalf("evidence %q: %v", c.Evidence, err)
	}
	for _, want := range []string{`VM "a"`, `VM "b"`, "lun-0"} {
		if !strings.Contains(ev.Detail, want) {
			t.Errorf("evidence %s does not name %s", ev.Detail, want)
		}
	}
	if strings.Contains(ev.Detail, `VM "c"`) {
		t.Errorf("evidence names c, which is alone on its LUN: %s", c.Evidence)
	}
	if strings.Join(c.Hosts, ",") != "host-a,host-b" {
		t.Errorf("hosts = %v, want host-a,host-b", c.Hosts)
	}

	s.detectSharedLUNs(ctx)
	if c, _ = sharedLUNCondition(t, s); c.Lifecycle != corrosion.ConditionConfirmed || c.Severity != corrosion.SeverityCritical {
		t.Errorf("second scan: %s/%s, want confirmed/critical", c.Lifecycle, c.Severity)
	}

	// Starting either VM is not refused: refusing would not undo anything.
	for _, vm := range []string{"a", "b"} {
		if err := s.checkHostSafety(ctx, "host-a", corrosion.WorkloadVM, vm, true, true); err != nil {
			t.Errorf("admission for VM %s refused over the shared LUN: %v", vm, err)
		}
	}
	after, err := corrosion.LiveVMDisksWithPathPrefix(ctx, s.db, "/")
	if err != nil {
		t.Fatalf("list disks: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("disk rows %d → %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Path != after[i].Path || before[i].VMName != after[i].VMName {
			t.Errorf("disk row changed: %+v → %+v", before[i], after[i])
		}
	}

	// The operator moves b off the LUN (here: deletes it); two clean scans resolve.
	if err := corrosion.DeleteVM(ctx, s.db, "b"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	s.detectSharedLUNs(ctx)
	if c, _ = sharedLUNCondition(t, s); c.Lifecycle == corrosion.ConditionResolved {
		t.Error("resolved after one clean scan")
	}
	s.detectSharedLUNs(ctx)
	if c, _ = sharedLUNCondition(t, s); c.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("after two clean scans: %s, want resolved", c.Lifecycle)
	}
}

// One VM's own disks never count against it, and VMs on distinct LUNs raise
// nothing.
func TestSharedLUN_DistinctLUNsRaiseNothing(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertLUNVM(t, s, "a", "host-a", "root", "/dev/disk/by-path/ip-10.0.0.1-iscsi-iqn.2020-01.com.example:store-lun-0")
	insertLUNVM(t, s, "c", "host-b", "root", "/dev/disk/by-path/ip-10.0.0.1-iscsi-iqn.2020-01.com.example:store-lun-1")
	s.detectSharedLUNs(ctx)
	s.detectSharedLUNs(ctx)
	if c, ok := sharedLUNCondition(t, s); ok {
		t.Errorf("distinct LUNs raised %+v", c)
	}
}

// insertCloneVM records a linked clone whose root overlay is layered on base.
func insertCloneVM(t *testing.T, s *Server, name, host, base string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: name, HostName: host, State: "stopped", Spec: "{}"},
		nil, []corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: host,
			Path: "/var/lib/litevirt/disks/" + name + "-root.qcow2", BackingDisk: base,
			SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda"}}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// A LUN a linked clone reads from is in use. A VM whose disk is that LUN and
// that was created AFTER the clone cannot be the clone's source — its source
// was deleted with --keep-disks and the LUN taken again — so the new guest
// writes under the clone's overlay: shared. A source with its own (younger)
// clones is not.
//
// Mutation: ignore backing uses in the scan — the first case raises nothing
// and this goes red.
func TestSharedLUN_ALinkedClonesBaseTakenAgainIsShared(t *testing.T) {
	const lun = "/dev/disk/by-path/ip-10.0.0.1-iscsi-iqn.2020-01.com.example:store-lun-0"
	t.Run("clone older than the LUN's VM", func(t *testing.T) {
		s := testServerR2(t)
		insertCloneVM(t, s, "clone", "host-a", lun)
		insertLUNVM(t, s, "newcomer", "host-b", "root", lun)
		s.detectSharedLUNs(adminCtx())
		c, ok := sharedLUNCondition(t, s)
		if !ok || !strings.Contains(c.Evidence, `clone`) || !strings.Contains(c.Evidence, `newcomer`) {
			t.Fatalf("a newer VM on a linked clone's base raised %+v (ok=%v)", c, ok)
		}
	})
	t.Run("a source and its clone", func(t *testing.T) {
		s := testServerR2(t)
		insertLUNVM(t, s, "source", "host-a", "root", lun)
		insertCloneVM(t, s, "clone", "host-a", lun)
		s.detectSharedLUNs(adminCtx())
		if c, ok := sharedLUNCondition(t, s); ok {
			t.Fatalf("a source and its own clone raised %+v", c)
		}
	})
}
