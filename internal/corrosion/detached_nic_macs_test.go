package corrosion

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A bound successful NIC detach marks its MAC after the reaper tombstones
// both its header and completed step.
//
// Mutation: read live headers only (deleted_at IS NULL) — the reaped check
// goes red.
func TestDetachedNICMACs_AReapedDetachStillMarksTheMAC(t *testing.T) {
	const mac = "52:54:00:aa:dd:01"
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	op := OperationRecord{ID: DeterministicOperationID("DetachDevice", "p", "", "vm1", "k1"),
		Method: "DetachDevice", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpDeviceDetach), RequestHash: NICDetachRequestHash("vm1", mac)}
	if _, err := c.BeginVMOperation(ctx, op, "{}", 0, 0); err != nil {
		t.Fatalf("begin: %v", err)
	}
	vm, err := GetVM(ctx, c, "vm1")
	if err != nil || vm == nil {
		t.Fatal(vm, err)
	}
	if _, err := c.CompleteVMNICDetach(ctx, "vm1", op.ID, 0, 1, vm.CreatedAt, mac); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got, err := DetachedNICMACs(ctx, c, "vm1", []string{strings.ToUpper(mac), "52:54:00:aa:dd:02"}); err != nil || !got[mac] || len(got) != 1 {
		t.Fatalf("live header: %v, %v; want only %s", got, err, mac)
	}
	ageOperationSteps(t, c, op.ID, "2020-01-01T00:00:00Z")
	if n, _, err := ReapTerminalOperations(ctx, c, time.Hour); err != nil || n != 1 {
		t.Fatalf("reap: n=%d err=%v", n, err)
	}
	if got, err := DetachedNICMACs(ctx, c, "vm1", []string{mac}); err != nil || !got[mac] {
		t.Fatalf("reaped header: %v, %v; want %s still marked", got, err, mac)
	}
}

// DetachedNICMACs relies on operation headers never being removed: a
// hard delete of a reaped NIC-detach header would make a NIC attached again
// under that MAC render the detached NIC's model. No Go source under the
// module's internal/ or cmd/ may delete from operations. Only those two are
// walked: the module root of a checkout can hold other trees (worktrees of
// other branches under .claude/), whose statements are not this one's.
//
// Mutation: add a `DELETE FROM operations` statement in internal/ or cmd/ —
// red.
func TestOperationHeadersAreNeverHardDeleted(t *testing.T) {
	del := regexp.MustCompile("(?is)DELETE\\s+FROM\\s+[\"`]?operations[\"`]?(\\s|$|;|`)")
	var hits []string
	for _, dir := range []string{"internal", "cmd"} {
		root, err := filepath.Abs(filepath.Join("..", "..", dir))
		if err != nil {
			t.Fatal(err)
		}
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			if del.Match(b) {
				hits = append(hits, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(hits) > 0 {
		t.Fatalf("operation headers are hard-deleted in %v; DetachedNICMACs needs them kept (soft-delete only)", hits)
	}
}

// A render reads the operations only for a NIC whose vm_nics row and spec
// entry disagree on its model; when they agree the answer is the same either
// way, and no detach is looked up.
//
// Mutation: look the detaches up for every NIC — the agreeing NIC is marked.
func TestNICModelSources_ReadsDetachesOnlyOnADisagreement(t *testing.T) {
	const agree, differ = "52:54:00:aa:dd:01", "52:54:00:aa:dd:02"
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "stopped", Spec: "{}"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	vm, err := GetVM(ctx, c, "vm1")
	if err != nil || vm == nil {
		t.Fatal(vm, err)
	}
	for _, n := range []NICRecord{
		{VMName: "vm1", ID: DeterministicNICID("vm1", agree), NetworkName: "lan", Model: "e1000", MAC: agree},
		{VMName: "vm1", ID: DeterministicNICID("vm1", differ), NetworkName: "lan2", Model: "virtio", MAC: differ, Ordinal: 1},
	} {
		if err := UpsertNIC(ctx, c, n); err != nil {
			t.Fatal(err)
		}
	}
	for i, mac := range []string{agree, differ} {
		op := OperationRecord{ID: "op-" + mac, Method: "DetachDevice", ResourceKind: "vm", ResourceID: "vm1", OperationKind: string(OpDeviceDetach), RequestHash: NICDetachRequestHash("vm1", mac)}
		if applied, err := c.BeginVMOperation(ctx, op, vm.Spec, 0, int64(i)); err != nil || !applied {
			t.Fatal(applied, err)
		}
		if applied, err := c.CompleteVMNICDetach(ctx, "vm1", op.ID, 0, int64(i+1), vm.CreatedAt, mac); err != nil || !applied {
			t.Fatal(applied, err)
		}
	}
	nics, err := MergedVMNICs(ctx, c, "vm1")
	if err != nil {
		t.Fatal(err)
	}
	_, reattached, err := NICModelSources(ctx, c, "vm1", nics, map[string]string{agree: "e1000", differ: "e1000"})
	if err != nil {
		t.Fatal(err)
	}
	if reattached[agree] || !reattached[differ] {
		t.Fatalf("reattached = %v, want only %s", reattached, differ)
	}
}
