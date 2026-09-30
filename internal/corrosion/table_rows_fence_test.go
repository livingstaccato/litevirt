package corrosion

import (
	"context"
	"testing"
)

// mergePaged merges source's whole public lane into receiver over the paged
// pull, with pages small enough that every table spans several.
func mergePaged(t *testing.T, receiver, source *Client) {
	t.Helper()
	withPageBounds(t, 2, 1<<20)
	pages := collectPages(t, source, tableNames, nil)
	if _, _, perr, merr := receiver.mergeTableRowsStream(replay(pages), replicatedTableSet, nil); perr != nil || merr != nil {
		t.Fatalf("paged merge: pull=%v merge=%v", perr, merr)
	}
}

// The workload-authority fence (TestCreateOperationAntiEntropyFencesStaleWorkloadAuthority)
// over the PAGED pull: a create commit from a source whose workload authority
// is older than the receiver's must not land its child rows or steps. The
// children are judged against the manifest built from every parent page, so a
// paged merge that judged them without it would apply them.
func TestStreamTableRows_FencesStaleWorkloadAuthority(t *testing.T) {
	ctx := context.Background()

	t.Run("vm", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-paged-vm", "vm", "vm1", "hash", "", 1)
		vm := VMRecord{Name: "vm1", HostName: "h1", Project: "p1", Spec: `{"cpu":2}`, OwnerEpoch: 1, SpecGeneration: 1}
		if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.CommitVMCreateOperation(ctx, op.ID, 1, vm,
			[]InterfaceRecord{{NetworkName: "net1", MAC: "52:54:00:00:00:01"}},
			[]DiskRecord{{DiskName: "root", HostName: "h1", Path: "/vm1.img"}},
			[]NICRecord{{ID: "nic1", NetworkName: "net1"}}, nil,
		); err != nil || !applied {
			t.Fatalf("source commit: applied=%v err=%v", applied, err)
		}
		receiver := testClient(t)
		if err := InsertVM(ctx, receiver, VMRecord{
			Name: "vm1", HostName: "h2", Project: "p1", Spec: `{"cpu":8}`,
			State: "running", OwnerEpoch: 2, SpecGeneration: 2,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.db.Exec(`UPDATE vms SET vm_owner_epoch = 2, spec_generation = 2, updated_at = ? WHERE name = ?`,
			"9000000000000-0000-newer", "vm1"); err != nil {
			t.Fatal(err)
		}
		mergePaged(t, receiver, source)
		for _, table := range []string{"vm_interfaces", "vm_disks", "vm_nics"} {
			if rows, _ := receiver.Query(ctx, `SELECT 1 FROM `+table+` WHERE vm_name = ?`, "vm1"); len(rows) != 0 {
				t.Errorf("stale paged commit wrote %s: %v", table, rows)
			}
		}
		assertNoOperationSteps(t, receiver, op.ID)
	})

	t.Run("container", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-paged-ct", "container", "ct1", "hash", "", 1)
		ct := ContainerRecord{HostName: "h1", Name: "ct1", Image: "alpine", Project: "p1",
			CreateSpec: `{"template":"alpine"}`, OwnerEpoch: 1, SpecGeneration: 1}
		if applied, err := source.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.CommitContainerCreateOperation(ctx, op.ID, 1, ct,
			[]ContainerInterfaceRecord{{NetworkName: "net1", MAC: "52:00:00:00:00:01"}}); err != nil || !applied {
			t.Fatalf("source commit: applied=%v err=%v", applied, err)
		}
		receiver := testClient(t)
		if err := UpsertContainer(ctx, receiver, ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "debian", Project: "p1",
			State: "running", OwnerEpoch: 2, SpecGeneration: 2,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.db.Exec(`UPDATE containers SET owner_epoch = 2, spec_generation = 2, updated_at = ? WHERE host_name = ? AND name = ?`,
			"9000000000000-0000-newer", "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		mergePaged(t, receiver, source)
		if rows, _ := receiver.Query(ctx, `SELECT 1 FROM container_interfaces WHERE host_name = ? AND ct_name = ?`, "h1", "ct1"); len(rows) != 0 {
			t.Errorf("stale paged commit wrote container interfaces: %v", rows)
		}
		assertNoOperationSteps(t, receiver, op.ID)
	})

	// The control: the same kind of commit over the paged pull DOES land on a
	// receiver with no newer authority, so the fence above is the manifest's
	// doing and not a pull that carried nothing.
	t.Run("vm without a newer authority converges", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-paged-ok", "vm", "vm2", "hash", "", 1)
		vm := VMRecord{Name: "vm2", HostName: "h1", Project: "p1", Spec: `{"cpu":2}`, OwnerEpoch: 1, SpecGeneration: 1}
		if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.CommitVMCreateOperation(ctx, op.ID, 1, vm, nil,
			[]DiskRecord{{DiskName: "root", HostName: "h1", Path: "/vm2.img"}}, nil, nil); err != nil || !applied {
			t.Fatalf("source commit: applied=%v err=%v", applied, err)
		}
		receiver := testClient(t)
		mergePaged(t, receiver, source)
		if rows, _ := receiver.Query(ctx, `SELECT 1 FROM vm_disks WHERE vm_name = ?`, "vm2"); len(rows) != 1 {
			t.Fatalf("a current-authority commit did not land over the paged pull: %v", rows)
		}
	})
}
