package health

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review c2b: a path this host released is refused to every start of a
// domain that uses it — another VM's, or the released VM's own while its row
// names another host — and allowed again once the released VM's own row for
// the disk names this host (it came back with the disk). A domain not using
// the path is never touched.
//
// Mutation "no release check" (GuardSharedDiskStart allows everything) — red.
func TestGuardSharedDiskStart(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	unlock := LockSharedDiskStarts()
	if err := RecordSharedDiskRelease(dir, SharedDiskRelease{Path: "/nfs/db-data1.qcow2", VM: "db", Disk: "data1", Requester: "node-c"}); err != nil {
		t.Fatal(err)
	}
	unlock()
	uses := `<domain><devices><disk><source file="/nfs/db-data1.qcow2"/></disk></devices></domain>`
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "db", HostName: "node-c", State: "running", Spec: `{}`}, nil,
		[]corrosion.DiskRecord{{VMName: "db", DiskName: "data1", HostName: "node-c", Path: "/nfs/db-data1.qcow2", StorageType: "nfs"}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, vm, xml string
		refused       bool
	}{
		{"another VM using it", "intruder", uses, true},
		{"the released VM, its row elsewhere", "db", uses, true},
		{"a domain not using it", "other", `<domain><devices><disk><source file="/nfs/x.qcow2"/></disk></devices></domain>`, false},
	} {
		release, err := GuardSharedDiskStart(ctx, db, dir, "node-b", c.vm, c.xml)
		if (err != nil) != c.refused {
			t.Errorf("%s: err = %v, want refused=%v", c.name, err, c.refused)
		}
		if err == nil {
			release()
		} else if !strings.Contains(err.Error(), "released to node-c") {
			t.Errorf("%s: refusal %q does not say what was released", c.name, err)
		}
	}
	// The VM came back with its disk.
	if err := db.Execute(ctx, `UPDATE vm_disks SET host_name = 'node-b' WHERE vm_name = 'db'`); err != nil {
		t.Fatal(err)
	}
	release, err := GuardSharedDiskStart(ctx, db, dir, "node-b", "db", uses)
	if err != nil {
		t.Fatalf("the released VM back on node-b with its disk: %v", err)
	}
	release()
}

// Review m2: with a release on record, a start whose definition cannot be
// read is refused, not run unchecked. Review m6: a release whose VM no longer
// exists protects nothing and refuses nothing; the refusal names the record.
//
// Mutation "unreadable definition passes" — red on the first half; mutation
// "a deleted VM's release still refuses" — red on the second.
func TestGuardSharedDiskStart_UnreadableDefinitionAndDeletedVM(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	unlock := LockSharedDiskStarts()
	if err := RecordSharedDiskRelease(dir, SharedDiskRelease{Path: "/nfs/gone-data1.qcow2", VM: "gone", Disk: "data1", Requester: "node-c"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordSharedDiskRelease(dir, SharedDiskRelease{Path: "/nfs/db-data1.qcow2", VM: "db", Disk: "data1", Requester: "node-c"}); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "db", HostName: "node-c", State: "running", Spec: `{}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := GuardSharedDiskStart(ctx, db, dir, "node-b", "x", ""); err == nil {
		t.Error("a start whose definition cannot be read ran unchecked against the releases on record")
	}
	release, err := GuardSharedDiskStart(ctx, db, dir, "node-b", "x",
		`<domain><devices><disk><source file="/nfs/gone-data1.qcow2"/></disk></devices></domain>`)
	if err != nil {
		t.Errorf("a release for a deleted VM refused a start: %v", err)
	} else {
		release()
	}
	_, err = GuardSharedDiskStart(ctx, db, dir, "node-b", "x",
		`<domain><devices><disk><source file="/nfs/db-data1.qcow2"/></disk></devices></domain>`)
	if err == nil || !strings.Contains(err.Error(), "shared-disk-released") {
		t.Errorf("refusal = %v, want it to name the release record", err)
	}
}
