package corrosion

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A vms tie settles although a VM child table differs in the same pull. The
// child's buckets widen vms in the dump (dump_scope.go), so the vms rows the
// pull carried are those of vms's own buckets AND the child's; the proof must
// compare against exactly that set, or it counts rows it did not expect and
// never settles.
func TestRecordSettledTies_ParentWidenedByChild(t *testing.T) {
	ctx := context.Background()
	const ts = "2026-01-01T00:00:00Z"
	a, b := testClient(t), testClient(t)
	for _, c := range []*Client{a, b} {
		for i := 0; i < 60; i++ {
			vm := fmt.Sprintf("vm-%02d", i)
			mustExec(t, c, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES (?, 'h1', '{}', 'running', ?, ?)`, vm, ts, ts)
			mustExec(t, c, `INSERT INTO vm_disks (vm_name, disk_name, host_name, path, size_bytes, updated_at) VALUES (?, 'root', 'h1', '/p', 10, ?)`, vm, ts)
		}
	}
	// The tie: vm-07 differs in a column no resolver rule decides, at one
	// timestamp, so both sides keep their own.
	mustExec(t, a, `UPDATE vms SET spec = '{"a":1}' WHERE name = 'vm-07'`)
	mustExec(t, b, `UPDATE vms SET spec = '{"b":1}' WHERE name = 'vm-07'`)
	if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if a.UnresolvedTieTables()["vms"] == 0 {
		t.Fatal("precondition: a vms spec tie is not tracked as unresolved")
	}
	// A child difference on b, for a VM in another bucket.
	tieBucket, _ := bucketIndexOf([]interface{}{"vm-07"})
	child := ""
	for i := 0; i < 60; i++ {
		vm := fmt.Sprintf("vm-%02d", i)
		if bk, _ := bucketIndexOf([]interface{}{vm}); bk != tieBucket {
			child = vm
			break
		}
	}
	mustExec(t, b, `UPDATE vm_disks SET size_bytes = 99, updated_at = '2026-02-01T00:00:00Z' WHERE vm_name = ?`, child)
	childBucket, _ := bucketIndexOf([]interface{}{child})

	remote := func(table string) map[int]BucketDigest {
		out := map[int]BucketDigest{}
		for _, bd := range bucketsOf(t, b, table).Buckets {
			out[bd.Index] = bd
		}
		return out
	}
	scope := &pullScope{
		buckets: map[string][]int{"vms": {tieBucket}, "vm_disks": {childBucket}},
		remote:  map[string]map[int]BucketDigest{"vms": remote("vms"), "vm_disks": remote("vm_disks")},
	}
	pull := []string{"vms", "vm_disks"}
	blob, err := b.DumpTablesScopedBytes(pull, scope.buckets)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := a.mergeRepairPull(blob, pull, scope, false)
	if err != nil {
		t.Fatal(err)
	}
	remoteDigests := map[string]*pb.TableDigest{}
	for _, d := range func() []TableDigest { ds, _ := b.StateDigest(ctx); return ds }() {
		remoteDigests[d.Name] = &pb.TableDigest{Name: d.Name, Count: int32(d.Count), Hash: d.Hash, HashV2: d.HashV2}
	}
	a.recordSettledTies(ctx, "peer-b", pull, payload, remoteDigests, scope)
	a.settled.mu.Lock()
	_, settled := a.settled.entries[settledKey("peer-b", "vms")]
	a.settled.mu.Unlock()
	if !settled {
		t.Fatal("the vms tie did not settle while a child table differed in the same pull")
	}
}
