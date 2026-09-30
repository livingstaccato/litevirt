package corrosion

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

func TestResolveTableDumpScope(t *testing.T) {
	whole := map[int]bool(nil)
	b37 := map[int]bool{3: true, 7: true}
	for _, tc := range []struct {
		name    string
		tables  []string
		buckets map[string][]int
		want    dumpScope
	}{
		{"a VM child narrows its parent to the same buckets",
			[]string{"vm_disks"}, map[string][]int{"vm_disks": {3, 7}},
			dumpScope{"vm_disks": b37, "vms": b37}},
		{"a container interface narrows its container",
			[]string{"container_interfaces"}, map[string][]int{"container_interfaces": {3, 7}},
			dumpScope{"container_interfaces": b37, "containers": b37}},
		{"operation_steps is never narrowed, nor are its parents",
			[]string{"operation_steps"}, map[string][]int{"operation_steps": {3}},
			dumpScope{"operation_steps": whole, "operations": whole, "vms": whole, "containers": whole}},
		{"a parent pulled whole for one child stays whole for another",
			[]string{"vm_disks", "operation_steps"}, map[string][]int{"vm_disks": {3}},
			dumpScope{"vm_disks": {3: true}, "vms": whole, "operation_steps": whole, "operations": whole, "containers": whole}},
		{"a table with no buckets named is whole",
			[]string{"stacks"}, nil, dumpScope{"stacks": whole}},
		{"an out-of-range bucket makes the table whole",
			[]string{"stacks"}, map[string][]int{"stacks": {3, BucketCount}}, dumpScope{"stacks": whole}},
		{"an empty bucket list is whole, not nothing",
			[]string{"stacks"}, map[string][]int{"stacks": {}}, dumpScope{"stacks": whole}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, got, err := resolveTableDumpScope(tc.tables, tc.buckets)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("scope = %v, want %v", got, tc.want)
			}
		})
	}
	if _, _, err := resolveTableDumpScope([]string{"user_credentials"}, nil); err == nil {
		t.Fatal("a sensitive table was accepted on the public lane")
	}
}

func payloadRows(t *testing.T, data []byte) map[string][][]interface{} {
	t.Helper()
	p, err := decompressPayload(data)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][][]interface{}{}
	for _, st := range p.Tables {
		out[st.Name] = st.Rows
	}
	return out
}

func TestDumpTablesScoped_CarriesOnlyTheBuckets(t *testing.T) {
	c := testClient(t)
	seedStacks(t, c, 500)
	b, _ := bucketIndexOf([]interface{}{"stack-0123"})
	var want int
	for _, bd := range bucketsOf(t, c, "stacks").Buckets {
		if bd.Index == b {
			want = bd.Count
		}
	}
	data, err := c.DumpTablesScopedBytes([]string{"stacks"}, map[string][]int{"stacks": {b}})
	if err != nil {
		t.Fatal(err)
	}
	rows := payloadRows(t, data)["stacks"]
	if len(rows) != want || want == 0 {
		t.Fatalf("scoped dump carried %d rows, bucket %d holds %d", len(rows), b, want)
	}
	found := false
	for _, r := range rows {
		if got, _ := bucketIndexOf([]interface{}{r[0]}); got != b {
			t.Fatalf("row %v from bucket %d in a dump of bucket %d", r[0], got, b)
		}
		found = found || r[0] == "stack-0123"
	}
	if !found {
		t.Fatal("the dump of stack-0123's bucket does not carry it")
	}
	whole, _ := c.DumpTablesScopedBytes([]string{"stacks"}, nil)
	if n := len(payloadRows(t, whole)["stacks"]); n != 500 {
		t.Fatalf("an unnarrowed dump carried %d rows, want 500", n)
	}

	// Sensitive lane: named tables only, narrowed the same way.
	for i := 0; i < 50; i++ {
		mustExec(t, c, `INSERT INTO registry_credentials (id, registry, username, secret, created_at, updated_at) VALUES (?, ?, 'u', 's', 'x', 'x')`, fmt.Sprintf("rc-%02d", i), fmt.Sprintf("reg-%02d", i))
	}
	rb, _ := bucketIndexOf([]interface{}{"rc-07"})
	sens := payloadRows(t, c.DumpSensitiveTablesScopedBytes([]string{"registry_credentials", "stacks"}, map[string][]int{"registry_credentials": {rb}}))
	if _, leaked := sens["stacks"]; leaked {
		t.Fatal("the sensitive dump carried a public table")
	}
	for _, r := range sens["registry_credentials"] {
		if got, _ := bucketIndexOf([]interface{}{r[0]}); got != rb {
			t.Fatalf("sensitive row %v outside bucket %d", r[0], rb)
		}
	}
	if len(sens["registry_credentials"]) == 0 {
		t.Fatal("the narrowed sensitive dump is empty")
	}
}

// The settled-tie proof over a narrowed pull: it compares only the pulled
// buckets row by row, and every other bucket must agree with the peer's bucket
// digest.
func TestResidualIsTrackedTies_NarrowedToBuckets(t *testing.T) {
	ctx := context.Background()
	const ts = "2026-01-01T00:00:00Z"
	a, b := newTestDB(t), newTestDB(t)
	for i := 1; i <= 300; i++ {
		putLeaseTerm(t, a, "bulk", int64(i), "h", ts, ts)
		putLeaseTerm(t, b, "bulk", int64(i), "h", ts, ts)
	}
	putLeaseTerm(t, a, "dual_run_detector", 2, "host-a", ts, ts)
	putLeaseTerm(t, b, "dual_run_detector", 2, "host-b", ts, ts)
	if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	tieBucket, _ := bucketIndexOf([]interface{}{"dual_run_detector", int64(2)})
	inPull := map[int]bool{tieBucket: true}
	remoteBuckets := func() map[int]BucketDigest {
		out := map[int]BucketDigest{}
		for _, bd := range bucketsOf(t, b, "leader_lease_terms").Buckets {
			out[bd.Index] = bd
		}
		return out
	}
	narrowed := func() syncTable {
		p, err := decompressPayload(b.dumpStateForScope([]string{"leader_lease_terms"}, dumpScope{"leader_lease_terms": inPull}))
		if err != nil || len(p.Tables) != 1 {
			t.Fatalf("narrowed dump: %v", err)
		}
		return p.Tables[0]
	}

	local, ties, ok := a.residualIsTrackedTies(ctx, narrowed(), inPull, remoteBuckets())
	if !ok || len(ties) != 1 {
		t.Fatalf("a narrowed pull differing only by the tracked tie was not proven: ok=%v ties=%v", ok, ties)
	}
	digests, _ := a.stateDigestForTables(ctx, []string{"leader_lease_terms"})
	if !sameDigest(local, digests[0]) {
		t.Fatalf("the proof's local digest %+v is not the table digest %+v", local, digests[0])
	}

	// A difference in a bucket the pull did NOT carry must fail the proof.
	var other int64
	for i := int64(1); i <= 300; i++ {
		if bk, _ := bucketIndexOf([]interface{}{"bulk", i}); bk != tieBucket {
			other = i
			break
		}
	}
	putLeaseTerm(t, b, "bulk", other, "moved", ts, ts)
	if _, _, ok := a.residualIsTrackedTies(ctx, narrowed(), inPull, remoteBuckets()); ok {
		t.Fatal("proven settled although a bucket outside the pull differs from the peer's")
	}
	putLeaseTerm(t, b, "bulk", other, "h", ts, ts)

	// A row this node holds in an unpulled bucket the peer has no rows in.
	putLeaseTerm(t, a, "zz-only-a", 1, "h", ts, ts)
	if bk, _ := bucketIndexOf([]interface{}{"zz-only-a", int64(1)}); bk != tieBucket {
		if _, _, ok := a.residualIsTrackedTies(ctx, narrowed(), inPull, remoteBuckets()); ok {
			t.Fatal("proven settled although this node holds a row in a bucket the peer's digests do not")
		}
	}
}

func TestDifferingBucketIndexes(t *testing.T) {
	x := BucketDigest{Count: 1, Hash: "a"}
	local := map[int]BucketDigest{1: x, 2: x, 3: x, 4: {Count: 1, Hash: "a", HashV2: "v"}}
	remote := map[int]BucketDigest{
		1: x,                     // agrees
		2: {Count: 1, Hash: "b"}, // hash differs
		// 3 is on this side only
		4: {Count: 1, Hash: "other-v1", HashV2: "v"}, // both carry v2, and it agrees
		5: x,                                         // on the peer only
	}
	if got := differingBucketIndexes(local, remote); !reflect.DeepEqual(got, []int{2, 3, 5}) {
		t.Fatalf("differing buckets %v, want [2 3 5]", got)
	}
}
