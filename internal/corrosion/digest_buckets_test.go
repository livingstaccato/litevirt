package corrosion

import (
	"context"
	"fmt"
	"testing"
)

// seedStacks writes n stacks rows directly (no mutation_log), named
// stack-0000.., all with one fixed timestamp so two clients seeded alike hold
// byte-identical rows.
func seedStacks(t *testing.T, c *Client, n int) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := tx.Exec(`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
			VALUES (?, 'h', 'services: {}', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
			fmt.Sprintf("stack-%04d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func bucketsOf(t *testing.T, c *Client, table string) TableBuckets {
	t.Helper()
	for _, tb := range c.TableBucketDigests(context.Background(), []string{table}) {
		if tb.Name == table {
			return tb
		}
	}
	t.Fatalf("no bucket digests for %s", table)
	return TableBuckets{}
}

func digestOf(t *testing.T, ds []TableDigest, table string) TableDigest {
	t.Helper()
	for _, d := range ds {
		if d.Name == table {
			return d
		}
	}
	t.Fatalf("no digest for %s", table)
	return TableDigest{}
}

// differingBuckets is the set of bucket indexes whose digests disagree,
// including a bucket only one side has.
func differingBuckets(a, b TableBuckets) []int {
	am := map[int]BucketDigest{}
	for _, x := range a.Buckets {
		am[x.Index] = x
	}
	bm := map[int]BucketDigest{}
	for _, x := range b.Buckets {
		bm[x.Index] = x
	}
	var out []int
	for i := 0; i < BucketCount; i++ {
		x, xok := am[i]
		y, yok := bm[i]
		if xok != yok || x != y {
			out = append(out, i)
		}
	}
	return out
}

// The bucket function is part of the wire protocol: two builds must agree on
// which rows a bucket holds. These vectors pin BucketScheme 1.
func TestBucketIndex_GoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		cells []interface{}
		want  int
	}{
		{[]interface{}{"web-1"}, goldenBucketWeb1},
		{[]interface{}{"node-a", "ct-1"}, goldenBucketNodeACt1},
		{[]interface{}{int64(42)}, goldenBucket42},
		{[]interface{}{nil}, goldenBucketNil},
	} {
		got, ok := bucketIndexOf(tc.cells)
		if !ok || got != tc.want {
			t.Errorf("bucketIndexOf(%v) = %d,%v, want %d", tc.cells, got, ok, tc.want)
		}
	}
	// A number read back from a JSON payload is a float64; it must bucket
	// with the int64 SQLite returned.
	a, _ := bucketIndexOf([]interface{}{int64(42)})
	b, _ := bucketIndexOf([]interface{}{float64(42)})
	if a != b {
		t.Errorf("int64 42 -> %d, float64 42 -> %d: a JSON round trip moves a row's bucket", a, b)
	}
}

const (
	goldenBucketWeb1     = 250
	goldenBucketNodeACt1 = 232
	goldenBucket42       = 37
	goldenBucketNil      = 40
)

// A VM child is merged against the vms row that has its vm_name, and a
// container interface against its containers row, so each must share a bucket
// with its parent — or a bucketed pull of the child carries a repair the merge
// then refuses for want of its parent.
func TestBucketKey_ChildSharesItsParentsBucket(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	now := "2026-01-01T00:00:00Z"
	for i := 0; i < 40; i++ {
		vm := fmt.Sprintf("vm-%02d", i)
		mustExec(t, c, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES (?, 'h1', '{}', 'running', ?, ?)`, vm, now, now)
		mustExec(t, c, `INSERT INTO vm_disks (vm_name, disk_name, host_name, path, size_bytes, updated_at) VALUES (?, 'root', 'h1', '/p', 10, ?)`, vm, now)
		ct := fmt.Sprintf("ct-%02d", i)
		mustExec(t, c, `INSERT INTO containers (host_name, name, image, state, created_at, updated_at) VALUES ('h1', ?, 'img', 'running', ?, ?)`, ct, now, now)
		mustExec(t, c, `INSERT INTO container_interfaces (host_name, ct_name, ordinal, network_name, mac, updated_at) VALUES ('h1', ?, 0, 'net', 'aa:bb', ?)`, ct, now)
	}
	for _, pair := range [][2]string{{"vms", "vm_disks"}, {"containers", "container_interfaces"}} {
		sets := c.tableDigestSets(ctx, pair[:], true)
		if len(sets) != 2 || !sets[0].bucketed || !sets[1].bucketed {
			t.Fatalf("%v: not both bucketed: %+v", pair, sets)
		}
		parent, child := sets[0].buckets, sets[1].buckets
		if len(child) < 2 {
			t.Fatalf("%v: 40 keys landed in %d buckets; the test cannot tell buckets apart", pair, len(child))
		}
		for idx, cb := range child {
			pb, ok := parent[idx]
			if !ok || pb.Count != cb.Count {
				t.Errorf("%s bucket %d holds %d rows; %s holds %+v there", pair[1], idx, cb.Count, pair[0], pb)
			}
		}
	}
}

func mustExec(t *testing.T, c *Client, q string, args ...interface{}) {
	t.Helper()
	c.mu.Lock()
	_, err := c.db.Exec(q, args...)
	c.mu.Unlock()
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// The table digest is what an older peer compares, so bucketing must not
// change a byte of it.
func TestTableDigest_UnchangedByBuckets(t *testing.T) {
	c := testClient(t)
	seedStacks(t, c, 50)
	c.mu.RLock()
	rows, err := c.db.Query(`SELECT * FROM stacks`)
	if err != nil {
		c.mu.RUnlock()
		t.Fatal(err)
	}
	cols, _ := rows.Columns()
	var keys []string
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, encodeRowCells(vals))
	}
	rows.Close()
	c.mu.RUnlock()
	want := TableDigest{Name: "stacks", Count: len(keys), Hash: hashRowKeys(keys)}

	ds, _ := c.StateDigest(context.Background())
	got := digestOf(t, ds, "stacks")
	got.HashV2 = "" // the v1 construction is what an older peer compares
	if got != want {
		t.Fatalf("stacks digest = %+v, want the pre-bucket construction %+v", got, want)
	}
	tb := bucketsOf(t, c, "stacks")
	total := 0
	for _, b := range tb.Buckets {
		total += b.Count
	}
	if !tb.Bucketed || total != 50 {
		t.Fatalf("buckets: bucketed=%v rows=%d, want true/50", tb.Bucketed, total)
	}
}

// One row that differs moves exactly its own bucket.
func TestBucketDigests_OneDifferingRowIsOneBucket(t *testing.T) {
	a, b := testClient(t), testClient(t)
	a.SetDigestV2Enabled(func() bool { return true })
	b.SetDigestV2Enabled(func() bool { return true })
	seedStacks(t, a, 500)
	seedStacks(t, b, 500)
	if d := differingBuckets(bucketsOf(t, a, "stacks"), bucketsOf(t, b, "stacks")); len(d) != 0 {
		t.Fatalf("identical tables differ in buckets %v", d)
	}
	mustExec(t, b, `UPDATE stacks SET state = 'failed', updated_at = '2026-02-01T00:00:00Z' WHERE name = 'stack-0123'`)
	want, _ := bucketIndexOf([]interface{}{"stack-0123"})
	d := differingBuckets(bucketsOf(t, a, "stacks"), bucketsOf(t, b, "stacks"))
	if len(d) != 1 || d[0] != want {
		t.Fatalf("differing buckets %v, want exactly [%d]", d, want)
	}
	for _, x := range bucketsOf(t, a, "stacks").Buckets {
		if x.HashV2 == "" {
			t.Fatalf("bucket %d has no v2 hash with digest_v2 on", x.Index)
		}
	}
}

// operation_steps is never bucketed: its merge reads the workload its
// operation names, which no bucket key can co-locate.
func TestBucketKey_OperationStepsIsWhole(t *testing.T) {
	c := testClient(t)
	if tb := bucketsOf(t, c, "operation_steps"); tb.Bucketed {
		t.Fatal("operation_steps reported as bucketed")
	}
	if tb := bucketsOf(t, c, "operations"); !tb.Bucketed {
		t.Fatal("operations should bucket by id")
	}
}

// ── the digest cache ──

func cacheCounts(f *fakeSyncMetrics) (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.digestCached, f.digestComputed
}

func withMetrics(c *Client) *fakeSyncMetrics {
	f := &fakeSyncMetrics{}
	c.SetSyncMetrics(f)
	return f
}

func TestDigestCache_ServesAnUnchangedTable(t *testing.T) {
	c := testClient(t)
	f := withMetrics(c)
	seedStacks(t, c, 20)
	ctx := context.Background()
	d1, _ := c.StateDigestCached(ctx)
	_, computedBefore := cacheCounts(f)
	d2, _ := c.StateDigestCached(ctx)
	cachedN, computedAfter := cacheCounts(f)
	first, second := digestOf(t, d1, "stacks"), digestOf(t, d2, "stacks")
	if computedAfter != computedBefore {
		t.Fatalf("second digest of unchanged tables scanned %d tables", computedAfter-computedBefore)
	}
	if cachedN == 0 || first != second {
		t.Fatalf("cached=%d first=%+v second=%+v", cachedN, first, second)
	}
}

// Every way a row can change must invalidate the table's entry: after each
// write the cached digest must equal a fresh scan.
func TestDigestCache_EveryWritePathInvalidates(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, c *Client, suffix string)
	}{
		{"Execute", func(t *testing.T, c *Client, suffix string) {
			if err := c.Execute(ctx, `UPDATE stacks SET state = 'x', updated_at = '2026-03-01T00:00:00Z' WHERE name = 'stack-0001'`); err != nil {
				t.Fatal(err)
			}
		}},
		{"raw DB handle", func(t *testing.T, c *Client, suffix string) {
			if _, err := c.DB().Exec(`UPDATE stacks SET state = 'y' WHERE name = 'stack-0002'`); err != nil {
				t.Fatal(err)
			}
		}},
		{"DELETE without WHERE", func(t *testing.T, c *Client, suffix string) {
			if _, err := c.DB().Exec(`DELETE FROM stacks`); err != nil {
				t.Fatal(err)
			}
		}},
		{"anti-entropy merge", func(t *testing.T, c *Client, suffix string) {
			peer := testClient(t)
			mustExec(t, peer, `INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
				VALUES ('from-peer', 'h', 'y', 'active', '2026-04-01T00:00:00Z', '2026-04-01T00:00:00Z')`)
			if err := c.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
				t.Fatal(err)
			}
		}},
		{"another client on the same database", func(t *testing.T, c *Client, suffix string) {
			other, err := NewSharedTestClient(suffix, "other")
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if _, err := other.DB().Exec(`UPDATE stacks SET state = 'z' WHERE name = 'stack-0003'`); err != nil {
				t.Fatal(err)
			}
		}},
		{"schema change", func(t *testing.T, c *Client, suffix string) {
			if _, err := c.DB().Exec(`ALTER TABLE stacks ADD COLUMN zz_extra TEXT DEFAULT 'q'`); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, suffix := sharedDigestClient(t)
			seedStacks(t, c, 10)
			before, _ := c.StateDigestCached(ctx)
			tc.write(t, c, suffix)
			cached, _ := c.StateDigestCached(ctx)
			fresh, _ := c.StateDigest(ctx)
			got, want := digestOf(t, cached, "stacks"), digestOf(t, fresh, "stacks")
			if got != want {
				t.Fatalf("cached digest %+v after the write, a fresh scan says %+v", got, want)
			}
			if digestOf(t, before, "stacks") == want {
				t.Fatal("precondition: the write did not change the digest")
			}
		})
	}
}

// sharedDigestClient is a test client on a named shared-cache database, so a
// second client can open the same one.
func sharedDigestClient(t *testing.T) (*Client, string) {
	t.Helper()
	suffix := fmt.Sprintf("digestcache%d", testDBCounter.Add(1))
	c, err := NewSharedTestClient(suffix, "test-node")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c, suffix
}

func TestDigestCache_BoundedByAgeFlagAndStandDown(t *testing.T) {
	ctx := context.Background()
	scans := func(c *Client, f *fakeSyncMetrics) int {
		_, before := cacheCounts(f)
		if _, err := c.StateDigestCached(ctx); err != nil {
			t.Fatal(err)
		}
		_, after := cacheCounts(f)
		return after - before
	}

	t.Run("max age", func(t *testing.T) {
		c := testClient(t)
		f := withMetrics(c)
		scans(c, f)
		old := digestCacheMaxAge
		digestCacheMaxAge = 0
		defer func() { digestCacheMaxAge = old }()
		if n := scans(c, f); n == 0 {
			t.Fatal("an entry past digestCacheMaxAge was served")
		}
	})
	t.Run("digest_v2 flag", func(t *testing.T) {
		c := testClient(t)
		f := withMetrics(c)
		seedStacks(t, c, 3)
		c.SetDigestV2Enabled(func() bool { return false })
		before, _ := c.StateDigestCached(ctx)
		c.SetDigestV2Enabled(func() bool { return true })
		after, _ := c.StateDigestCached(ctx)
		if digestOf(t, after, "stacks").HashV2 == "" || digestOf(t, before, "stacks").HashV2 != "" {
			t.Fatal("the v1-only entry was served after digest_v2 was turned on")
		}
		if _, computed := cacheCounts(f); computed == 0 {
			t.Fatal("nothing was scanned")
		}
	})
	t.Run("stand-down", func(t *testing.T) {
		c := testClient(t)
		f := withMetrics(c)
		scans(c, f)
		c.SetDigestCacheEnabled(false)
		scans(c, f)
		if n := scans(c, f); n == 0 {
			t.Fatal("the cache served a digest while disabled")
		}
	})
	t.Run("fresh digest always scans", func(t *testing.T) {
		c := testClient(t)
		f := withMetrics(c)
		scans(c, f)
		_, before := cacheCounts(f)
		if _, err := c.StateDigest(ctx); err != nil {
			t.Fatal(err)
		}
		if _, after := cacheCounts(f); after == before {
			t.Fatal("StateDigest (fresh) scanned nothing")
		}
	})
}
