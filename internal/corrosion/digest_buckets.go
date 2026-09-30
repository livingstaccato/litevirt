package corrosion

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"sort"
	"strconv"
	"time"
)

// Bucketed table digests (colonelpanik/litevirt#262,
// docs/design/ae-incremental.md).
//
// A table's rows are split into BucketCount buckets by a hash of a bucket key,
// and each bucket gets a count and hash built exactly the way the table's own
// digest is (hashRowKeys over the rows' encodings). Two tables whose digests
// disagree then only need the buckets that disagree pulled, not every row.
//
// The bucket key keeps together the rows a merge reads from ONE payload: a VM
// child is judged against the vms row with its vm_name, a container interface
// against its containers row (anti_entropy_authority.go). Keying parent and
// children by the same value puts them in the same bucket, so a pull of some
// buckets of a child table plus the same buckets of its parent carries every
// parent row those children can name.

const (
	// BucketScheme versions the bucket function, the bucket keys and
	// BucketCount together. A peer answering with another scheme is treated
	// as one that cannot bucket.
	BucketScheme = 1
	// BucketCount is how many buckets a table is split into.
	BucketCount = 256
)

// bucketKeyColumns names the columns a table's rows are bucketed by, or nil
// when the table is not bucketed (it is always pulled whole).
func bucketKeyColumns(table string) []string {
	switch {
	case table == "vms":
		return []string{"name"}
	case vmAuthorityChildTables[table]:
		return []string{"vm_name"}
	case table == "containers":
		return []string{"host_name", "name"}
	case table == "container_interfaces":
		return []string{"host_name", "ct_name"}
	case table == "operation_steps":
		// Its merge reads the operation AND the workload that operation
		// names; no one key co-locates both, so it is pulled whole, with its
		// parents whole, exactly as before buckets existed.
		return nil
	}
	return tablePrimaryKeys[table]
}

// bucketIndexOf maps a row's bucket-key cells to a bucket. The table name is
// deliberately not hashed, so co-keyed tables share buckets.
//
// BYTE-FROZEN for BucketScheme 1 (TestBucketIndex_GoldenVectors): changing it
// makes two builds disagree about which rows a bucket holds.
func bucketIndexOf(cells []interface{}) (int, bool) {
	h := sha256.New()
	for _, v := range cells {
		if v == nil {
			h.Write([]byte("N;"))
			continue
		}
		cv, err := canonicalCellValue(v)
		if err != nil {
			return 0, false
		}
		h.Write([]byte("V" + strconv.Itoa(len(cv)) + ":" + cv))
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return int(sum[0]) % BucketCount, true
}

// rowBucket is bucketIndexOf over the key columns at keyIdx.
func rowBucket(row []interface{}, keyIdx []int) (int, bool) {
	cells := make([]interface{}, len(keyIdx))
	for i, k := range keyIdx {
		if k >= len(row) {
			return 0, false
		}
		cells[i] = row[k]
	}
	return bucketIndexOf(cells)
}

// BucketDigest is one bucket's count and hashes. Buckets with no rows are not
// represented.
type BucketDigest struct {
	Index  int
	Count  int
	Hash   string
	HashV2 string
}

// TableBuckets is one table's bucket digests. Bucketed is false when the
// table cannot be bucketed (no bucket key, a key column missing, a key cell
// that does not canonicalise): it must then be pulled whole.
type TableBuckets struct {
	Name     string
	Bucketed bool
	Buckets  []BucketDigest // ascending Index
}

// tableDigestSet is what one scan of a table yields: the table digest every
// peer compares, and its bucket digests.
type tableDigestSet struct {
	digest   TableDigest
	bucketed bool
	buckets  map[int]BucketDigest
}

func (s tableDigestSet) tableBuckets() TableBuckets {
	tb := TableBuckets{Name: s.digest.Name, Bucketed: s.bucketed}
	if !s.bucketed {
		return tb
	}
	tb.Buckets = make([]BucketDigest, 0, len(s.buckets))
	for _, b := range s.buckets {
		tb.Buckets = append(tb.Buckets, b)
	}
	sort.Slice(tb.Buckets, func(i, j int) bool { return tb.Buckets[i].Index < tb.Buckets[j].Index })
	return tb
}

// tableScanKeys are one table's row encodings, read under the lock and hashed
// outside it.
type tableScanKeys struct {
	v1, v2   []string
	v2ok     bool
	bucketed bool
	bv1, bv2 map[int][]string
}

func (k tableScanKeys) digestSet(table string) tableDigestSet {
	set := tableDigestSet{
		digest:   TableDigest{Name: table, Count: len(k.v1)},
		bucketed: k.bucketed,
	}
	if k.bucketed {
		// Before hashRowKeys sorts the whole-table slices in place: the bucket
		// slices hold the same strings, not the same backing array.
		set.buckets = make(map[int]BucketDigest, len(k.bv1))
		for b, keys := range k.bv1 {
			bd := BucketDigest{Index: b, Count: len(keys), Hash: hashRowKeys(keys)}
			if k.v2ok {
				bd.HashV2 = hashRowKeys(k.bv2[b])
			}
			set.buckets[b] = bd
		}
	}
	set.digest.Hash = hashRowKeys(k.v1)
	if k.v2ok {
		set.digest.HashV2 = hashRowKeys(k.v2) // order-invariant; sort makes row order irrelevant
	}
	return set
}

// scanTableDigest reads one table's row encodings under a brief read lock,
// together with the table's generation as of that lock (digest_cache.go).
//
// Content digest: it encodes the table's row VALUES (the declared columns —
// SELECT * never returns the rowid). An older digest hashed
// GROUP_CONCAT(rowid), which is node-local: identical content inserted in a
// different order produced different digests while equal counts of contiguous
// rowids hashed identically whatever the content. Hashing content fixes both.
//
// The v2 (order-invariant) encodings come from the same scan when wantV2; any
// row that fails v2 encoding (dup-name / unexpected type) drops the table to a
// v1-only digest. The table digest is byte-for-byte what it was before buckets
// existed, because older peers still compare it.
func (c *Client) scanTableDigest(ctx context.Context, table string, wantV2 bool) (keys tableScanKeys, gen uint64, genOK, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	gen, genOK = c.tableGens.get(table)

	rows, err := c.db.QueryContext(ctx, "SELECT * FROM "+table)
	if err != nil {
		return keys, 0, false, false // table may not exist yet
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return keys, 0, false, false
	}
	keys.v2ok = wantV2
	keyCols := bucketKeyColumns(table)
	keyIdx := columnIndexes(cols, keyCols)
	keys.bucketed = len(keyCols) > 0 && len(keyIdx) == len(keyCols)
	if keys.bucketed {
		keys.bv1 = make(map[int][]string)
		keys.bv2 = make(map[int][]string)
	}
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		v1 := encodeRowCells(vals)
		keys.v1 = append(keys.v1, v1)
		var v2 string
		if keys.v2ok {
			ek, eerr := encodeRowCellsV2(cols, vals)
			if eerr != nil {
				slog.Error("digest_v2: row encode failed — falling back to v1 for this table",
					"table", table, "error", eerr)
				keys.v2ok = false
				keys.v2 = nil
			} else {
				v2 = ek
				keys.v2 = append(keys.v2, ek)
			}
		}
		if keys.bucketed {
			b, bok := rowBucket(vals, keyIdx)
			if !bok {
				keys.bucketed, keys.bv1, keys.bv2 = false, nil, nil
				continue
			}
			keys.bv1[b] = append(keys.bv1[b], v1)
			if keys.v2ok {
				keys.bv2[b] = append(keys.bv2[b], v2)
			}
		}
	}
	return keys, gen, genOK, true
}

// tableDigestSets returns each named table's digest set, from the cache
// unless fresh or the entry is no longer valid (digest_cache.go). A table that
// does not exist is left out.
func (c *Client) tableDigestSets(ctx context.Context, tables []string, fresh bool) []tableDigestSet {
	start := time.Now()
	schema, schemaOK := c.schemaVersion(ctx)
	v2 := c.digestV2On()
	out := make([]tableDigestSet, 0, len(tables))
	cached, computed := 0, 0
	for _, table := range tables {
		if !fresh && schemaOK {
			if set, ok := c.cachedDigest(table, schema, v2, time.Now()); ok {
				out = append(out, set)
				cached++
				continue
			}
		}
		at := time.Now()
		keys, gen, genOK, ok := c.scanTableDigest(ctx, table, v2)
		if !ok {
			continue // table may not exist yet
		}
		set := keys.digestSet(table)
		computed++
		if schemaOK {
			c.storeDigest(table, set, gen, genOK, schema, v2, at)
		}
		out = append(out, set)
	}
	c.observeDigest(time.Since(start))
	c.observeDigestTables(cached, computed)
	return out
}

func digestsOf(sets []tableDigestSet) []TableDigest {
	out := make([]TableDigest, 0, len(sets))
	for _, s := range sets {
		out = append(out, s.digest)
	}
	return out
}

// stateDigestForTables is a fresh digest of tables: every one scanned now.
func (c *Client) stateDigestForTables(ctx context.Context, tables []string) ([]TableDigest, error) {
	return digestsOf(c.tableDigestSets(ctx, tables, true)), nil
}

// StateDigestCached is StateDigest served from the digest cache where it is
// still valid. It is what an anti-entropy pass and the GetStateDigest RPC
// use: the per-pass hot path, asked once per pass and once per peer.
func (c *Client) StateDigestCached(ctx context.Context) ([]TableDigest, error) {
	return digestsOf(c.tableDigestSets(ctx, tableNames, false)), nil
}

// SensitiveStateDigestCached is SensitiveStateDigest from the digest cache.
func (c *Client) SensitiveStateDigestCached(ctx context.Context) ([]TableDigest, error) {
	return digestsOf(c.tableDigestSets(ctx, sensitiveTableNames, false)), nil
}

// TableBucketDigests returns the bucket digests of the named tables, public or
// sensitive, from the digest cache where it is still valid. A name neither
// lane replicates is left out. Callers serving the sensitive lane must have
// checked the peer first.
func (c *Client) TableBucketDigests(ctx context.Context, tables []string) []TableBuckets {
	known := make([]string, 0, len(tables))
	seen := make(map[string]bool, len(tables))
	for _, t := range tables {
		if seen[t] || !(replicatedTableSet[t] || sensitiveTableSet[t]) {
			continue
		}
		seen[t] = true
		known = append(known, t)
	}
	sets := c.tableDigestSets(ctx, known, false)
	out := make([]TableBuckets, 0, len(sets))
	for _, s := range sets {
		out = append(out, s.tableBuckets())
	}
	return out
}
