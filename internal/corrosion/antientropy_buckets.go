package corrosion

import (
	"context"
	"log/slog"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The client half of bucketed repair (colonelpanik/litevirt#262,
// docs/design/ae-incremental.md): once a table's digest disagrees with a
// peer's, ask that peer for the table's bucket digests and pull only the
// buckets that differ. Any doubt — a peer on an older build, another scheme,
// a table either side cannot bucket, a bucket exchange that finds nothing
// differing although the table digests did — pulls the table whole, which is
// what every pass did before.

// pullScope is what one exchange narrowed its pull to.
type pullScope struct {
	// buckets is, per narrowed table, the buckets that differ.
	buckets map[string][]int
	// remote is the peer's bucket digests of every narrowed table, which the
	// settled-tie proof checks the buckets it did NOT pull against.
	remote map[string]map[int]BucketDigest
}

func (s *pullScope) narrowed(table string) bool {
	return s != nil && len(s.buckets[table]) > 0
}

// bucketsFor returns the pull narrowing for req's bucket fields, or nil.
func (s *pullScope) wire() map[string]*pb.BucketSet {
	if s == nil || len(s.buckets) == 0 {
		return nil
	}
	out := make(map[string]*pb.BucketSet, len(s.buckets))
	for t, bs := range s.buckets {
		set := &pb.BucketSet{Buckets: make([]uint32, 0, len(bs))}
		for _, b := range bs {
			set.Buckets = append(set.Buckets, uint32(b))
		}
		out[t] = set
	}
	return out
}

// bucketsAgree compares one bucket's digests the way TableDigestsAgree
// compares tables: v2 when both sides carry it, else v1, and the count always.
func bucketsAgree(local, remote BucketDigest) bool {
	if local.Count != remote.Count {
		return false
	}
	if local.HashV2 != "" && remote.HashV2 != "" {
		return local.HashV2 == remote.HashV2
	}
	return local.Hash == remote.Hash
}

// differingBucketIndexes returns the buckets whose digests disagree, a bucket
// only one side holds included, ascending.
func differingBucketIndexes(local, remote map[int]BucketDigest) []int {
	var out []int
	for b := 0; b < BucketCount; b++ {
		l, lok := local[b]
		r, rok := remote[b]
		if !lok && !rok {
			continue
		}
		if lok != rok || !bucketsAgree(l, r) {
			out = append(out, b)
		}
	}
	return out
}

// bucketScope asks peer for the bucket digests of tables and returns the
// narrowing for those it can narrow; nil means pull every table whole.
func (ae *AntiEntropy) bucketScope(ctx context.Context, client pb.LiteVirtClient, peer string, tables []string) *pullScope {
	if ae.legacyRepair {
		return nil
	}
	var candidates []string
	for _, t := range tables {
		if bucketKeyColumns(t) != nil {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	dctx, cancel := context.WithTimeout(ctx, antiEntropyDigestTimeout)
	resp, err := client.GetTableBucketDigests(dctx, &pb.BucketDigestRequest{
		Sender: ae.client.HostName(), Tables: candidates, Scheme: BucketScheme,
	})
	cancel()
	if err != nil {
		// Unimplemented is an older build; anything else is this exchange
		// failing. Either way the whole-table pull is correct.
		slog.Debug("anti-entropy: no bucket digests from peer; pulling whole tables", "peer", peer, "error", err)
		return nil
	}
	if resp.GetScheme() != BucketScheme || resp.GetBucketCount() != BucketCount {
		slog.Debug("anti-entropy: peer buckets in another scheme; pulling whole tables",
			"peer", peer, "scheme", resp.GetScheme(), "buckets", resp.GetBucketCount())
		return nil
	}
	local := make(map[string]TableBuckets)
	for _, tb := range ae.client.TableBucketDigests(ctx, candidates) {
		local[tb.Name] = tb
	}
	scope := &pullScope{buckets: map[string][]int{}, remote: map[string]map[int]BucketDigest{}}
	for _, rt := range resp.GetTables() {
		lt, ok := local[rt.GetName()]
		if !ok || !lt.Bucketed || !rt.GetBucketed() {
			continue
		}
		lb := make(map[int]BucketDigest, len(lt.Buckets))
		for _, b := range lt.Buckets {
			lb[b.Index] = b
		}
		rb := make(map[int]BucketDigest, len(rt.GetBuckets()))
		for _, b := range rt.GetBuckets() {
			if b.GetIndex() >= BucketCount {
				rb = nil
				break
			}
			rb[int(b.GetIndex())] = BucketDigest{Index: int(b.GetIndex()), Count: int(b.GetCount()), Hash: b.GetHash(), HashV2: b.GetHashV2()}
		}
		if rb == nil {
			continue
		}
		diff := differingBucketIndexes(lb, rb)
		if len(diff) == 0 {
			// The table digests disagreed a moment ago and no bucket does now:
			// a write landed in between, or the two digests negotiated
			// differently. Pull it whole rather than trust either reading.
			continue
		}
		scope.buckets[rt.GetName()] = diff
		scope.remote[rt.GetName()] = rb
	}
	if len(scope.buckets) == 0 {
		return nil
	}
	return scope
}

// mergeRepairPull merges one repair pull, counting its rows by scope first:
// "bucket" for a table the pull narrowed (a co-bucketed parent included),
// "table" for one sent whole. sensitive selects the lane's allowlist.
func (c *Client) mergeRepairPull(data []byte, pull []string, scope *pullScope, sensitive bool) error {
	if len(data) == 0 {
		return nil
	}
	payload, err := decompressPayload(data)
	if err != nil {
		slog.Error("sync: decompress", "error", err)
		return err
	}
	var narrowedTo dumpScope
	var buckets map[string][]int
	if scope != nil {
		buckets = scope.buckets
	}
	allowed := replicatedTableSet
	if sensitive {
		allowed = sensitiveTableSet
		_, narrowedTo = resolveSensitiveDumpScope(pull, buckets)
	} else if _, sc, rerr := resolveTableDumpScope(pull, buckets); rerr == nil {
		narrowedTo = sc
	}
	for _, t := range payload.Tables {
		label := "table"
		if narrowedTo[t.Name] != nil {
			label = "bucket"
		}
		c.observePullRows(label, len(t.Rows))
	}
	return c.mergeStatePayloadLWWWithAllowlist(payload, allowed)
}
