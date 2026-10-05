package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"
)

// An adopted host whose chain is still only pre-v45 history.
//
// Such a host has no numbered row (every legacy row carries seq 0), so
// PublishAuditChainHead used to publish nothing — "a head over an empty chain
// says nothing" — and no signed statement committed to its legacy tail. The
// verifier excuses an internally-linked seq-0 region with nothing closing it,
// so cutting rows off the end of that region, or deleting all of it, read
// exactly like an idle host. The anchor is a head at seq 0 over the legacy
// tail's hash, written through the same statement every head uses.

// legacyAnchorClient is an upgraded host that has adopted signing over four
// legacy rows and written nothing since. It returns the client, the keyring,
// and the hash of the last legacy row.
func legacyAnchorClient(t *testing.T) (*Client, *AuditKeyring, string) {
	t.Helper()
	c := newAuditTestClient(t)
	tail := writeLegacyRows(t, c, "node-0", "r1", "r2", "r3", "r4")
	adoptSigning(t, c, "node-0")
	return c, c.AuditKeyringOf(), tail
}

// settledAnchor records a signed seq-0 head over hash, old enough that the
// settle window no longer applies.
func settledAnchor(t *testing.T, c *Client, kr *AuditKeyring, hash string) {
	t.Helper()
	old := time.Now().Add(-2 * headSettleWindow).UTC().Format(time.RFC3339Nano)
	insertSignedHead(t, c, kr, 0, 0, hash, old)
}

func TestAuditAnchor_PublishedOverTheLegacyTail(t *testing.T) {
	ctx := context.Background()
	c, _, tail := legacyAnchorClient(t)
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	rows, err := c.Query(ctx,
		`SELECT seq, head_hash FROM audit_chain_heads WHERE host_name = 'node-0'`)
	if err != nil {
		t.Fatalf("read heads: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one anchor head for a host holding only legacy rows, got %d\n"+
			"without it nothing signed commits to the legacy tail, and a truncated "+
			"legacy region reads as an idle host", len(rows))
	}
	if rows[0].Int64("seq") != 0 || rows[0].String("head_hash") != tail {
		t.Fatalf("anchor is (seq %d, %s), want (seq 0, %s): it must commit to the "+
			"legacy tail's hash", rows[0].Int64("seq"), rows[0].String("head_hash"), tail)
	}
	if res := verify(t, c); res.Tampered() {
		t.Fatalf("an untouched legacy host with its own anchor reports tampering: %+v", res)
	}
}

// A host that has written nothing at all has nothing to anchor.
func TestAuditAnchor_EmptyChainPublishesNothing(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	if n := oneCol(t, c, `SELECT n FROM (SELECT COUNT(*) AS n FROM audit_chain_heads)`); n != "0" {
		t.Fatalf("an empty chain published %s head(s); there is nothing to attest to", n)
	}
}

func TestAuditAnchor_TruncatedLegacyTailIsFlagged(t *testing.T) {
	ctx := context.Background()
	c, kr, tail := legacyAnchorClient(t)
	settledAnchor(t, c, kr, tail)
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('r3', 'r4')`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	res := verify(t, c)
	if !strings.Contains(strings.Join(res.TruncatedHosts, " "), "node-0") {
		t.Fatalf("the last two legacy rows were cut and nothing was reported: %+v\n"+
			"the signed anchor says the legacy region ended at %s", res, tail)
	}
	if !res.Tampered() {
		t.Fatalf("a truncation against a signed anchor must be a tamper verdict: %+v", res)
	}
}

func TestAuditAnchor_DeletingTheWholeLegacyRegionIsFlagged(t *testing.T) {
	ctx := context.Background()
	c, kr, tail := legacyAnchorClient(t)
	settledAnchor(t, c, kr, tail)
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE host_name = 'node-0'`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if res := verify(t, c); !strings.Contains(strings.Join(res.TruncatedHosts, " "), "node-0") {
		t.Fatalf("every row of an anchored host was deleted and it reads as idle: %+v", res)
	}
}

// An edit followed by a restart: the daemon's legacy reseal re-hashes the
// region around the edit, so every link verifies again. The anchor is the one
// thing that still remembers what the region hashed to.
func TestAuditAnchor_ResealedEditIsFlagged(t *testing.T) {
	ctx := context.Background()
	c, kr, tail := legacyAnchorClient(t)
	settledAnchor(t, c, kr, tail)
	if err := c.Execute(ctx, `UPDATE audit_log SET target = 'edited' WHERE id = 'r2'`); err != nil {
		t.Fatalf("edit: %v", err)
	}
	c.ResetAuditChainForTests()
	if n, err := ResealAuditChain(ctx, c, "node-0"); err != nil || n == 0 {
		t.Fatalf("ResealAuditChain = %d, %v; want the edit re-hashed", n, err)
	}
	if res := verify(t, c); !strings.Contains(strings.Join(res.TruncatedHosts, " "), "node-0") {
		t.Fatalf("an edited, resealed legacy region verified clean against its anchor: %+v", res)
	}
}

// The anchor's head_hash must be found among seq-0 rows, not anywhere in the
// host's chain: a numbered row carrying the anchored hash is not the legacy
// region the anchor describes.
func TestAuditAnchor_AnchoredHashOnANumberedRowDoesNotCount(t *testing.T) {
	ctx := context.Background()
	c, kr, tail := legacyAnchorClient(t)
	settledAnchor(t, c, kr, tail)
	if err := c.Execute(ctx, `UPDATE audit_log SET seq = 7 WHERE id = 'r4'`); err != nil {
		t.Fatalf("renumber: %v", err)
	}
	if res := verify(t, c); !strings.Contains(strings.Join(res.TruncatedHosts, " "), "node-0") {
		t.Fatalf("the anchored legacy tail was moved out of the legacy region and the "+
			"anchor still read as satisfied: %+v", res)
	}
}

// An anchor published by a node whose copy of its own legacy history was
// behind — restored from an older snapshot — names a row that is not the last.
// That is not tampering, and must not become a permanent verdict: the anchor
// table is append-only, so a stale anchor can never be withdrawn.
func TestAuditAnchor_StaleAnchorOverAnEarlierRowIsNotTampering(t *testing.T) {
	c := newAuditTestClient(t)
	early := writeLegacyRows(t, c, "node-0", "r1", "r2")
	adoptSigning(t, c, "node-0")
	kr := c.AuditKeyringOf()
	settledAnchor(t, c, kr, early)
	// The rest of the legacy region arrives afterwards, chained on.
	if err := c.Execute(context.Background(), `DELETE FROM audit_log`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	writeLegacyRows(t, c, "node-0", "r1", "r2", "r3", "r4")
	if res := verify(t, c); res.Tampered() {
		t.Fatalf("an anchor over a legacy row that is not the region's last reports "+
			"tampering: %+v", res)
	}
}

// An anchor inside the settle window says nothing yet: a peer can hold the
// head before it holds the legacy rows behind it.
func TestAuditAnchor_FreshAnchorIsInsideTheSettleWindow(t *testing.T) {
	ctx := context.Background()
	c, kr, tail := legacyAnchorClient(t)
	insertSignedHead(t, c, kr, 0, 0, tail, time.Now().UTC().Format(time.RFC3339Nano))
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('r3', 'r4')`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if res := verify(t, c); len(res.TruncatedHosts) > 0 {
		t.Fatalf("an anchor published seconds ago was read as a truncated log: %v", res.TruncatedHosts)
	}
}

// Once the host writes its first numbered row, the anchor stays satisfied and
// normal heads take over.
func TestAuditAnchor_SatisfiedAfterTheFirstNumberedRow(t *testing.T) {
	c, kr, tail := legacyAnchorClient(t)
	settledAnchor(t, c, kr, tail)
	ins(t, c, "r5", "node-0", "2026-07-29T10:00:09Z")
	if res := verify(t, c); res.Tampered() {
		t.Fatalf("an anchored legacy host that then wrote a signed row reports tampering: %+v", res)
	}
}

// The anchor must not move the floor every boundary and contract start is
// taken from: a seq-0 head proves nothing about numbered positions.
func TestAuditAnchor_DoesNotRaiseTheChainFloor(t *testing.T) {
	ctx := context.Background()
	c, kr, tail := legacyAnchorClient(t)
	settledAnchor(t, c, kr, tail)
	floor, err := FlooredHostTailSeq(ctx, c, kr, "node-0")
	if err != nil {
		t.Fatalf("FlooredHostTailSeq: %v", err)
	}
	if floor != 0 {
		t.Fatalf("a seq-0 anchor raised the chain floor to %d", floor)
	}
	if _, behind, err := AuditReplicaIsBehind(ctx, c, kr, "node-0"); err != nil || behind {
		t.Fatalf("AuditReplicaIsBehind = %v, %v; a seq-0 anchor says nothing about numbered rows", behind, err)
	}
}

// Any peer can write the heads table. An anchor whose signature does not verify
// is reported as a bad signature where it is the key's latest head, and must not
// ALSO be able to put a truncation on a host: an unverifiable row asserts
// nothing about what the host wrote.
func TestAuditAnchor_ForgedAnchorAssertsNothing(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := legacyAnchorClient(t)
	old := time.Now().Add(-2 * headSettleWindow).UTC().Format(time.RFC3339Nano)
	if err := c.Execute(ctx,
		`INSERT INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-0', 0, 0, 'feedface', ?, 'deadbeef', ?, ?, NULL)`,
		kr.KeyID(), old, old); err != nil {
		t.Fatalf("insert forged anchor: %v", err)
	}
	if res := verify(t, c); len(res.TruncatedHosts) > 0 {
		t.Fatalf("an unverifiable anchor put a truncation on the host: %v", res.TruncatedHosts)
	}
}
