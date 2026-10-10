package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// A later release's token, which this build has never heard of: what a node
// rolled back onto this build sees in a used record written by its newer peers.
const futureReleaseToken = "release_2099_01_v1"

// TestRecordReleaseFeatureUse_RefusedUntilGateOpens: the used record is a
// cluster_policies row, so it is written only once a previous-release peer can
// no longer be listening — the same gate as every other writer of the table.
func TestRecordReleaseFeatureUse_RefusedUntilGateOpens(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	err := RecordReleaseFeatureUse(ctx, c, capabilities.ReleaseToken, "widgets", "n1")
	if !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("RecordReleaseFeatureUse with the gate unwired: err=%v, want ErrClusterPolicyGateClosed", err)
	}
	if n := oneString(t, c, `SELECT count(*) AS n FROM cluster_policies`, "n"); n != "0" {
		t.Fatalf("a refused record left %s row(s) in cluster_policies", n)
	}
}

// TestRecordReleaseFeatureUse_RoundTrip: a recorded use reads back as used, is
// listed with its token, feature and recorder, travels on the replication
// stream, and is kept apart from the table's other keys.
func TestRecordReleaseFeatureUse_RoundTrip(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if err := SetFailoverScope(ctx, c, FailoverScopeRegion, "admin"); err != nil {
		t.Fatalf("SetFailoverScope: %v", err)
	}
	if used, err := ReleaseFeatureUsed(ctx, c, capabilities.ReleaseToken, "widgets"); err != nil || used {
		t.Fatalf("before any record: used=%v err=%v, want false", used, err)
	}
	before := mutationLogLen(t, c)
	if err := RecordReleaseFeatureUse(ctx, c, capabilities.ReleaseToken, "widgets", "n1"); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	if got := mutationLogLen(t, c); got != before+1 {
		t.Fatalf("mutation log grew from %d to %d, want one replicated entry for the record", before, got)
	}
	if used, err := ReleaseFeatureUsed(ctx, c, capabilities.ReleaseToken, "widgets"); err != nil || !used {
		t.Fatalf("after the record: used=%v err=%v, want true", used, err)
	}
	if used, _ := ReleaseFeatureUsed(ctx, c, capabilities.ReleaseToken, "gadgets"); used {
		t.Fatal("recording widgets marked gadgets used")
	}
	uses, err := ListReleaseFeatureUses(ctx, c)
	if err != nil {
		t.Fatalf("ListReleaseFeatureUses: %v", err)
	}
	if len(uses) != 1 || uses[0].Token != capabilities.ReleaseToken || uses[0].Feature != "widgets" ||
		uses[0].FirstUsedBy != "n1" || uses[0].UpdatedAt == "" {
		t.Fatalf("ListReleaseFeatureUses = %+v, want one widgets use recorded by n1", uses)
	}
}

// TestRecordReleaseFeatureUse_RejectsMalformedNames: token and feature are
// joined into one key, so a slash in either would forge another's record.
func TestRecordReleaseFeatureUse_RejectsMalformedNames(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	for _, tc := range [][2]string{{"", "widgets"}, {capabilities.ReleaseToken, ""},
		{capabilities.ReleaseToken, "a/b"}, {"a/b", "widgets"}} {
		if err := RecordReleaseFeatureUse(ctx, c, tc[0], tc[1], "n1"); err == nil {
			t.Errorf("RecordReleaseFeatureUse(%q, %q) accepted a malformed name", tc[0], tc[1])
		}
	}
}

func releaseUseStatement(token, feature, hlc string) Statement {
	return Statement{SQL: clusterPolicyUpsertSQL,
		Params: []interface{}{releaseFeatureKey(token, feature), "used", "n2", hlc}}
}

// TestReleaseUse_WALOfUnknownTokenQuarantines is the rolled-back node's half of
// the ordering argument. Its startup preflight found no use of the newer
// release's features and let it run; a newer peer then records a first use
// and, right behind it on the same stream, writes the feature's data. The
// record must quarantine this node BEFORE that write is applied — in the same
// batch included — so it can never emit a rewrite that drops the data.
func TestReleaseUse_WALOfUnknownTokenQuarantines(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	use := replayEntry(t, "n2", "3000000000000-0000-n2", releaseUseStatement(futureReleaseToken, "widgets", "3000000000000-0000-n2"))
	data := replayEntry(t, "n2", "3000000000001-0000-n2", Statement{SQL: clusterPolicyUpsertSQL,
		Params: []interface{}{"some_feature_data", "v", "n2", "3000000000001-0000-n2"}})
	data[0].Seq = 2
	if _, err := r.ApplyRemoteMutations(ctx, append(use, data...)); err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}
	if got := c.ReleaseUseQuarantine(); !slices.Equal(got, []string{futureReleaseToken}) {
		t.Fatalf("ReleaseUseQuarantine = %v, want [%s]: a node that cannot keep the feature's data "+
			"would keep emitting writes over it", got, futureReleaseToken)
	}
	err := InsertProject(ctx, c, ProjectRecord{Name: "acme"})
	if err == nil || !strings.Contains(err.Error(), "quarantine") || !strings.Contains(err.Error(), futureReleaseToken) {
		t.Fatalf("a replicated write after the use arrived: err=%v, want a quarantine refusal naming %s",
			err, futureReleaseToken)
	}
}

// TestReleaseUse_WALTripsBeforeTheNextStatementApplies pins the ordering inside
// one batch: the quarantine is up before the statement that follows the record
// is applied, not merely once the batch has committed.
func TestReleaseUse_WALTripsBeforeTheNextStatementApplies(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	var seenAtData []string
	releaseUseApplyHook = func(s Statement) {
		if len(s.Params) > 0 && s.Params[0] == "some_feature_data" {
			seenAtData = c.ReleaseUseQuarantine()
		}
	}
	t.Cleanup(func() { releaseUseApplyHook = nil })

	entries := replayEntry(t, "n2", "3000000000000-0000-n2",
		releaseUseStatement(futureReleaseToken, "widgets", "3000000000000-0000-n2"))
	data := replayEntry(t, "n2", "3000000000001-0000-n2", Statement{SQL: clusterPolicyUpsertSQL,
		Params: []interface{}{"some_feature_data", "v", "n2", "3000000000001-0000-n2"}})
	data[0].Seq = 2
	if _, err := r.ApplyRemoteMutations(ctx, append(entries, data...)); err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}
	if !slices.Equal(seenAtData, []string{futureReleaseToken}) {
		t.Fatalf("quarantine when the feature's data applied = %v, want [%s]", seenAtData, futureReleaseToken)
	}
}

// TestReleaseUse_KnownTokenDoesNotQuarantine: a use of a token this build
// knows is the normal state of a latched cluster, by WAL and by anti-entropy.
func TestReleaseUse_KnownTokenDoesNotQuarantine(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	if _, err := r.ApplyRemoteMutations(ctx, replayEntry(t, "n2", "3000000000000-0000-n2",
		releaseUseStatement(capabilities.ReleaseToken, "widgets", "3000000000000-0000-n2"))); err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}
	src := testClient(t)
	openClusterPolicyGate(src)
	if err := RecordReleaseFeatureUse(ctx, src, capabilities.ReleaseToken, "gadgets", "n3"); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	if err := c.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("MergeStateBytesLWW: %v", err)
	}
	if got := c.ReleaseUseQuarantine(); len(got) != 0 {
		t.Fatalf("ReleaseUseQuarantine = %v for a token this build knows", got)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("a replicated write was refused on a healthy node: %v", err)
	}
}

// TestReleaseUse_AntiEntropyOfUnknownTokenQuarantines: the record can also
// arrive by anti-entropy, for a node that was away while it was written.
func TestReleaseUse_AntiEntropyOfUnknownTokenQuarantines(t *testing.T) {
	ctx := context.Background()
	src := testClient(t)
	openClusterPolicyGate(src)
	if err := RecordReleaseFeatureUse(ctx, src, futureReleaseToken, "widgets", "n3"); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	c := testClient(t)
	if err := c.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("MergeStateBytesLWW: %v", err)
	}
	if got := c.ReleaseUseQuarantine(); !slices.Equal(got, []string{futureReleaseToken}) {
		t.Fatalf("ReleaseUseQuarantine = %v after anti-entropy, want [%s]", got, futureReleaseToken)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err == nil {
		t.Fatal("a replicated write was accepted after an unknown release feature's use arrived")
	}
}

// TestReleaseUse_PagedMergeChecksItsOwnTable: paged anti-entropy merges table
// by table with no payload to scan first; the cluster_policies table is still
// checked before its rows are merged.
func TestReleaseUse_PagedMergeChecksItsOwnTable(t *testing.T) {
	c := testClient(t)
	st := syncTable{Name: "cluster_policies",
		Columns: []string{"key", "value", "set_by", "updated_at", "deleted_at"},
		Rows: [][]interface{}{{releaseFeatureKey(futureReleaseToken, "widgets"), "used", "n3",
			"3000000000000-0000-n3", nil}}}
	if _, _, err := c.mergeTable(st, replicatedTableSet); err != nil {
		t.Fatalf("mergeTable: %v", err)
	}
	if got := c.ReleaseUseQuarantine(); !slices.Equal(got, []string{futureReleaseToken}) {
		t.Fatalf("ReleaseUseQuarantine = %v after a paged merge, want [%s]", got, futureReleaseToken)
	}
}

// TestReleaseUse_AntiEntropyTripsBeforeAnyTableMerges: in a full payload the
// feature's data may sit in a table merged ahead of cluster_policies, so the
// quarantine is up before the FIRST table is merged, whichever that is.
func TestReleaseUse_AntiEntropyTripsBeforeAnyTableMerges(t *testing.T) {
	ctx := context.Background()
	src := testClient(t)
	openClusterPolicyGate(src)
	if err := InsertProject(ctx, src, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := RecordReleaseFeatureUse(ctx, src, futureReleaseToken, "widgets", "n3"); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	c := testClient(t)
	var first []string
	var seen bool
	mergeTableHook = func(string) {
		if !seen {
			seen, first = true, c.ReleaseUseQuarantine()
		}
	}
	t.Cleanup(func() { mergeTableHook = nil })
	if err := c.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("MergeStateBytesLWW: %v", err)
	}
	if !seen || !slices.Equal(first, []string{futureReleaseToken}) {
		t.Fatalf("quarantine when the first table merged = %v (merged=%v), want [%s]", first, seen, futureReleaseToken)
	}
}

// TestWriteQuarantine_RecheckedUnderTheLock: a writer that passed the
// quarantine check and then waited for the lock must not write if the
// quarantine came up meanwhile — an apply holding the lock trips it, and the
// feature's data may be the next thing that apply commits.
func TestWriteQuarantine_RecheckedUnderTheLock(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	calls := 0
	c.SetWriteQuarantine(func() string {
		calls++
		if calls > 1 {
			return "tripped while waiting for the lock"
		}
		return ""
	})
	before := mutationLogLen(t, c)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err == nil {
		t.Fatal("a write went through although the quarantine came up before it took the lock")
	}
	c.SetWriteQuarantine(nil)
	if got := mutationLogLen(t, c); got != before {
		t.Fatalf("mutation log grew from %d to %d", before, got)
	}
	calls = 0
	c.SetWriteQuarantine(func() string {
		calls++
		if calls > 1 {
			return "tripped while waiting for the lock"
		}
		return ""
	})
	ok, err := c.ExecuteBatchGuarded(ctx, func(*sql.Tx) (bool, error) { return true, nil },
		[]Statement{{SQL: clusterPolicyUpsertSQL, Params: []interface{}{"probe", "v", "n1", c.NowTS()}}})
	if err == nil || ok {
		t.Fatalf("ExecuteBatchGuarded after the quarantine came up: ok=%v err=%v, want a refusal", ok, err)
	}
}
