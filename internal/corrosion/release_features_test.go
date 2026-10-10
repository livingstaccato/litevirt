package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
	err := RecordReleaseFeatureUse(ctx, c, capabilities.ReleaseToken, "widgets", "n1", false)
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
	if err := RecordReleaseFeatureUse(ctx, c, capabilities.ReleaseToken, "widgets", "n1", false); err != nil {
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
		uses[0].RecordedBy != "n1" || uses[0].UpdatedAt == "" {
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
		if err := RecordReleaseFeatureUse(ctx, c, tc[0], tc[1], "n1", false); err == nil {
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

// TestReleaseUse_KnownTokenDoesNotQuarantine: a use of a feature this build
// declares, under its token, is the normal state of a latched cluster, by WAL
// and by anti-entropy.
func TestReleaseUse_KnownTokenDoesNotQuarantine(t *testing.T) {
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		"widgets": {Token: capabilities.ReleaseToken, Description: "w"},
		"gadgets": {Token: capabilities.ReleaseToken, Description: "g"},
	}))
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	if _, err := r.ApplyRemoteMutations(ctx, replayEntry(t, "n2", "3000000000000-0000-n2",
		releaseUseStatement(capabilities.ReleaseToken, "widgets", "3000000000000-0000-n2"))); err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}
	src := testClient(t)
	openClusterPolicyGate(src)
	if err := RecordReleaseFeatureUse(ctx, src, capabilities.ReleaseToken, "gadgets", "n3", false); err != nil {
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
	if err := RecordReleaseFeatureUse(ctx, src, futureReleaseToken, "widgets", "n3", false); err != nil {
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
	if err := RecordReleaseFeatureUse(ctx, src, futureReleaseToken, "widgets", "n3", false); err != nil {
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

// TestReleaseUse_UndeclaredFeatureOfAKnownTokenQuarantines (I3): a build that
// knows the release token but not one of its features — a main build from
// before that feature's branch landed — cannot keep that feature's data.
func TestReleaseUse_UndeclaredFeatureOfAKnownTokenQuarantines(t *testing.T) {
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		"widgets": {Token: capabilities.ReleaseToken, Description: "w"},
	}))
	ctx := context.Background()
	want := []string{capabilities.ReleaseToken + "/gadgets"}

	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	if _, err := r.ApplyRemoteMutations(ctx, replayEntry(t, "n2", "3000000000000-0000-n2",
		releaseUseStatement(capabilities.ReleaseToken, "gadgets", "3000000000000-0000-n2"))); err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}
	if got := c.ReleaseUseQuarantine(); !slices.Equal(got, want) {
		t.Fatalf("WAL: ReleaseUseQuarantine = %v, want %v", got, want)
	}

	src := testClient(t)
	openClusterPolicyGate(src)
	if err := RecordReleaseFeatureUse(ctx, src, capabilities.ReleaseToken, "gadgets", "n3", false); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	ae := testClient(t)
	if err := ae.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("MergeStateBytesLWW: %v", err)
	}
	if got := ae.ReleaseUseQuarantine(); !slices.Equal(got, want) {
		t.Fatalf("anti-entropy: ReleaseUseQuarantine = %v, want %v", got, want)
	}
}

// TestReleaseUse_WALFindsTheKeyByColumn (M2): the reader is frozen once this
// build ships, so it finds the record's key by the column's NAME, not by the
// position the one writer happens to use today.
func TestReleaseUse_WALFindsTheKeyByColumn(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	reordered := Statement{
		SQL: `INSERT INTO cluster_policies (value, key, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, NULL)
	 ON CONFLICT(key) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`,
		Params: []interface{}{"used", releaseFeatureKey(futureReleaseToken, "widgets"), "n2", "3000000000000-0000-n2"},
	}
	// A later build's shape this ledger does not hold: the apply back-pressures,
	// but the record is noticed before anything is applied.
	_, _ = r.ApplyRemoteMutations(ctx, replayEntry(t, "n2", "3000000000000-0000-n2", reordered))
	if got := c.ReleaseUseQuarantine(); !slices.Equal(got, []string{futureReleaseToken}) {
		t.Fatalf("ReleaseUseQuarantine = %v, want [%s]", got, futureReleaseToken)
	}
}

// TestListReleaseFeatureUses_IncludesTombstoned (M1): nothing tombstones a used
// record, so a tombstone is not evidence the use is over. The preflight must
// count it exactly as the runtime trip does.
func TestListReleaseFeatureUses_IncludesTombstoned(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if err := RecordReleaseFeatureUse(ctx, c, futureReleaseToken, "widgets", "n1", false); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	if _, err := c.db.ExecContext(ctx, `UPDATE cluster_policies SET deleted_at = 'x' WHERE key = ?`,
		releaseFeatureKey(futureReleaseToken, "widgets")); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	uses, err := ListReleaseFeatureUses(ctx, c)
	if err != nil || len(uses) != 1 || uses[0].Token != futureReleaseToken {
		t.Fatalf("ListReleaseFeatureUses = %+v (err %v), want the tombstoned record", uses, err)
	}
}

// TestRecordReleaseFeatureUse_Acked: the second state of a record, written
// once every recipient has acknowledged it, and read back by ReleaseFeatureState.
func TestRecordReleaseFeatureUse_Acked(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if present, acked, err := ReleaseFeatureState(ctx, c, capabilities.ReleaseToken, "widgets"); err != nil || present || acked {
		t.Fatalf("before any record: present=%v acked=%v err=%v", present, acked, err)
	}
	if err := RecordReleaseFeatureUse(ctx, c, capabilities.ReleaseToken, "widgets", "n1", false); err != nil {
		t.Fatal(err)
	}
	if present, acked, _ := ReleaseFeatureState(ctx, c, capabilities.ReleaseToken, "widgets"); !present || acked {
		t.Fatalf("after an unacked record: present=%v acked=%v, want present and not acked", present, acked)
	}
	if err := RecordReleaseFeatureUse(ctx, c, capabilities.ReleaseToken, "widgets", "n1", true); err != nil {
		t.Fatal(err)
	}
	if present, acked, _ := ReleaseFeatureState(ctx, c, capabilities.ReleaseToken, "widgets"); !present || !acked {
		t.Fatalf("after the acked record: present=%v acked=%v", present, acked)
	}
}

// TestReleaseProbation_RefusesWritesUntilLifted (C1): a node that started below
// a safe_if_unused token cannot trust its own replica's "nothing used"; it emits
// nothing until a pull from a voter majority has shown that.
func TestReleaseProbation_RefusesWritesUntilLifted(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.EnterReleaseProbation([]string{futureReleaseToken})
	if got := c.ReleaseProbation(); !slices.Equal(got, []string{futureReleaseToken}) {
		t.Fatalf("ReleaseProbation = %v", got)
	}
	err := InsertProject(ctx, c, ProjectRecord{Name: "acme"})
	if err == nil || !strings.Contains(err.Error(), "probation") {
		t.Fatalf("a replicated write in probation: %v, want a probation refusal", err)
	}
	c.liftReleaseProbation([]string{futureReleaseToken})
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("a write after probation lifted: %v", err)
	}
}

// fakeRowsClient serves StreamTableRows from a source client and records which
// tables each call asked for, and the receiver's quarantine at each call.
type fakeRowsClient struct {
	pb.LiteVirtClient
	t        *testing.T
	src      *Client
	recv     *Client
	requests [][]string
	tripped  [][]string
}

type pageStream struct {
	grpc.ClientStream
	pages []*pb.TableRowsPage
}

func (p *pageStream) Recv() (*pb.TableRowsPage, error) {
	if len(p.pages) == 0 {
		return nil, io.EOF
	}
	pg := p.pages[0]
	p.pages = p.pages[1:]
	return pg, nil
}

func (f *fakeRowsClient) StreamTableRows(_ context.Context, req *pb.TableDumpRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.TableRowsPage], error) {
	f.requests = append(f.requests, append([]string(nil), req.Tables...))
	f.tripped = append(f.tripped, f.recv.ReleaseUseQuarantine())
	return &pageStream{pages: collectPages(f.t, f.src, req.Tables, nil)}, nil
}

// TestAntiEntropy_PagedPullMergesClusterPoliciesFirst (I2): the paged stream
// merges vms and containers before cluster_policies, so a pull that includes
// cluster_policies pulls it ALONE first — the used record is in, and any
// quarantine it trips is up, before any feature table is merged.
func TestAntiEntropy_PagedPullMergesClusterPoliciesFirst(t *testing.T) {
	ctx := context.Background()
	src := testClient(t)
	openClusterPolicyGate(src)
	if err := InsertProject(ctx, src, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordReleaseFeatureUse(ctx, src, futureReleaseToken, "widgets", "n3", false); err != nil {
		t.Fatal(err)
	}
	c := testClient(t)
	ae := NewAntiEntropy(c, "", time.Minute)
	f := &fakeRowsClient{t: t, src: src, recv: c}
	if _, perr, merr := ae.pullAndMerge(ctx, f, []string{"projects", "cluster_policies"}, nil, nil); perr != nil || merr != nil {
		t.Fatalf("pullAndMerge: pull %v merge %v", perr, merr)
	}
	if len(f.requests) != 2 || !slices.Equal(f.requests[0], []string{"cluster_policies"}) {
		t.Fatalf("requests = %v, want cluster_policies alone first", f.requests)
	}
	if !slices.Equal(f.tripped[1], []string{futureReleaseToken}) {
		t.Fatalf("quarantine when the rest was requested = %v, want [%s]", f.tripped[1], futureReleaseToken)
	}
}

// TestVerifyReleaseProbation_NeedsAVoterMajority: with only this node's own
// replica to go on — no other voter reachable — probation does not lift.
func TestVerifyReleaseProbation_NeedsAVoterMajority(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	for _, h := range []string{c.HostName(), "voter-b", "voter-c"} {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.9", State: "active", Role: "worker"}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	c.EnterReleaseProbation([]string{futureReleaseToken})
	lifted, err := NewAntiEntropy(c, t.TempDir(), time.Minute).VerifyReleaseProbation(ctx)
	if lifted {
		t.Fatalf("probation lifted on one voter of three (err %v)", err)
	}
	if got := c.ReleaseProbation(); !slices.Equal(got, []string{futureReleaseToken}) {
		t.Fatalf("ReleaseProbation = %v, want it kept", got)
	}
}

// TestWALQuarantined_IsNotProbation (N1): probation refuses this node's own
// replicated writes, but it is not a rollback quarantine. Reporting it as one
// (Ping's wal_quarantined) gets the node isolated by its peers until a reseed.
func TestWALQuarantined_IsNotProbation(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.EnterReleaseProbation([]string{futureReleaseToken})
	if c.WALQuarantined() {
		t.Fatal("a node in release probation reports WAL quarantine")
	}
	if c.QuarantineReason() == "" {
		t.Fatal("probation does not refuse replicated writes")
	}
	err := InsertProject(ctx, c, ProjectRecord{Name: "acme"})
	if err == nil || !strings.Contains(err.Error(), "release probation") || strings.Contains(err.Error(), "reseed required") {
		t.Fatalf("refusal in probation = %v, want it to name the probation and not ask for a reseed (N9)", err)
	}
	c.liftReleaseProbation([]string{futureReleaseToken})
	c.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	if !c.WALQuarantined() {
		t.Fatal("a rollback quarantine is not reported")
	}
	c.SetWriteQuarantine(nil)
	r := NewReplicator(c, "", RelayConfig{})
	if _, err := r.ApplyRemoteMutations(ctx, replayEntry(t, "n2", "3000000000000-0000-n2",
		releaseUseStatement(futureReleaseToken, "widgets", "3000000000000-0000-n2"))); err != nil {
		t.Fatal(err)
	}
	if !c.WALQuarantined() {
		t.Fatal("a tripped release use is not reported as WAL quarantine")
	}
}

// TestLiftReleaseProbation_OnlyTheCheckedTokens (N8): a token that entered
// probation after a verification round began is not lifted by it.
func TestLiftReleaseProbation_OnlyTheCheckedTokens(t *testing.T) {
	c := testClient(t)
	c.EnterReleaseProbation([]string{"release_2099_01_v1"})
	checked := c.ReleaseProbation()
	c.EnterReleaseProbation([]string{"release_2099_02_v1"})
	c.liftReleaseProbation(checked)
	if got := c.ReleaseProbation(); !slices.Equal(got, []string{"release_2099_02_v1"}) {
		t.Fatalf("ReleaseProbation = %v, want the later token kept", got)
	}
}

// probationVoters seeds a voter set {self, others...} and returns a client in
// probation whose pulls are answered by pull.
func probationVoters(t *testing.T, others []string, pull func(peer string) (bool, error)) (*Client, *AntiEntropy) {
	t.Helper()
	ctx := context.Background()
	c := testClient(t)
	for _, h := range append([]string{c.HostName()}, others...) {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.9", State: "active", Role: "worker"}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	c.EnterReleaseProbation([]string{futureReleaseToken})
	ae := NewAntiEntropy(c, t.TempDir(), time.Minute)
	ae.probationPull = func(_ context.Context, peer string) (bool, error) { return pull(peer) }
	return c, ae
}

// TestVerifyReleaseProbation_CountsOnlyOtherVotersNotInProbation (N3): this
// node's own replica is the one in doubt, and a peer in probation is in the
// same doubt, so neither counts toward the majority.
func TestVerifyReleaseProbation_CountsOnlyOtherVotersNotInProbation(t *testing.T) {
	ctx := context.Background()
	// 3 voters: self, b answers, c unreachable. Self does not count: 1 < 2.
	_, ae := probationVoters(t, []string{"voter-b", "voter-c"}, func(peer string) (bool, error) {
		if peer == "voter-b" {
			return false, nil
		}
		return false, errors.New("unreachable")
	})
	if lifted, _ := ae.VerifyReleaseProbation(ctx); lifted {
		t.Fatal("probation lifted on one other voter of three: this node counted itself")
	}
	// b and c answer, but b is itself in probation: 1 < 2.
	_, ae = probationVoters(t, []string{"voter-b", "voter-c"}, func(peer string) (bool, error) {
		return peer == "voter-b", nil
	})
	if lifted, _ := ae.VerifyReleaseProbation(ctx); lifted {
		t.Fatal("probation lifted on the word of a peer that is itself in probation")
	}
	// Both answer and neither is in probation: lifted.
	c, ae := probationVoters(t, []string{"voter-b", "voter-c"}, func(string) (bool, error) { return false, nil })
	if lifted, err := ae.VerifyReleaseProbation(ctx); !lifted || err != nil {
		t.Fatalf("both other voters answered: lifted=%v err=%v", lifted, err)
	}
	if len(c.ReleaseProbation()) != 0 {
		t.Fatal("probation still set after it lifted")
	}
	// Two voters: the one other voter is the whole of what can be asked.
	_, ae = probationVoters(t, []string{"voter-b"}, func(string) (bool, error) { return false, nil })
	if lifted, _ := ae.VerifyReleaseProbation(ctx); !lifted {
		t.Fatal("a two-voter cluster cannot lift probation: stuck")
	}
}

type sensitiveRowsClient struct {
	fakeRowsClient
	calls []string
}

func (f *sensitiveRowsClient) StreamTableRows(ctx context.Context, req *pb.TableDumpRequest, o ...grpc.CallOption) (grpc.ServerStreamingClient[pb.TableRowsPage], error) {
	f.calls = append(f.calls, "public:"+strings.Join(req.Tables, ","))
	return f.fakeRowsClient.StreamTableRows(ctx, req, o...)
}

func (f *sensitiveRowsClient) StreamSensitiveTableRows(_ context.Context, _ *pb.SensitiveStateRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.TableRowsPage], error) {
	f.calls = append(f.calls, "sensitive")
	f.tripped = append(f.tripped, f.recv.ReleaseUseQuarantine())
	return &pageStream{pages: []*pb.TableRowsPage{{Final: true}}}, nil
}

// TestAntiEntropy_SensitivePullTakesClusterPoliciesFirst (N6): feature data in
// a sensitive table must not merge ahead of its used record either.
func TestAntiEntropy_SensitivePullTakesClusterPoliciesFirst(t *testing.T) {
	ctx := context.Background()
	src := testClient(t)
	openClusterPolicyGate(src)
	if err := RecordReleaseFeatureUse(ctx, src, futureReleaseToken, "widgets", "n3", false); err != nil {
		t.Fatal(err)
	}
	c := testClient(t)
	f := &sensitiveRowsClient{fakeRowsClient: fakeRowsClient{t: t, src: src, recv: c}}
	ae := NewAntiEntropy(c, "", time.Minute)
	_, _, _ = ae.pullAndMerge(ctx, f, []string{"user_credentials"}, nil, &pb.SensitiveStateRequest{})
	if len(f.calls) < 2 || f.calls[0] != "public:cluster_policies" || f.calls[1] != "sensitive" {
		t.Fatalf("calls = %v, want cluster_policies pulled before the sensitive lane", f.calls)
	}
	if len(f.tripped) == 0 || !slices.Equal(f.tripped[len(f.tripped)-1], []string{futureReleaseToken}) {
		t.Fatalf("quarantine at the sensitive pull = %v, want [%s]", f.tripped, futureReleaseToken)
	}
}
