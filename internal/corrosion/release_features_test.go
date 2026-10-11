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
	if _, perr, merr := ae.pullAndMerge(ctx, f, []string{"projects", "cluster_policies"}, nil, nil, nil); perr != nil || merr != nil {
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
	ae.probationPull = func(_ context.Context, peer string) (probationAnswer, error) {
		excluded, err := pull(peer)
		return probationAnswer{excluded: excluded}, err
	}
	return c, ae
}

// TestVerifyReleaseProbation_CountsOtherVotersInProbation (N3, C-R2-1): this
// node's own replica is the one in doubt, so it is never an answer. A voter
// that is itself in probation DOES count: every voter acknowledged a first
// use, so a voter holding no record of one was not there for it, and its
// replica is as good evidence as any other. Only a WAL-quarantined voter (a
// rollback below a use, or a pre-rule build) is excluded.
func TestVerifyReleaseProbation_CountsOtherVotersInProbation(t *testing.T) {
	ctx := context.Background()
	// 3 voters: self, b WAL-quarantined, c unreachable. Nobody counts: 0 < 1.
	_, ae := probationVoters(t, []string{"voter-b", "voter-c"}, func(peer string) (bool, error) {
		if peer == "voter-b" {
			return true, nil
		}
		return false, errors.New("unreachable")
	})
	if lifted, _ := ae.VerifyReleaseProbation(ctx); lifted {
		t.Fatal("probation lifted on the word of a WAL-quarantined peer and its own replica")
	}
	// Both answer, both themselves in probation (a whole-cluster rollback):
	// they count, and it lifts. The pull reports only quarantine as excluded.
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
	// One voter (this node): nobody else can have acknowledged as a voter, and
	// it lifts on its own check (documented).
	_, ae = probationVoters(t, nil, func(string) (bool, error) { return false, errors.New("never asked") })
	if lifted, _ := ae.VerifyReleaseProbation(ctx); !lifted {
		t.Fatal("a one-voter cluster cannot lift probation: stuck")
	}
}

// TestVerifyReleaseProbation_MajorityCountsOwnSeat (I-R4-1): the majority is
// of the WHOLE voter set, this node's own seat counted when it is a voter. A
// three-voter cluster with one voter dead must lift — every boot below a
// marker is a probation, and probation applies nothing, so a voter that needs
// every other voter freezes in both directions until the dead one returns.
func TestVerifyReleaseProbation_MajorityCountsOwnSeat(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		others   []string
		answer   []string // the others that answer; the rest are unreachable
		nonVoter bool
		lifts    bool
	}{
		{"3 voters, 1 other answers", []string{"b", "c"}, []string{"b"}, false, true},
		{"3 voters, none answers", []string{"b", "c"}, nil, false, false},
		{"5 voters, 1 other answers", []string{"b", "c", "d", "e"}, []string{"b"}, false, false},
		{"5 voters, 2 others answer", []string{"b", "c", "d", "e"}, []string{"b", "d"}, false, true},
		{"4 voters, 1 other answers", []string{"b", "c", "d"}, []string{"c"}, false, false},
		{"4 voters, 2 others answer", []string{"b", "c", "d"}, []string{"c", "d"}, false, true},
		{"non-voter, 1 of 3 voters answers", []string{"b", "c", "d"}, []string{"b"}, true, false},
		{"non-voter, 2 of 3 voters answer", []string{"b", "c", "d"}, []string{"b", "d"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ae := probationVoters(t, tc.others, func(peer string) (bool, error) {
				if slices.Contains(tc.answer, peer) {
					return false, nil
				}
				return false, errors.New("unreachable")
			})
			if tc.nonVoter {
				c.liftReleaseProbation([]string{futureReleaseToken}) // a replicated write, made before the boot
				if err := UpdateHostState(ctx, c, c.HostName(), "maintenance"); err != nil {
					t.Fatal(err)
				}
				c.EnterReleaseProbation([]string{futureReleaseToken})
			}
			if lifted, err := ae.VerifyReleaseProbation(ctx); lifted != tc.lifts || err != nil {
				t.Fatalf("lifted=%v err=%v, want lifted=%v", lifted, err, tc.lifts)
			}
		})
	}
}

// TestVerifyReleaseProbation_NamesTheVotersItWaitsOn (I-R4-1): a probation
// that stays names each voter it could not count, with why — in the
// probation's reason, which `lv cluster upgrade-status` shows — and clears it
// on the lift.
func TestVerifyReleaseProbation_NamesTheVotersItWaitsOn(t *testing.T) {
	ctx := context.Background()
	down := map[string]bool{"b": true, "c": true}
	c, ae := probationVoters(t, []string{"b", "c", "d", "e"}, func(peer string) (bool, error) {
		if peer == "d" {
			return true, nil
		}
		if down[peer] {
			return false, errors.New("unreachable")
		}
		return false, nil
	})
	if lifted, _ := ae.VerifyReleaseProbation(ctx); lifted {
		t.Fatal("lifted on one of four other voters")
	}
	want := []string{"b (unreachable)", "c (unreachable)", "d (WAL-quarantined)"}
	if got := c.ReleaseProbationWaitingOn(); !slices.Equal(got, want) {
		t.Fatalf("waiting on %v, want %v", got, want)
	}
	if r := c.QuarantineReason(); !strings.Contains(r, "b (unreachable), c (unreachable), d (WAL-quarantined)") {
		t.Fatalf("probation reason %q does not name the voters it waits on", r)
	}
	down["b"] = false
	if lifted, err := ae.VerifyReleaseProbation(ctx); !lifted || err != nil {
		t.Fatalf("b and e answer: lifted=%v err=%v", lifted, err)
	}
	if got := c.ReleaseProbationWaitingOn(); len(got) != 0 {
		t.Fatalf("still waiting on %v after the lift", got)
	}
}

// staleVoterView seeds a replica that has ADOPTED generation 1 = gen1 and holds
// generation 2 = gen2 unadopted, as a probation pull leaves it, with this node
// in probation and its pulls answered by answer.
func staleVoterView(t *testing.T, gen1, gen2 []string, answer map[string]probationAnswer) (*Client, *AntiEntropy, *[]string) {
	t.Helper()
	ctx := context.Background()
	c := testClient(t)
	c.SetVoterConfigGate(func() bool { return true })
	members := func(names []string) []VoterMember {
		var out []VoterMember
		for _, n := range names {
			out = append(out, VoterMember{Name: n, Incarnation: "inc-" + n})
		}
		return out
	}
	for g, names := range map[int64][]string{1: gen1, 2: gen2} {
		if names == nil {
			continue
		}
		v := VoterConfigValue{Generation: g, Members: members(names), Change: "test", CreatedBy: "test"}
		if err := WriteVoterConfig(ctx, c, v, ClaimCertificate{}); err != nil {
			t.Fatalf("write generation %d: %v", g, err)
		}
	}
	if err := RecordVoterAdoption(ctx, c, 1); err != nil {
		t.Fatal(err)
	}
	c.EnterReleaseProbation([]string{futureReleaseToken})
	var asked []string
	ae := NewAntiEntropy(c, t.TempDir(), time.Minute)
	ae.probationPull = func(_ context.Context, peer string) (probationAnswer, error) {
		asked = append(asked, peer)
		if a, ok := answer[peer]; ok {
			return a, nil
		}
		return probationAnswer{}, errors.New("unreachable")
	}
	return c, ae, &asked
}

// TestVerifyReleaseProbation_LearnsANewerVoterGeneration (I-R4-2): this node
// was away while the voters were replaced — {A..E} became {A,B,F,G,H} — and
// its replica still counts {A..E}, of which only A and B answer. A peer
// reports the newer generation; the round adopts it (the merged row) and
// counts against it: A, B and F are a majority of the new set, and it lifts.
func TestVerifyReleaseProbation_LearnsANewerVoterGeneration(t *testing.T) {
	ctx := context.Background()
	ans := map[string]probationAnswer{"A": {voterGeneration: 2}, "B": {voterGeneration: 2}, "F": {voterGeneration: 2}}
	c, ae, asked := staleVoterView(t, []string{"A", "B", "C", "D", "E"}, []string{"A", "B", "F", "G", "H"}, ans)
	ae.SetVoterAdopter(func(ctx context.Context) (int64, error) {
		return 2, RecordVoterAdoption(ctx, c, 2)
	})
	if lifted, err := ae.VerifyReleaseProbation(ctx); !lifted || err != nil {
		t.Fatalf("lifted=%v err=%v (asked %v), want a lift against the newer generation", lifted, err, *asked)
	}
	if g, _ := AdoptedVoterGeneration(ctx, c); g != 2 {
		t.Fatalf("adopted generation %d after the round, want 2", g)
	}
}

// TestVerifyReleaseProbation_NeverLiftsOnAStaleGeneration (I-R4-2): a majority
// of the voter set this node holds is not enough once a peer reports a newer
// generation this node cannot adopt yet — the set it would count is gone.
func TestVerifyReleaseProbation_NeverLiftsOnAStaleGeneration(t *testing.T) {
	ctx := context.Background()
	ans := map[string]probationAnswer{"A": {voterGeneration: 2}, "B": {voterGeneration: 1}}
	c, ae, _ := staleVoterView(t, []string{"A", "B", "C"}, nil, ans)
	if lifted, err := ae.VerifyReleaseProbation(ctx); lifted || err != nil {
		t.Fatalf("lifted=%v err=%v on a stale voter set, want probation kept", lifted, err)
	}
	if w := strings.Join(c.ReleaseProbationWaitingOn(), " "); !strings.Contains(w, "voter generation 2") {
		t.Fatalf("waiting on %q, want it to name the newer generation", w)
	}
}

// TestReplicator_DeclaresReleaseTokensBeforeWiring (I-R2-2): until the server
// wires the live advertisement, a push declares this build's release tokens —
// a fact about the binary — so a restarted, healthy host is never refused.
func TestReplicator_DeclaresReleaseTokensBeforeWiring(t *testing.T) {
	r := NewReplicator(testClient(t), "", RelayConfig{})
	if got := r.advertisedCapabilities(); !slices.Contains(got, capabilities.ReleaseToken) {
		t.Fatalf("an unwired replicator declares %v, want %s", got, capabilities.ReleaseToken)
	}
}

// TestOnUnknownReleaseToken_RetriesWithBackoff (m-R2-4): a failed look is
// retried, with backoff, until one succeeds.
func TestOnUnknownReleaseToken_RetriesWithBackoff(t *testing.T) {
	prev := releaseCheckBackoff
	releaseCheckBackoff = time.Millisecond
	t.Cleanup(func() { releaseCheckBackoff = prev })
	ae := NewAntiEntropy(testClient(t), "", time.Minute)
	calls := 0
	ae.checkFrom = func(context.Context, string) error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	}
	ae.OnUnknownReleaseToken(context.Background(), "peer", futureReleaseToken)
	if calls != 3 {
		t.Fatalf("checks = %d, want 3 (two failures retried)", calls)
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
	_, _, _ = ae.pullAndMerge(ctx, f, []string{"user_credentials"}, nil, &pb.SensitiveStateRequest{}, nil)
	if len(f.calls) < 2 || f.calls[0] != "public:cluster_policies" || f.calls[1] != "sensitive" {
		t.Fatalf("calls = %v, want cluster_policies pulled before the sensitive lane", f.calls)
	}
	if len(f.tripped) == 0 || !slices.Equal(f.tripped[len(f.tripped)-1], []string{futureReleaseToken}) {
		t.Fatalf("quarantine at the sensitive pull = %v, want [%s]", f.tripped, futureReleaseToken)
	}
}

// TestVerifyReleaseProbation_EmptyVoterSetAsksAdmittedMembers (m-R2-6): a
// replica that holds no voter at all — no hosts row voting-eligible, no
// adopted generation — never lifts having asked nobody. It asks a majority of
// its admitted members instead, and with none to ask — and no row even for
// itself, so nothing to show it is the only host (m6) — it stays in probation.
func TestVerifyReleaseProbation_EmptyVoterSetAsksAdmittedMembers(t *testing.T) {
	ctx := context.Background()
	asked := map[string]int{}
	answer := map[string]error{}
	setup := func(members []string) (*Client, *AntiEntropy) {
		c := testClient(t)
		if v, err := VoterSet(ctx, c); err != nil || len(v) != 0 {
			t.Fatalf("setup: voter set = %v (err %v), want empty", v, err)
		}
		c.SetMembersForTests(func() []PeerInfo {
			out := make([]PeerInfo, 0, len(members))
			for _, m := range members {
				out = append(out, PeerInfo{Name: m})
			}
			return out
		})
		c.EnterReleaseProbation([]string{futureReleaseToken})
		ae := NewAntiEntropy(c, t.TempDir(), time.Minute)
		ae.probationPull = func(_ context.Context, peer string) (probationAnswer, error) {
			asked[peer]++
			return probationAnswer{}, answer[peer]
		}
		return c, ae
	}
	if _, ae := setup(nil); func() bool { l, _ := ae.VerifyReleaseProbation(ctx); return l }() {
		t.Fatal("probation lifted with an empty voter set and nobody to ask")
	}
	answer["member-b"], answer["member-c"] = errors.New("unreachable"), errors.New("unreachable")
	if _, ae := setup([]string{"member-a", "member-b", "member-c"}); func() bool { l, _ := ae.VerifyReleaseProbation(ctx); return l }() {
		t.Fatalf("probation lifted on one admitted member of three (asked %v)", asked)
	}
	answer["member-b"] = nil
	c, ae := setup([]string{"member-a", "member-b", "member-c"})
	if lifted, err := ae.VerifyReleaseProbation(ctx); !lifted || err != nil {
		t.Fatalf("two admitted members of three answered: lifted=%v err=%v (asked %v)", lifted, err, asked)
	}
	if len(c.ReleaseProbation()) != 0 {
		t.Fatal("probation still set after it lifted")
	}
}

// TestVerifyReleaseProbation_RecountsADerivedSetTheMergeChanged (I-R4-2): with
// no voter generation the voter set is derived from the hosts rows, and the
// probation pull merges those. When what it merged grows the set, the round
// counts against the grown set before it lifts: {self, b, c} needs one other
// answer, {self, b, c, d, e} two.
func TestVerifyReleaseProbation_RecountsADerivedSetTheMergeChanged(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		answers []string
		lifts   bool
	}{
		{"only b answers", []string{"b"}, false},
		{"b and d answer", []string{"b", "d"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ae := probationVoters(t, []string{"b", "c"}, nil)
			ae.probationPull = func(_ context.Context, peer string) (probationAnswer, error) {
				if peer == "b" {
					// What b's voter view merges in: two more voting hosts. A
					// probation applies nothing else, so the rows are written
					// here as the merge would leave them.
					c.liftReleaseProbation([]string{futureReleaseToken})
					for _, h := range []string{"d", "e"} {
						if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.7", State: "active", Role: "worker"}); err != nil {
							t.Fatal(err)
						}
					}
					c.EnterReleaseProbation([]string{futureReleaseToken})
				}
				if slices.Contains(tc.answers, peer) {
					return probationAnswer{}, nil
				}
				return probationAnswer{}, errors.New("unreachable")
			}
			if lifted, err := ae.VerifyReleaseProbation(ctx); lifted != tc.lifts || err != nil {
				t.Fatalf("lifted=%v err=%v, want %v (waiting on %v)", lifted, err, tc.lifts, c.ReleaseProbationWaitingOn())
			}
		})
	}
}

// TestVerifyReleaseProbation_LoneHostLifts (m6): a one-host cluster with no
// voter generation whose only host is in maintenance has an empty voter set and
// nobody to ask. No other host exists to have acknowledged a use, so it lifts —
// as a one-voter cluster does — instead of staying frozen, unable even to run
// `lv host maintenance exit`. With another host in the replica it stays.
func TestVerifyReleaseProbation_LoneHostLifts(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertHost(ctx, c, HostRecord{Name: c.HostName(), Address: "10.0.0.9", State: "maintenance", Role: "worker"}); err != nil {
		t.Fatal(err)
	}
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: c.HostName()}} })
	c.EnterReleaseProbation([]string{futureReleaseToken})
	ae := NewAntiEntropy(c, t.TempDir(), time.Minute)
	ae.probationPull = func(context.Context, string) (probationAnswer, error) {
		return probationAnswer{}, errors.New("nobody to ask")
	}
	if lifted, err := ae.VerifyReleaseProbation(ctx); !lifted || err != nil {
		t.Fatalf("the only host, in maintenance: lifted=%v err=%v", lifted, err)
	}
	if err := InsertHost(ctx, c, HostRecord{Name: "other", Address: "10.0.0.8", State: "maintenance", Role: "worker"}); err != nil {
		t.Fatal(err)
	}
	c.EnterReleaseProbation([]string{futureReleaseToken})
	if lifted, _ := ae.VerifyReleaseProbation(ctx); lifted {
		t.Fatal("lifted with another host in the replica and nobody asked")
	}
	if w := strings.Join(c.ReleaseProbationWaitingOn(), " "); !strings.Contains(w, "no voter or admitted member") {
		t.Fatalf("waiting on %q, want the reason", w)
	}
}

// TestAntiEntropy_PassSkippedInProbationIsNotSpent (m2): a scheduled pass in
// probation would take nothing from any peer. It is skipped and NOT counted as
// run, so the pass right after the lift is not held back by the cooldown.
func TestAntiEntropy_PassSkippedInProbationIsNotSpent(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.SetMembersForTests(func() []PeerInfo { return nil })
	ae := NewAntiEntropy(c, t.TempDir(), time.Minute)
	c.EnterReleaseProbation([]string{futureReleaseToken})
	if ae.RunSampledOnce(ctx) {
		t.Fatal("an anti-entropy pass ran in release probation")
	}
	c.liftReleaseProbation([]string{futureReleaseToken})
	if !ae.RunSampledOnce(ctx) {
		t.Fatal("the first pass after the lift did not run: the skipped pass was counted against the cooldown")
	}
}

// TestReplicationSource_RefusedInReleaseProbation (I-R3-1): a node in release
// probation takes no replicated state by anti-entropy either — the data a
// first use wrote can arrive with its record pruned away — until the probation
// pull, which is exempt, has asked a voter majority.
func TestReplicationSource_RefusedInReleaseProbation(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := c.ReplicationSourceAllowed(ctx, "peer-a"); err != nil {
		t.Fatalf("no probation, no gate: %v", err)
	}
	c.EnterReleaseProbation([]string{futureReleaseToken})
	if err := c.ReplicationSourceAllowed(ctx, "peer-a"); err == nil || !strings.Contains(err.Error(), "probation") {
		t.Fatalf("anti-entropy source in probation: %v, want a probation refusal", err)
	}
	c.liftReleaseProbation([]string{futureReleaseToken})
	if err := c.ReplicationSourceAllowed(ctx, "peer-a"); err != nil {
		t.Fatalf("after the lift: %v", err)
	}
}
