package corrosion

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// A retired host_fence_credentials row stays retired.
//
// A re-admission (or removal) retires the host's credential row on every node
// that applies it. A node that held the host's live hosts row from BEFORE the
// re-admission — d itself, booting on its old database — keeps the old
// machine's hosts.ipmi_pass under a hosts row NEWER than the admission
// (RegisterHost re-records its serial with a fresh clock), so the readmit reset
// does not apply there. Two things then put the old machine's password back:
//
//   - the read path fell back to hosts.ipmi_pass once the credential row was
//     retired, so a fence from that node authenticated with it;
//   - the split pass, copy and clear alike, read the tombstone as "no row" and
//     upserted the old column into a LIVE row stamped with the stale hosts
//     row's updated_at. That is a logged write, newer than the tombstone, and
//     every survivor applied it over its own.

const (
	staleOldPass   = "Old-Machine-Pass"
	staleAdmission = "2026-10-01T00:00:00.000001Z"
	staleBoot      = "2026-10-02T00:00:00.000001Z"
)

// staleDBAfterReadmission leaves c as d's own database once the re-admission
// has reached it: the old machine's live hosts row (re-recorded serial,
// newer than the admission) holding its IPMI password, and the credential row
// retired by the admission.
func staleDBAfterReadmission(t *testing.T, c *Client) {
	t.Helper()
	configuredHost(t, c)
	// d's daemon boots on its old database and re-records its new serial.
	if _, err := c.DB().Exec(`UPDATE hosts SET ipmi_address = '10.0.1.15', ipmi_user = 'probe',
		ipmi_pass = ?, cert_serial = '02new', updated_at = ? WHERE name = 'host-x'`, staleOldPass, staleBoot); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().Exec(HostFenceCredentialUpsertSQL, "host-x", staleOldPass, credTS); err != nil {
		t.Fatal(err)
	}
	// The re-admission arrives: its hosts half matches nothing here (the row
	// is live), and the credential row is retired at the admission's instant.
	applyRemote(t, c, "2026000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, "02new", staleAdmission, "host-x", "02new"}})
	if _, ok := liveCredential(t, c); ok {
		t.Fatal("fixture: the re-admission did not retire the credential row")
	}
	if got := readHostSettings(t, c); got.ipmiPass != "'"+staleOldPass+"'" || got.deleted {
		t.Fatalf("fixture: hosts row has ipmi_pass %s (deleted %v), want the stale live row with the old password",
			redactedPass(got.ipmiPass), got.deleted)
	}
}

// Channel 2, the read path. Mutation: join only a live credential row again,
// so a tombstone reads as "no row" and the old column is served — red.
func TestGetHost_ARetiredCredentialIsNotReadFromTheOldColumn(t *testing.T) {
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	h, err := GetHost(context.Background(), c, "host-x")
	if err != nil || h == nil {
		t.Fatalf("GetHost = %s", hostPassState(h, err))
	}
	if h.IPMIPass != "" {
		t.Errorf("GetHost served IPMIPass %s from the old column over a retired credential row; want none",
			redactedPass(h.IPMIPass))
	}
	if !h.IPMIPassRetired {
		t.Error("GetHost did not report the credential row as retired; a fence cannot say why it has no password")
	}
}

// A tombstone is no password whatever its secret column holds: retirement
// blanks it, but the reader does not rely on that. Mutation: serve a retired
// row's value — red.
func TestGetHost_ARetiredCredentialServesNoValue(t *testing.T) {
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	if _, err := c.DB().Exec(`UPDATE host_fence_credentials SET ipmi_pass = 'Tombstoned-Value' WHERE host_name = 'host-x'`); err != nil {
		t.Fatal(err)
	}
	h, err := GetHost(context.Background(), c, "host-x")
	if err != nil || h == nil || h.IPMIPass != "" || !h.IPMIPassRetired {
		t.Fatalf("GetHost: password set %v, retired %v, err %v; want no password, retired", h != nil && h.IPMIPass != "", h != nil && h.IPMIPassRetired, err)
	}
}

// Before credentials_split_v1 there is no credential row at all, and the old
// column is the only copy: the fallback stays.
func TestGetHost_NoCredentialRowStillReadsTheOldColumn(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertHost(ctx, c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "01old", FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET ipmi_pass = 'pre-split' WHERE name = 'host-x'`); err != nil {
		t.Fatal(err)
	}
	h, err := GetHost(ctx, c, "host-x")
	if err != nil || h == nil || h.IPMIPass != "pre-split" || h.IPMIPassRetired {
		t.Fatalf("GetHost = %s; want the old column's password, not retired", hostPassState(h, err))
	}
}

// Channel 1, the copy pass. Mutation: needsCopy treats a tombstone as no row
// — red.
func TestSplitCredentials_CopyPassDoesNotReviveARetiredCredential(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	rep, err := c.SplitCredentials(ctx)
	if err != nil {
		t.Fatalf("SplitCredentials: %v", err)
	}
	if pass, ok := liveCredential(t, c); ok {
		t.Fatalf("the copy pass revived the retired credential row (ipmi_pass %s, report %+v)",
			redactedPass(pass), rep)
	}
	if rep.Copied != 0 {
		t.Errorf("the copy pass copied %d secrets over a retired credential row, want 0", rep.Copied)
	}
}

// Channel 1, the clear pass (credentials_clear_v1). The old column is cleared
// and nothing is re-emitted. Mutation: credentialFor re-emits the tombstone's
// row, or copies the old column — red.
func TestSplitCredentials_ClearPassDoesNotReviveARetiredCredential(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	c.SetCredentialsClearGate(func() bool { return true })
	c.credentialsLive.Store(true) // the copy pass already ran: exercise the clear alone
	rep, err := c.SplitCredentials(ctx)
	if err != nil {
		t.Fatalf("SplitCredentials: %v", err)
	}
	if pass, ok := liveCredential(t, c); ok {
		t.Fatalf("the clear pass revived the retired credential row (ipmi_pass %s, report %+v)",
			redactedPass(pass), rep)
	}
	if rep.Copied != 0 || rep.Cleared != 1 {
		t.Errorf("clear pass report %+v, want Copied 0 Cleared 1", rep)
	}
	if got := readHostSettings(t, c); got.ipmiPass != "''" {
		t.Errorf("hosts.ipmi_pass = %s after the clear pass, want empty", redactedPass(got.ipmiPass))
	}
}

// A neighbour that has not latched sets the new machine's password in the old
// column alone; the absorb revives the retired row with it, gate open or
// closed. The revived row carries the retirement it was set after (review
// m-14), so a node still holding only the tombstone takes it by anti-entropy.
// Mutation: the absorb writes no evidence — red.
func TestRetiredCredential_AnUnlatchedWriteIsStillAbsorbed(t *testing.T) {
	for _, gate := range []bool{true, false} {
		c := newTestDB(t)
		staleDBAfterReadmission(t, c)
		c.SetCredentialsSplitGate(func() bool { return gate })
		applyRemote(t, c, "2026000000001-0000-peer", Statement{SQL: hostsClearIPMIPassSQL,
			Params: []interface{}{"Unlatched-New-Pass", "2026-10-03T00:00:00.000001Z", "host-x"}})
		h, err := GetHost(context.Background(), c, "host-x")
		if err != nil || h == nil || h.IPMIPass != "Unlatched-New-Pass" || h.IPMIPassRetired {
			t.Errorf("gate %v: GetHost = %s; want the unlatched write's password, not retired", gate, hostPassState(h, err))
		}
		rows, err := c.Query(context.Background(), `SELECT after_retirement FROM host_fence_credentials WHERE host_name = 'host-x'`)
		if err != nil || len(rows) != 1 || rows[0].String("after_retirement") != staleAdmission {
			t.Errorf("gate %v: after_retirement = %v (%v); want the retirement it was set after, %s", gate, rows, err, staleAdmission)
		}
		// A node that holds only the tombstone pulls the absorbing node's row.
		holder := newTestDB(t)
		staleDBAfterReadmission(t, holder)
		if err := holder.MergeSensitiveStateBytesLWW(c.DumpSensitiveStateBytes()); err != nil {
			t.Fatal(err)
		}
		if pass, ok := liveCredential(t, holder); !ok || pass != "Unlatched-New-Pass" {
			t.Errorf("gate %v: a tombstone holder pulled the absorbed row and holds %s (live %v); want the unlatched write's password",
				gate, redactedPass(pass), ok)
		}
	}
}

// hostPassState describes what GetHost returned without printing a secret.
func hostPassState(h *HostRecord, err error) string {
	if err != nil || h == nil {
		return fmt.Sprintf("(nil host, err %v)", err)
	}
	return fmt.Sprintf("(ipmi_pass %s, retired %v)", redactedPass(h.IPMIPass), h.IPMIPassRetired)
}

func redactedPass(s string) string {
	if s == "" {
		return "<empty>"
	}
	return "<set>"
}

// I-1(a): a node that holds a stale hosts row and NO credential row (it took
// the row on a public pull before any sensitive pull) cannot tell a password
// that was never copied from one whose row it has not pulled retired yet. It
// copies nothing until it has merged the sensitive lane. Mutation: drop the
// gate in the copy pass — red.
func TestSplitCredentials_NoHostCopyBeforeTheSensitiveLaneMerged(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	if _, err := c.DB().Exec(`DELETE FROM host_fence_credentials WHERE host_name = 'host-x'`); err != nil {
		t.Fatal(err)
	}
	c.MarkSensitiveLaneUnmergedForTests()
	rep, err := c.SplitCredentials(ctx)
	if err != nil {
		t.Fatalf("SplitCredentials: %v", err)
	}
	if _, ok := liveCredential(t, c); ok || rep.Copied != 0 {
		t.Fatalf("a node that has not merged the sensitive lane copied a host password (report %+v)", rep)
	}
	// Once merged with host-x, the only voter (a peer with no row either), the
	// copy proceeds.
	c.markSensitiveLaneMerged("host-x")
	if rep, err = c.SplitCredentials(ctx); err != nil || rep.Copied != 1 {
		t.Fatalf("after the sensitive lane merged: report %+v, err %v; want the copy", rep, err)
	}
}

// The clear pass does not clear a password it may not copy yet: that would
// drop the only copy. Mutation: drop the gate in the clear pass — red.
func TestSplitCredentials_NoHostClearBeforeTheSensitiveLaneMerged(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	if _, err := c.DB().Exec(`DELETE FROM host_fence_credentials WHERE host_name = 'host-x'`); err != nil {
		t.Fatal(err)
	}
	c.MarkSensitiveLaneUnmergedForTests()
	c.SetCredentialsClearGate(func() bool { return true })
	c.credentialsLive.Store(true)
	rep, err := c.SplitCredentials(ctx)
	if err != nil {
		t.Fatalf("SplitCredentials: %v", err)
	}
	if _, ok := liveCredential(t, c); ok || rep.Copied != 0 || rep.Cleared != 0 {
		t.Errorf("clear pass before the sensitive lane merged: report %+v; want nothing copied or cleared", rep)
	}
	if got := readHostSettings(t, c); got.ipmiPass != "'"+staleOldPass+"'" {
		t.Errorf("hosts.ipmi_pass = %s; the only copy of the password was cleared", redactedPass(got.ipmiPass))
	}
}

// A cluster of one has no peer to pull a row from: its copy is not gated.
func TestSplitCredentials_AClusterOfOneCopiesWithoutAMerge(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetCredentialsSplitGate(func() bool { return true })
	c.MarkSensitiveLaneUnmergedForTests()
	if err := InsertHost(ctx, c, HostRecord{
		Name: c.HostName(), Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "01", FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET ipmi_pass = 'Solo-Pass', updated_at = ? WHERE name = ?`,
		credTS, c.HostName()); err != nil {
		t.Fatal(err)
	}
	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Copied != 1 {
		t.Fatalf("a cluster of one: report %+v, err %v; want its password copied", rep, err)
	}
}

// I-1(b): an entry that revives a retired credential with no operator password
// write beside it — a previous build's copy pass (the upsert alone) or its
// clear pass (the upsert and the empty old-column clear) — is not applied over
// a tombstone. Mutation: entryWritesHostPassword reports every entry paired, or
// the apply hook is removed — red.
func TestApply_AnUnpairedReviveOfARetiredCredentialIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stmts []Statement
	}{
		{"previous build's copy pass", []Statement{
			{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", staleOldPass, staleBoot}}}},
		{"previous build's clear pass", []Statement{
			{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", staleOldPass, staleBoot}},
			{SQL: hostsClearIPMIPassSQL, Params: []interface{}{"", "2026-10-02T00:00:00.000002Z", "host-x"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			staleDBAfterReadmission(t, c)
			applyRemote(t, c, "2026000000002-0000-peer", tc.stmts...)
			if pass, ok := liveCredential(t, c); ok {
				t.Errorf("the entry revived the retired credential row (ipmi_pass %s)", redactedPass(pass))
			}
			if h, err := GetHost(context.Background(), c, "host-x"); err != nil || h == nil || !h.IPMIPassRetired {
				t.Errorf("GetHost = %s; want retired", hostPassState(h, err))
			}
		})
	}
}

// The operator's write revives it: its entry carries the hosts write of the
// password. Applied from a peer, whatever the old column holds after
// credentials_clear_v1 (empty), as long as the statement is not the clear.
func TestApply_AnOperatorPasswordWriteRevivesARetiredCredential(t *testing.T) {
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	const ts = "2026-10-03T00:00:00.000001Z"
	applyRemote(t, c, "2026000000003-0000-peer",
		Statement{SQL: operatorConfigureHostSQL,
			Params: []interface{}{"ipmi", nil, nil, "", nil, nil, nil, nil, nil, nil, nil, ts, "host-x"}},
		Statement{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", "New-Machine-Pass", ts}})
	h, err := GetHost(context.Background(), c, "host-x")
	if err != nil || h == nil || h.IPMIPass != "New-Machine-Pass" || h.IPMIPassRetired {
		t.Fatalf("GetHost = %s; want the operator's new password, not retired", hostPassState(h, err))
	}
}

// The local write path refuses the same entry, and logs nothing for a peer.
func TestLocalWrite_AnUnpairedReviveOfARetiredCredentialIsRefused(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	before, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(ctx, HostFenceCredentialUpsertSQL, "host-x", staleOldPass, staleBoot); err != nil {
		t.Fatal(err)
	}
	if pass, ok := liveCredential(t, c); ok {
		t.Errorf("a local unpaired upsert revived the retired credential row (ipmi_pass %s)", redactedPass(pass))
	}
	after, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatal(err)
	}
	if after[0].Int("n") != before[0].Int("n") {
		t.Errorf("the refused revive was logged for peers (%d -> %d entries)", before[0].Int("n"), after[0].Int("n"))
	}
}

// operatorConfigureHostSQL is grpcapi's configureHostSQL, the statement
// `lv host config` writes (copied: corrosion cannot import grpcapi). The
// grpcapi test TestConfigureHost_SetsAPasswordOverARetiredCredential covers the
// real ConfigureHost path.
const operatorConfigureHostSQL = `UPDATE hosts SET ` +
	`fence_strategy = COALESCE(?, fence_strategy), ` +
	`ipmi_address = COALESCE(?, ipmi_address), ` +
	`ipmi_user = COALESCE(?, ipmi_user), ` +
	`ipmi_pass = COALESCE(?, ipmi_pass), ` +
	`watchdog_dev = COALESCE(?, watchdog_dev), ` +
	`role = COALESCE(?, role), ` +
	`region = COALESCE(?, region), ` +
	`cpu_overcommit = COALESCE(?, cpu_overcommit), ` +
	`mem_overcommit = COALESCE(?, mem_overcommit), ` +
	`cpu_reserve = COALESCE(?, cpu_reserve), ` +
	`mem_reserve_mib = COALESCE(?, mem_reserve_mib), ` +
	`updated_at = ? ` +
	`WHERE name = ?`

// Review m-5: merging with one peer that holds nothing either (another node
// that joined on an empty database) does not open the copy. Only a majority of
// the voter set does. Mutation: open the gate on any one merge — red.
func TestSplitCredentials_OneEmptyPeerDoesNotOpenTheHostCopy(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetCredentialsSplitGate(func() bool { return true })
	for _, n := range []string{c.HostName(), "p1", "p2", "p3", "p4"} {
		if err := InsertHost(ctx, c, HostRecord{
			Name: n, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
			State: "active", CertSerial: "01-" + n, FenceStrategy: "ipmi",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET ipmi_pass = 'P4-Pass', updated_at = ? WHERE name = 'p4'`, credTS); err != nil {
		t.Fatal(err)
	}
	c.MarkSensitiveLaneUnmergedForTests()
	c.markSensitiveLaneMerged("p1")
	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Copied != 0 || rep.Deferred != 1 {
		t.Fatalf("merged with one of four peers: report %+v, err %v; want the host copy deferred", rep, err)
	}
	if c.CredentialsLive() {
		t.Error("a pass that deferred a host copy made this node live")
	}
	c.markSensitiveLaneMerged("p2")
	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Copied != 1 || rep.Deferred != 0 {
		t.Fatalf("merged with a majority: report %+v, err %v; want the copy", rep, err)
	}
	if !c.CredentialsLive() {
		t.Error("a complete pass did not make this node live")
	}
}

// ── Round 3: retirement evidence (credentials_revive_guard.go) ──────────────

// credRow is one host_fence_credentials row as anti-entropy carries it.
// withEvidence false leaves the after_retirement column out, as a previous
// build's dump does.
type credRow struct {
	pass, updatedAt, deletedAt, after string
	withEvidence                      bool
}

func (r credRow) table() syncTable {
	var del interface{}
	if r.deletedAt != "" {
		del = r.deletedAt
	}
	if !r.withEvidence {
		return syncTable{Name: "host_fence_credentials",
			Columns: []string{"host_name", "ipmi_pass", "updated_at", "deleted_at"},
			Rows:    [][]interface{}{{"host-x", r.pass, r.updatedAt, del}}}
	}
	return syncTable{Name: "host_fence_credentials",
		Columns: []string{"host_name", "ipmi_pass", "updated_at", "deleted_at", "after_retirement"},
		Rows:    [][]interface{}{{"host-x", r.pass, r.updatedAt, del, r.after}}}
}

func mergeCredRows(t *testing.T, rows ...credRow) (pass string, live bool) {
	t.Helper()
	c := newTestDB(t)
	for _, r := range rows {
		if err := c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{r.table()}})); err != nil {
			t.Fatalf("merge: %v", err)
		}
	}
	return liveCredential(t, c)
}

const (
	evRetired  = "2026-10-01T00:00:00.000001Z" // the retirement (T_a)
	evStale    = "2026-10-02T00:00:00.000001Z" // a stale copy's clock (T_b)
	evOperator = "2026-10-03T00:00:00.000001Z" // the operator's set (T_c)
	evEarlier  = "2026-09-01T00:00:00.000001Z" // a retirement before T_a
)

// The anti-entropy merge of a host credential is the same whichever row a node
// saw first: rows are ordered by the retirement they were set after, then by
// their clock. Mutations: drop the order from the merge (plain LWW) — the
// stale and previous-build cases go red; refuse every live row over a
// tombstone (round 2) — the operator case goes red in one order.
func TestCredentialMerge_TheOrderDoesNotDependOnArrival(t *testing.T) {
	tomb := credRow{pass: "", updatedAt: evRetired, deletedAt: evRetired, withEvidence: true}
	for _, tc := range []struct {
		name     string
		other    credRow
		wantLive bool
	}{
		{"an operator's set after the retirement", credRow{pass: "New-Pass", updatedAt: evOperator, after: evRetired, withEvidence: true}, true},
		{"a newer copy with no evidence", credRow{pass: staleOldPass, updatedAt: evStale, withEvidence: true}, false},
		{"a previous build's row with no column", credRow{pass: staleOldPass, updatedAt: evStale}, false},
		{"a set after an earlier retirement", credRow{pass: staleOldPass, updatedAt: evOperator, after: evEarlier, withEvidence: true}, false},
		{"a previous build's tombstone", credRow{pass: "", updatedAt: evRetired, deletedAt: evRetired}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p1, live1 := mergeCredRows(t, tomb, tc.other)
			p2, live2 := mergeCredRows(t, tc.other, tomb)
			if live1 != live2 || p1 != p2 {
				t.Errorf("the merge depends on arrival: tombstone first -> live %v %s; other first -> live %v %s",
					live1, redactedPass(p1), live2, redactedPass(p2))
			}
			if live1 != tc.wantLive {
				t.Errorf("merged row live %v, want %v", live1, tc.wantLive)
			}
		})
	}
}

// Review m-11: the order touches only host_fence_credentials, and inside it
// only rows whose retirements differ. Mutations: apply the order to every
// table, or keep the local row whenever retirements are equal — red.
func TestCredentialMerge_TheOrderLeavesOrdinaryMergesAlone(t *testing.T) {
	// Same retirement: plain LWW, either way.
	older := credRow{pass: "Older", updatedAt: evStale, after: evRetired, withEvidence: true}
	newer := credRow{pass: "Newer", updatedAt: evOperator, after: evRetired, withEvidence: true}
	for _, order := range [][]credRow{{older, newer}, {newer, older}} {
		if p, live := mergeCredRows(t, order...); !live || p != "Newer" {
			t.Errorf("same retirement: got %s live %v, want the newer row", redactedPass(p), live)
		}
	}
	// No local row: the incoming row lands.
	if p, live := mergeCredRows(t, newer); !live || p != "Newer" {
		t.Errorf("no local row: got %s live %v, want the incoming row", redactedPass(p), live)
	}
	// Another credential table is not ordered: a newer live user credential
	// beats an older tombstone there by LWW.
	c := newTestDB(t)
	for _, row := range [][]interface{}{
		{"alice", "", evRetired, evRetired},
		{"alice", "$2a$10$x", evOperator, nil},
	} {
		if err := c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
			Name: "user_credentials", Columns: []string{"username", "password_hash", "updated_at", "deleted_at"},
			Rows: [][]interface{}{row}}}})); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := c.Query(context.Background(), `SELECT deleted_at FROM user_credentials WHERE username = 'alice'`)
	if err != nil || len(rows) != 1 || rows[0].String("deleted_at") != "" {
		t.Errorf("user_credentials: a newer live row did not beat an older tombstone by LWW (%d rows, %v)", len(rows), err)
	}
}

// The operator's write, applied from a peer over a local tombstone, carries
// that retirement; a peer that pulls it later orders it after the tombstone.
// Mutation: an operator's write carries no evidence — red.
func TestApply_AnOperatorWriteCarriesTheRetirement(t *testing.T) {
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	applyRemote(t, c, "2026000000003-0000-peer",
		Statement{SQL: operatorConfigureHostSQL,
			Params: []interface{}{"ipmi", nil, nil, "", nil, nil, nil, nil, nil, nil, nil, evOperator, "host-x"}},
		Statement{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", "New-Machine-Pass", evOperator}})
	rows, err := c.Query(context.Background(), `SELECT after_retirement FROM host_fence_credentials WHERE host_name = 'host-x'`)
	if err != nil || len(rows) != 1 || rows[0].String("after_retirement") != staleAdmission {
		t.Fatalf("after_retirement = %v (%v); want the retirement it was set after, %s", rows, err, staleAdmission)
	}
}

// A retirement reaching a node that already took a stale revive retires it,
// however new the revive's clock: the revive carries no evidence. Mutation:
// keep a live row newer than the retirement (the old rule) — red.
func TestRetire_AStaleReviveFirstIsStillRetired(t *testing.T) {
	c := newTestDB(t)
	configuredHost(t, c)
	if _, err := c.DB().Exec(HostFenceCredentialUpsertSQL, "host-x", staleOldPass, staleBoot); err != nil {
		t.Fatal(err)
	}
	applyRemote(t, c, "2026000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, "02new", staleAdmission, "host-x", "02new"}})
	if pass, ok := liveCredential(t, c); ok {
		t.Errorf("a revive with no evidence stood over the retirement (ipmi_pass %s)", redactedPass(pass))
	}
}

// ── Round 4 ─────────────────────────────────────────────────────────────────

const evLaterRetired = "2026-10-04T00:00:00.000001Z" // a retirement after T_c (T_d)

// credentialRowCells is host-x's whole credential row, secrets redacted, for
// comparing two nodes' rows.
func credentialRowCells(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT ipmi_pass, updated_at, deleted_at, after_retirement FROM host_fence_credentials WHERE host_name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read credential row: %d rows, %v", len(rows), err)
	}
	r := rows[0]
	return fmt.Sprintf("pass %s updated %s deleted %q after %q", redactedPass(r.String("ipmi_pass")),
		r.String("updated_at"), r.String("deleted_at"), r.String("after_retirement"))
}

func credentialDigest(t *testing.T, c *Client) TableDigest {
	t.Helper()
	ds, err := c.SensitiveStateDigest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if d.Name == "host_fence_credentials" {
			return d
		}
	}
	t.Fatal("no host_fence_credentials digest")
	return TableDigest{}
}

func mergeInto(t *testing.T, c *Client, rows ...credRow) {
	t.Helper()
	for _, r := range rows {
		if err := c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{r.table()}})); err != nil {
			t.Fatalf("merge: %v", err)
		}
	}
}

// Review m-12: a previous build's tombstone (its dump has no after_retirement)
// pulled by anti-entropy over a live row set after an earlier retirement
// leaves the row a node would hold had it retired the row itself: a tombstone
// carries no evidence. Otherwise the two tombstones differ only in
// after_retirement, tie on updated_at, and the tie is unresolved for good.
// Mutation: keep the local after_retirement on the merged tombstone — red.
func TestCredentialMerge_APreviousBuildsTombstoneConvergesWithNoTie(t *testing.T) {
	live := credRow{pass: "New-Pass", updatedAt: evOperator, after: evRetired, withEvidence: true}
	prevTomb := credRow{pass: "", updatedAt: evLaterRetired, deletedAt: evLaterRetired}

	// x pulls the previous build's tombstone before the removal's WAL entry.
	x := newTestDB(t)
	mergeInto(t, x, live, prevTomb)
	// y applies the removal itself.
	y := newTestDB(t)
	mergeInto(t, y, live)
	tx, err := y.DB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := retireFenceCredential(context.Background(), tx, "host-x", evLaterRetired); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// The removal's WAL entry reaches x afterwards: nothing to do.
	tx, err = x.DB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := retireFenceCredential(context.Background(), tx, "host-x", evLaterRetired); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	gx, gy := credentialRowCells(t, x), credentialRowCells(t, y)
	if gx != gy {
		t.Errorf("rows differ:\n x (pulled the tombstone) %s\n y (retired it)          %s", gx, gy)
	}
	if dx, dy := credentialDigest(t, x), credentialDigest(t, y); dx != dy {
		t.Errorf("digests differ: x %+v, y %+v", dx, dy)
	}
	// Each pulls the other: no tie is left unresolved.
	xd, yd := x.DumpSensitiveStateBytes(), y.DumpSensitiveStateBytes()
	if err := x.MergeSensitiveStateBytesLWW(yd); err != nil {
		t.Fatal(err)
	}
	if err := y.MergeSensitiveStateBytesLWW(xd); err != nil {
		t.Fatal(err)
	}
	if nx, ny := x.UnresolvedTieCount(), y.UnresolvedTieCount(); nx != 0 || ny != 0 {
		t.Errorf("unresolved ties after the exchange: x %d, y %d; want none", nx, ny)
	}
	if _, ok := liveCredential(t, x); ok {
		t.Error("x: the later retirement did not retire the row")
	}
}

// Review m-13: a row the retirement order would apply over the local one is
// still set aside when its clock, or the retirement it carries, is
// future-dated, as any other anti-entropy row is. Mutation: apply the ordered
// row before the skew check, or skip the retirement check when there is no
// local row — red.
func TestCredentialMerge_AnOrderedRowIsStillSkewQuarantined(t *testing.T) {
	future := time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	live := credRow{pass: "New-Pass", updatedAt: evOperator, after: evRetired, withEvidence: true}
	tomb := credRow{pass: "", updatedAt: evRetired, deletedAt: evRetired, withEvidence: true}
	for _, tc := range []struct {
		name          string
		local, in     credRow
		wantLocalPass string
		wantLocalLive bool
	}{
		{"a future-dated tombstone over a live row",
			live, credRow{pass: "", updatedAt: future, deletedAt: future, withEvidence: true}, "New-Pass", true},
		{"a live row set after a future-dated retirement",
			tomb, credRow{pass: "Skewed-Pass", updatedAt: evOperator, after: future, withEvidence: true}, "", false},
		{"a live row with a future-dated clock",
			tomb, credRow{pass: "Skewed-Pass", updatedAt: future, after: evOperator, withEvidence: true}, "", false},
		// Review m-16: with no local row, the retirement is checked as well as
		// the clock; a first-seen row set after a future-dated retirement would
		// otherwise outrank every removal until the wall clock passed it.
		{"a first-seen live row set after a future-dated retirement",
			credRow{}, credRow{pass: "Skewed-Pass", updatedAt: evOperator, after: future, withEvidence: true}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, guard := range []bool{true, false} {
				c := newTestDB(t)
				c.SetHLCSkewGuard(func() bool { return guard })
				if tc.local != (credRow{}) {
					mergeInto(t, c, tc.local)
				}
				before := c.SkewQuarantinedCount()
				mergeInto(t, c, tc.in)
				pass, live := liveCredential(t, c)
				kept := pass == tc.wantLocalPass && live == tc.wantLocalLive
				if guard && (!kept || c.SkewQuarantinedCount() == before) {
					t.Errorf("guard on: got %s live %v (quarantined %d); want the local row kept and the row quarantined",
						redactedPass(pass), live, c.SkewQuarantinedCount()-before)
				}
				if !guard && kept {
					t.Errorf("guard off: the ordered row did not apply (got %s live %v)", redactedPass(pass), live)
				}
			}
		})
	}
}
