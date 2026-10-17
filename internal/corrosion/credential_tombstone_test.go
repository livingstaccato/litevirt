package corrosion

import (
	"context"
	"fmt"
	"testing"
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
		t.Errorf("GetHost served IPMIPass %q from the old column over a retired credential row; want none",
			h.IPMIPass)
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
		t.Errorf("hosts.ipmi_pass = %s after the clear pass, want ''", got.ipmiPass)
	}
}

// A neighbour that has not latched sets the new machine's password in the old
// column alone; the absorb revives the retired row with it, gate open or
// closed.
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
	// Once merged (a peer had no row either), the copy proceeds.
	c.markSensitiveLaneMerged("peer")
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
