package corrosion

import (
	"context"
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
		t.Fatalf("fixture: hosts row = %+v, want the stale live row with the old password", got)
	}
}

// Channel 2, the read path. Mutation: join only a live credential row again,
// so a tombstone reads as "no row" and the old column is served — red.
func TestGetHost_ARetiredCredentialIsNotReadFromTheOldColumn(t *testing.T) {
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	h, err := GetHost(context.Background(), c, "host-x")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %+v %v", h, err)
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
		t.Fatalf("GetHost = %+v, %v; want the old column's password, not retired", h, err)
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

// The operator sets the new machine's password after the re-admission: the
// latched write revives the row, and every reader serves it.
func TestRetiredCredential_OperatorCanSetItAgain(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	staleDBAfterReadmission(t, c)
	if err := c.ExecuteBatch(ctx, []Statement{
		{SQL: hostsClearIPMIPassSQL, Params: []interface{}{"New-Machine-Pass", "2026-10-03T00:00:00Z", "host-x"}},
		{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", "New-Machine-Pass", "2026-10-03T00:00:00Z"}},
	}); err != nil {
		t.Fatal(err)
	}
	h, err := GetHost(ctx, c, "host-x")
	if err != nil || h == nil || h.IPMIPass != "New-Machine-Pass" || h.IPMIPassRetired {
		t.Fatalf("GetHost = %+v, %v; want the operator's new password, not retired", h, err)
	}
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if pass, ok := liveCredential(t, c); !ok || pass != "New-Machine-Pass" {
		t.Errorf("credential row = %s (live %v) after a pass, want the operator's password", redactedPass(pass), ok)
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
			t.Errorf("gate %v: GetHost = %+v, %v; want the unlatched write's password, not retired", gate, h, err)
		}
	}
}

func redactedPass(s string) string {
	if s == "" {
		return "<empty>"
	}
	return "<set>"
}
