package corrosion

import (
	"context"
	"testing"
)

// `lv host rm` must not leave the removed machine's BMC password live on the
// sensitive lane. Readers take host_fence_credentials whenever a live row
// exists, so a live row outlives the host it fences: it is served for the name
// until something retires it, and until this change only a re-admission did,
// and only on the nodes that applied one.

const credTS = "2026-09-28T10:21:08.331604576Z"

// configuredHost registers host-x with an IPMI password in both places (the
// split latched), as `lv host config` leaves it.
func configuredHost(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	c.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertHost(ctx, c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "01old", FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET ipmi_pass = 'Ipmi-Probe-0928', updated_at = ? WHERE name = 'host-x'`,
		credTS); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().Exec(HostFenceCredentialUpsertSQL, "host-x", "Ipmi-Probe-0928", credTS); err != nil {
		t.Fatalf("credential row: %v", err)
	}
}

func credentialRow(t *testing.T, c *Client) (pass, deletedAt, updatedAt string) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT ipmi_pass, deleted_at, updated_at FROM host_fence_credentials WHERE host_name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read credential: %d %v", len(rows), err)
	}
	return rows[0].String("ipmi_pass"), rows[0].String("deleted_at"), rows[0].String("updated_at")
}

// The node `lv host rm` runs on.
func TestDeleteHost_RetiresTheFenceCredential(t *testing.T) {
	c := newTestDB(t)
	configuredHost(t, c)
	if err := DeleteHost(context.Background(), c, "host-x"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	if pass, ok := liveCredential(t, c); ok {
		t.Fatalf("the removed host's credential row is still live (ipmi_pass %q)", pass)
	}
	pass, del, upd := credentialRow(t, c)
	if pass != "" || del == "" || del != upd {
		t.Errorf("credential row = (pass %q, deleted_at %q, updated_at %q); want an empty tombstone "+
			"stamped with the removal's updated_at", pass, del, upd)
	}
	rows, err := c.Query(context.Background(), `SELECT updated_at FROM hosts WHERE name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	if hu := rows[0].String("updated_at"); hu != upd {
		t.Errorf("credential tombstone at %s, host tombstone at %s: every node must derive the same "+
			"credential tombstone from the removal's own updated_at", upd, hu)
	}
}

// Every node the removal replicates to, whichever way its credential gate
// stands: a gate-closed node holds the row only because a latched peer wrote
// it, and its reader serves it all the same.
func TestReplicatedHostDelete_RetiresTheFenceCredential(t *testing.T) {
	for _, gate := range []bool{true, false} {
		c := newTestDB(t)
		configuredHost(t, c)
		c.SetCredentialsSplitGate(func() bool { return gate })
		const ts = "2999-01-01T00:00:00.000001Z"
		applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: deleteHostSQL,
			Params: []interface{}{"2999-01-01T00:00:00Z", ts, "host-x"}})
		if pass, ok := liveCredential(t, c); ok {
			t.Errorf("gate %v: the removed host's credential row is still live (ipmi_pass %q)", gate, pass)
			continue
		}
		if pass, del, upd := credentialRow(t, c); pass != "" || del != ts || upd != ts {
			t.Errorf("gate %v: credential row = (pass %q, deleted_at %q, updated_at %q), want an empty "+
				"tombstone at %s", gate, pass, del, upd, ts)
		}
	}
}

// A credential newer than the removal belongs to whatever was admitted under
// the name since; a removal that reaches this node late leaves it alone.
func TestReplicatedHostDelete_KeepsANewerCredential(t *testing.T) {
	c := newTestDB(t)
	configuredHost(t, c)
	const newer = "2999-06-01T00:00:00.000001Z"
	if _, err := c.DB().Exec(HostFenceCredentialUpsertSQL, "host-x", "new-machine", newer); err != nil {
		t.Fatal(err)
	}
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: deleteHostSQL,
		Params: []interface{}{"2999-01-01T00:00:00Z", "2999-01-01T00:00:00.000001Z", "host-x"}})
	if pass, ok := liveCredential(t, c); !ok || pass != "new-machine" {
		t.Errorf("credential row = %q (live %v); a credential newer than the removal must stand", pass, ok)
	}
}

// The removal keeps its wire shape: the retirement travels with the
// fingerprint a previous-release receiver already knows.
func TestDeleteHost_KeepsItsWireShape(t *testing.T) {
	e, err := LedgerEntryFor(deleteHostSQL)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stmtLedger[e.Fingerprint]; !ok {
		t.Errorf("deleteHostSQL fingerprint %s is not in the generated ledger", e.Fingerprint)
	}
	if e.Disposition != DispFullPKUpdate {
		t.Errorf("disposition %s, want %s", e.Disposition, DispFullPKUpdate)
	}
}

// The split pass must not undo the removal. DeleteHost tombstones the hosts row
// and leaves ipmi_pass in the old column (a previous-release node reads it
// there), and the retirement makes the credential row a tombstone — which is
// exactly what needsCopy() reads as "no live row, copy the old column in". The
// pass runs every minute, so within one cycle the removed machine's BMC password
// was live again on every node, upserted with deleted_at = NULL and replicated.
func TestSplitCredentials_DoesNotReviveARemovedHostsCredential(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	configuredHost(t, c)
	if err := DeleteHost(ctx, c, "host-x"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	rep, err := c.SplitCredentials(ctx)
	if err != nil {
		t.Fatalf("SplitCredentials: %v", err)
	}
	if pass, ok := liveCredential(t, c); ok {
		t.Fatalf("the split pass revived the removed host's credential row (ipmi_pass %q, report %+v)",
			pass, rep)
	}
	if rep.Copied != 0 {
		t.Errorf("the split pass copied %d secrets after the removal, want 0", rep.Copied)
	}
}
