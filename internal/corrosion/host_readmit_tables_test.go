package corrosion

import (
	"context"
	"testing"
)

// The per-host tables keyed by the host's name, beyond hosts itself, decided
// one by one (host_readmit.go, THE HOST'S OTHER ROWS):
//   - host_networks is reset: its rows record wiring confirmed on the OLD
//     machine's NICs, and the new machine's next apply would render them;
//   - netbox_host_config is reset: the old machine's publication would stand
//     in for a new machine that never publishes, which the uniformity check
//     exists to catch;
//   - host_firewall_rules is kept: forward-chain policy for guest traffic on
//     the name, not a fact about the hardware.

// oldHostRows gives host-x's old incarnation one row in each table, written
// before its removal.
func oldHostRows(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	if err := UpsertHostNetwork(ctx, c, HostNetworkRecord{
		HostName: "host-x", Name: "vmbr0", Kind: "bridge", Members: []string{"enp3s0f0"},
		Addressing: `{"addresses":["10.0.10.15/24"]}`,
	}); err != nil {
		t.Fatalf("UpsertHostNetwork: %v", err)
	}
	if err := MarkHostNetworkApplied(ctx, c, "host-x", "vmbr0"); err != nil {
		t.Fatalf("MarkHostNetworkApplied: %v", err)
	}
	if err := PublishNetBoxHostConfig(ctx, c, "host-x", "dc1-cluster"); err != nil {
		t.Fatalf("PublishNetBoxHostConfig: %v", err)
	}
	if err := InsertHostFirewallRule(ctx, c, FirewallRule{
		ID: "fw-x-1", HostName: "host-x", Direction: "in", Proto: "tcp", PortRange: "443", Action: "accept",
	}); err != nil {
		t.Fatalf("InsertHostFirewallRule: %v", err)
	}
}

func liveRows(t *testing.T, c *Client, query string) int {
	t.Helper()
	rows, err := c.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return len(rows)
}

func assertHostOwnedRowsReset(t *testing.T, c *Client, ts string) {
	t.Helper()
	if n := liveRows(t, c, `SELECT 1 FROM host_networks WHERE host_name = 'host-x' AND deleted_at IS NULL`); n != 0 {
		t.Errorf("%d host_networks intent(s) of the previous machine are still live for the new one", n)
	}
	if n := liveRows(t, c, `SELECT 1 FROM netbox_host_config WHERE host_name = 'host-x' AND deleted_at IS NULL`); n != 0 {
		t.Errorf("the previous machine's NetBox publication still stands for the new one")
	}
	if n := liveRows(t, c, `SELECT 1 FROM host_firewall_rules WHERE host_name = 'host-x' AND deleted_at IS NULL`); n != 1 {
		t.Errorf("host_firewall_rules live rows = %d, want the 1 kept: guest-traffic policy on the name", n)
	}
	if ts == "" {
		return
	}
	for _, tbl := range []string{"host_networks", "netbox_host_config"} {
		rows, err := c.Query(context.Background(),
			`SELECT deleted_at, updated_at FROM `+tbl+` WHERE host_name = 'host-x'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: %d %v", tbl, len(rows), err)
		}
		if rows[0].String("deleted_at") != ts || rows[0].String("updated_at") != ts {
			t.Errorf("%s tombstone = (deleted_at %q, updated_at %q), want both at the admission's %s, "+
				"which every node derives alike", tbl, rows[0].String("deleted_at"), rows[0].String("updated_at"), ts)
		}
	}
}

func TestAdmitHost_ReadmissionResetsTheHostsOtherRows(t *testing.T) {
	c := newTestDB(t)
	oldHostRows(t, c)
	oldIncarnation(t, c)
	if err := AdmitHost(context.Background(), c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: HostStateJoining, CertSerial: readmitSerial,
	}); err != nil {
		t.Fatalf("AdmitHost: %v", err)
	}
	rows, err := c.Query(context.Background(), `SELECT updated_at FROM hosts WHERE name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	assertHostOwnedRowsReset(t, c, rows[0].String("updated_at"))
}

func TestReplicatedReadmission_ResetsTheHostsOtherRows(t *testing.T) {
	c := newTestDB(t)
	oldHostRows(t, c)
	oldIncarnation(t, c)
	const ts = "2999-01-01T00:00:00.000001Z"
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, ts, "host-x", readmitSerial,
	}})
	assertHostOwnedRowsReset(t, c, ts)
}

// Rows the new machine wrote after its admission are its own: a re-admission
// that reaches this node late leaves them alone.
func TestReplicatedReadmission_KeepsTheNewMachinesRows(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	oldHostRows(t, c) // written now: after the 1999 admission below
	applyRemote(t, c, "1999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "1999-01-01T00:00:00.000001Z", "host-x", readmitSerial,
	}})
	if n := liveRows(t, c, `SELECT 1 FROM host_networks WHERE host_name = 'host-x' AND deleted_at IS NULL`); n != 1 {
		t.Errorf("host_networks: %d live, want the new machine's 1", n)
	}
	if n := liveRows(t, c, `SELECT 1 FROM netbox_host_config WHERE host_name = 'host-x' AND deleted_at IS NULL`); n != 1 {
		t.Errorf("netbox_host_config: %d live, want the new machine's 1", n)
	}
}
