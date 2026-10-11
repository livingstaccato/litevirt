package corrosion

import (
	"context"
	"slices"
	"strings"
	"testing"
)

const redfishPass = "Redfish-Probe-1011"

// redfishHost registers host-x fencing by redfish, its BMC settings in
// host_fence_redfish as ConfigureHost leaves them.
func redfishHost(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	if err := InsertHost(ctx, c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "01old", FenceStrategy: "redfish",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if _, err := c.DB().Exec(HostFenceRedfishUpsertSQL, "host-x", "https://10.0.1.15", "admin", redfishPass,
		"System.Embedded.1", "basic", "", credTS); err != nil {
		t.Fatalf("redfish row: %v", err)
	}
}

func liveRedfish(t *testing.T, c *Client) (string, bool) {
	t.Helper()
	cfg, ok, err := GetHostFenceRedfish(context.Background(), c, "host-x")
	if err != nil {
		t.Fatalf("GetHostFenceRedfish: %v", err)
	}
	return cfg.Pass, ok
}

func redfishRow(t *testing.T, c *Client) (pass, endpoint, deletedAt, updatedAt string) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT password, endpoint, deleted_at, updated_at FROM host_fence_redfish WHERE host_name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read redfish row: %d %v", len(rows), err)
	}
	r := rows[0]
	return r.String("password"), r.String("endpoint"), r.String("deleted_at"), r.String("updated_at")
}

// GetHost — what the failover coordinator and FenceHost build the fence from —
// reads the Redfish row, and nothing of it is on the hosts row.
func TestGetHost_ReadsTheRedfishRow(t *testing.T) {
	c := newTestDB(t)
	redfishHost(t, c)
	h, err := GetHost(context.Background(), c, "host-x")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %+v %v", h, err)
	}
	want := "https://10.0.1.15 admin " + redfishPass + " System.Embedded.1 basic"
	got := strings.Join([]string{h.Redfish.Endpoint, h.Redfish.User, h.Redfish.Pass, h.Redfish.SystemID, h.Redfish.Auth}, " ")
	if got != want {
		t.Errorf("GetHost Redfish = %q, want %q", got, want)
	}
	hosts, err := ListHosts(context.Background(), c)
	if err != nil || len(hosts) != 1 || hosts[0].Redfish.Pass != redfishPass {
		t.Errorf("ListHosts Redfish = %+v %v", hosts, err)
	}
	rows, err := c.Query(context.Background(), `SELECT * FROM hosts WHERE name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	for i, col := range rows[0].Columns {
		if v := rows[0].String(col); strings.Contains(v, redfishPass) {
			t.Errorf("hosts.%s (column %d) carries the Redfish password", col, i)
		}
	}
}

// The Redfish row carries the BMC password: it is on the sensitive lane, so
// it never enters the operator-safe state dump.
func TestHostFenceRedfish_IsOnTheSensitiveLane(t *testing.T) {
	if !slices.Contains(SensitiveTableNames(), "host_fence_redfish") {
		t.Error("host_fence_redfish is not in sensitiveTableNames")
	}
	if slices.Contains(tableNames, "host_fence_redfish") {
		t.Error("host_fence_redfish is on the public lane")
	}
}

// A removed host's BMC settings are retired with it, on the node `lv host rm`
// runs on and on every node the removal replicates to; a row newer than the
// removal (a machine admitted under the name since) stands.
func TestHostDelete_RetiresTheRedfishRow(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		c := newTestDB(t)
		redfishHost(t, c)
		if err := DeleteHost(context.Background(), c, "host-x"); err != nil {
			t.Fatalf("DeleteHost: %v", err)
		}
		if pass, ok := liveRedfish(t, c); ok {
			t.Fatalf("the removed host's Redfish row is still live (password %q)", pass)
		}
		if pass, ep, del, upd := redfishRow(t, c); pass != "" || ep != "" || del == "" || del != upd {
			t.Errorf("redfish row = (%q, %q, deleted_at %q, updated_at %q); want an empty tombstone", pass, ep, del, upd)
		}
	})
	t.Run("replicated", func(t *testing.T) {
		c := newTestDB(t)
		redfishHost(t, c)
		const ts = "2999-01-01T00:00:00.000001Z"
		applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: deleteHostSQL,
			Params: []interface{}{"2999-01-01T00:00:00Z", ts, "host-x"}})
		if pass, _, del, upd := redfishRow(t, c); pass != "" || del != ts || upd != ts {
			t.Errorf("redfish row = (%q, deleted_at %q, updated_at %q), want an empty tombstone at %s", pass, del, upd, ts)
		}
	})
	t.Run("newer-stands", func(t *testing.T) {
		c := newTestDB(t)
		redfishHost(t, c)
		const newer = "2999-06-01T00:00:00.000001Z"
		if _, err := c.DB().Exec(HostFenceRedfishUpsertSQL, "host-x", "https://10.0.1.99", "admin", "new-machine",
			"", "", "", newer); err != nil {
			t.Fatal(err)
		}
		applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: deleteHostSQL,
			Params: []interface{}{"2999-01-01T00:00:00Z", "2999-01-01T00:00:00.000001Z", "host-x"}})
		if pass, ok := liveRedfish(t, c); !ok || pass != "new-machine" {
			t.Errorf("redfish row = %q (live %v); a row newer than the removal must stand", pass, ok)
		}
	})
}

// A re-admission under the name is a new machine; it must not be fenced
// through the old machine's BMC.
func TestReplicatedReadmission_RetiresTheRedfishRow(t *testing.T) {
	c := newTestDB(t)
	redfishHost(t, c)
	if err := DeleteHost(context.Background(), c, "host-x"); err != nil {
		t.Fatal(err)
	}
	// Revive the row as if the removal had not reached this replica's
	// sensitive lane, so only the admission can retire it.
	if _, err := c.DB().Exec(HostFenceRedfishUpsertSQL, "host-x", "https://10.0.1.15", "admin", redfishPass,
		"", "", "", credTS); err != nil {
		t.Fatal(err)
	}
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "2999-01-01T00:00:00.000001Z", "host-x", readmitSerial,
	}})
	if pass, ok := liveRedfish(t, c); ok {
		t.Errorf("the previous machine's Redfish row is still live (password %q)", pass)
	}
	h, err := GetHost(context.Background(), c, "host-x")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %+v %v", h, err)
	}
	if h.Redfish.Configured() || h.Redfish.Pass != "" {
		t.Errorf("a fence of the new machine would go to the old BMC: %+v", h.Redfish)
	}
}
