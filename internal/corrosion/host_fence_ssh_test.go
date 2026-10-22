package corrosion

import (
	"context"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// fenceSSHHost registers host-x with a live fence SSH row, written by its
// writer under fence_ssh's grant.
func fenceSSHHost(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	if err := InsertHost(ctx, c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "01old", FenceStrategy: "ssh",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := PutHostFenceSSH(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureFenceSSH), HostFenceSSHRow{
		HostName: "host-x", Generation: 1, FencePubkeys: "ssh-ed25519 AAAAfence", SSHDHostkeys: "ssh-ed25519 AAAAhost",
		Accepting: true, EverAccepting: true, CertPEM: "cert", Signature: "sig",
	}); err != nil {
		t.Fatalf("PutHostFenceSSH: %v", err)
	}
}

func fenceSSHRowOf(t *testing.T, c *Client) HostFenceSSHRow {
	t.Helper()
	r, ok, err := GetHostFenceSSH(context.Background(), c, "host-x")
	if err != nil || !ok {
		t.Fatalf("GetHostFenceSSH: %+v %v %v", r, ok, err)
	}
	return r
}

// The writer takes fence_ssh's grant and nothing else.
func TestPutHostFenceSSH_NeedsTheFeatureGrant(t *testing.T) {
	c := newTestDB(t)
	row := HostFenceSSHRow{HostName: "host-x", FencePubkeys: "k", SSHDHostkeys: "h"}
	if err := PutHostFenceSSH(context.Background(), c, capabilities.FeatureGrant{}, row); err == nil {
		t.Fatal("PutHostFenceSSH wrote with the zero grant")
	}
	if err := PutHostFenceSSH(context.Background(), c, capabilities.GrantForTest(t, capabilities.FeatureRedfishFence), row); err == nil {
		t.Fatal("PutHostFenceSSH wrote with another feature's grant")
	}
	if _, ok, _ := GetHostFenceSSH(context.Background(), c, "host-x"); ok {
		t.Fatal("a refused write left a row")
	}
}

// The row is public (public keys and a certificate) and is repaired by
// anti-entropy like any cluster fact: a node that missed it would fence that
// peer unpinned.
func TestHostFenceSSH_IsOnThePublicLane(t *testing.T) {
	if !slices.Contains(tableNames, "host_fence_ssh") {
		t.Error("host_fence_ssh is not repaired by anti-entropy")
	}
	if slices.Contains(SensitiveTableNames(), "host_fence_ssh") {
		t.Error("host_fence_ssh is on the sensitive lane")
	}
}

// A removed host's fence key leaves with it — on the node `lv host rm` (or
// `lv host rm --dead`) runs on and on every node the removal reaches — and a
// row newer than the removal (a machine admitted under the name since)
// stands.
func TestHostDelete_RetiresTheFenceSSHRow(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		c := newTestDB(t)
		fenceSSHHost(t, c)
		if err := DeleteHost(context.Background(), c, "host-x"); err != nil {
			t.Fatalf("DeleteHost: %v", err)
		}
		if r := fenceSSHRowOf(t, c); !r.Deleted || r.FencePubkeys != "" || r.Accepting || r.EverAccepting {
			t.Fatalf("row = %+v, want an empty tombstone", r)
		}
	})
	t.Run("replicated admission removal", func(t *testing.T) {
		c := newTestDB(t)
		fenceSSHHost(t, c)
		const ts = "2999-01-01T00:00:00.000001Z"
		applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: deleteHostAdmissionSQL,
			Params: []interface{}{"2999-01-01T00:00:00Z", ts, "host-x", "01OLD"}})
		if r := fenceSSHRowOf(t, c); !r.Deleted || r.UpdatedAt != ts || r.FencePubkeys != "" {
			t.Fatalf("row = %+v, want an empty tombstone at %s", r, ts)
		}
	})
	t.Run("newer-stands", func(t *testing.T) {
		c := newTestDB(t)
		fenceSSHHost(t, c)
		const newer = "2999-06-01T00:00:00.000001Z"
		if _, err := c.DB().Exec(HostFenceSSHUpsertSQL, "host-x", 2, "ssh-ed25519 AAAAnew", "ssh-ed25519 AAAAh", 1, 1, "",
			"cert", "sig", newer); err != nil {
			t.Fatal(err)
		}
		applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: deleteHostSQL,
			Params: []interface{}{"2999-01-01T00:00:00Z", "2999-01-01T00:00:00.000001Z", "host-x"}})
		if r := fenceSSHRowOf(t, c); r.Deleted || r.FencePubkeys != "ssh-ed25519 AAAAnew" {
			t.Fatalf("row = %+v; a row newer than the removal must stand", r)
		}
	})
}

// A re-admission is a new machine: the old machine's key must not stay in any
// peer's authorized_keys, nor its host keys pinned for the name.
func TestReplicatedReadmission_RetiresTheFenceSSHRow(t *testing.T) {
	c := newTestDB(t)
	fenceSSHHost(t, c)
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "2999-01-01T00:00:00.000001Z", "host-x", readmitSerial,
	}})
	if r := fenceSSHRowOf(t, c); !r.Deleted || r.SSHDHostkeys != "" {
		t.Fatalf("row = %+v; the previous machine's keys are still live", r)
	}
}
