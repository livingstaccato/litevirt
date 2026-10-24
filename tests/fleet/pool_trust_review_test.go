package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// (review r0 I4, the reviewer's test) alice confirms a row on node-1 through node-2. The audit of the
// trust grant should name alice, as the forwarded pit-overlay removal does.
func TestFleet_PoolTrust_ReviewAuditOfTheGrantNamesTheOperator(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.openClusterPolicyGate()
	t.Cleanup(c.Stop)
	ctx := context.Background()
	attacker, target, entry := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		pt, err := pooltrust.Open(filepath.Join(c.tmpRoot, n.Name, "data"), n.PKIDir)
		if err != nil {
			t.Fatal(err)
		}
		n.Server.SetPoolTrust(pt)
	}
	pwn := filepath.Join(c.tmpRoot, "srv-pwn")
	if err := os.MkdirAll(pwn, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, attacker.DB, corrosion.StoragePoolRecord{
		HostName: target.Name, Name: "pwn", Driver: "dir", Target: pwn, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	tok := adminUserToken(t, c, entry, "alice")
	c.WaitConverged(t, convergeTimeout)
	if _, err := c.bearerClient(entry, tok).TrustStoragePool(ctx, &pb.TrustStoragePoolRequest{Name: "pwn", Host: target.Name, Driver: "dir", Target: pwn}); err != nil {
		t.Fatalf("trust through node-2: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range []*Node{target, entry} {
		rows, err := n.DB.Query(ctx, `SELECT username, host_name FROM audit_log WHERE action = 'storage.pool.trust'`)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			t.Logf("%s sees storage.pool.trust by %q on %s", n.Name, r.String("username"), r.String("host_name"))
		}
	}
	rows, _ := target.DB.Query(ctx, `SELECT username FROM audit_log WHERE action = 'storage.pool.trust' AND host_name = ?`, target.Name)
	if len(rows) != 1 || rows[0].String("username") != "alice" {
		t.Errorf("audit of the trust grant = %v, want one row by alice", rows)
	}
}
